#include <event2/event.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <netdb.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>
#include <inttypes.h>

#include "sb_log.h"
#include "sb_config.h"
#include "sb_util.h"
#include "sb_tun.h"
#include "sb_net.h"
#include "sb_proto.h"
#include "sbwdn.h"

#ifdef SB_DEBUG
#include <mcheck.h>
#endif

static void libevent_log(int severity, const char *msg) {
    int lvl;
    switch (severity) {
        case EVENT_LOG_DEBUG:
            lvl = SB_LOG_DEBUG; break;
        case EVENT_LOG_MSG:
            lvl = SB_LOG_INFO;  break;
        case EVENT_LOG_WARN:
            lvl = SB_LOG_WARN;  break;
        case EVENT_LOG_ERR:
            lvl = SB_LOG_ERROR; break;
        default:
            lvl = SB_LOG_INFO;  break;
    }
    if (lvl >= sb_logger.lvl) {
        log_log(lvl, __FILE__, __LINE__, "libevent: %s", msg);
    }
}

void sb_do_tun_read(evutil_socket_t fd, short what, void * data) {
    SB_NOT_USED(what);
    struct sb_app * app = (struct sb_app *) data;
    /* read a package from tun */
    int tun_frame_size;
    int buflen = app->config->mtu + sizeof(struct sb_tun_pi);
    char buf[buflen];
    bool enable_udp_write = false;

    log_enter_func();
    while(1) {
        tun_frame_size = read(fd, buf, buflen);
        if (tun_frame_size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                log_trace("no more data from tun");
            } else {
                log_error("failed to receive package from tun: %s", sb_util_strerror(errno));
            }
            break;
        }
        log_trace("read %d bytes from tun", tun_frame_size);

        struct sb_tun_pi pi = *(struct sb_tun_pi *)buf;
        pi.flags = ntohs(pi.flags);
        pi.proto = ntohs(pi.proto);
        if (pi.proto != PROTO_IPV4) {
            log_debug("unsupported protocol %04x", pi.proto);
            continue;
        }
        /* check if the target ip is one of our client, if no, drop it on the floor */
        /* if target ip is one of our client, queue it into that connection's packages_t2n */
        /* if necessary, enable net_writeevent for that connection */
        struct iphdr * iphdr = &(((struct sb_tun_pkg *)buf)->iphdr);
        struct in_addr daddr = *(struct in_addr *)&(iphdr->daddr);
        log_trace("dst addr: %s", sb_util_human_addr(AF_INET, &daddr));

        struct sb_connection * conn;
        TAILQ_FOREACH(conn, &(app->conns), entries) {
            bool enable_net_write = false;
            log_trace("conn addr: %s", sb_util_human_addr(AF_INET, &conn->peer_vpn_addr.s_addr));
            log_trace("conn pkg addr: %s", sb_util_human_addr(AF_INET, &daddr.s_addr));
            if (app->config->app_mode == SB_CLIENT || conn->peer_vpn_addr.s_addr == daddr.s_addr) {
                if (conn->net_state != ESTABLISHED_2) {
                    log_warn("received pkg from tun, but connection is not in established state for %s", conn->desc);
                } else if (conn->t2n_pkg_count >= SB_PKG_BUF_MAX) {
                    /* should I send a ICMP or something? */
                    log_debug("connection queue full %s", conn->desc);
                } else {
                    struct sb_package * pkg = sb_package_new(SB_PKG_TYPE_DATA_2, (char *)buf, tun_frame_size);
                    if (!pkg) {
                        log_error("failed to create a sb_package for %s, dropping", conn->desc);
                        break;
                    }
                    /* statistics */
                    conn->stat.tun_ingress_pkgs++;
                    conn->stat.tun_ingress_bytes += pkg->ipdatalen;
                    log_trace("queuing a pkg from tun for connection %s", conn->desc);
                    TAILQ_INSERT_TAIL(&(conn->packages_t2n), pkg, entries);
                    conn->t2n_pkg_count++;
                    enable_net_write = true;
                }
            }
            enable_udp_write |= enable_net_write;
            if(enable_net_write && app->config->net_mode == SB_NET_MODE_TCP) {
                log_trace("enabling write for %s", conn->desc);
                event_add(conn->net_writeevent, 0);
            }
        }
        if (enable_udp_write && app->config->net_mode == SB_NET_MODE_UDP && app->udp_writeevent) {
            log_trace("enabling write for udp");
            event_add(app->udp_writeevent, 0);
        }
    }
    log_exit_func();
    return;
}

void sb_do_tun_write(evutil_socket_t fd, short what, void * data) {
    SB_NOT_USED(what);
    struct sb_app * app = (struct sb_app *)data;
    bool disable_tun_write = true;
    /* pick a connection that has package pending in packages_n2t */
    struct sb_connection * conn;

    log_enter_func();
    while(1) {
        struct sb_package * pkg = 0;
        TAILQ_FOREACH(conn, &(app->conns), entries) {
            log_trace("n2t_pkg_count is %d %s", conn->n2t_pkg_count, conn->desc);
            if (conn->n2t_pkg_count > 0) {
                pkg = TAILQ_FIRST(&(conn->packages_n2t));
                if (pkg) {
                    break;
                }
            }
        }
        if (!pkg) {
            log_trace("no more data from net");
            disable_tun_write = true;
            break;
        }
        /* send that package into tun */
        log_trace("sending a pkg with length %d to tun", pkg->ipdatalen);
        int ret = write(fd, pkg->ipdata, pkg->ipdatalen);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                log_trace("tun is not writable any more");
                break;
            } else {
                log_error("failed to write to tun device: %s", sb_util_strerror(errno));
                break;
            }
        } else {
            /* statistics */
            conn->stat.tun_egress_pkgs++;
            conn->stat.tun_egress_bytes += pkg->ipdatalen;
            /* tun will not write incomplete*/
            log_trace("sent a pkg with length %d to tun", ret);
            TAILQ_REMOVE(&(conn->packages_n2t), pkg, entries);
            conn->n2t_pkg_count--;
            free(pkg->ipdata);
            pkg->ipdata = 0;
            free(pkg);
            pkg = 0;
            log_trace("n2t_pkg_count is %d after remove", conn->n2t_pkg_count);
        }
    }
    if (disable_tun_write) {
        log_debug("disabling tun write");
        event_del(app->tun_writeevent);
    }
    log_exit_func();
}

struct sb_app * sb_app_new() {
    struct sb_app * app = malloc(sizeof(struct sb_app));
    if (!app) {
        log_error("failed to allocate memory for sb_app: %s", sb_util_strerror(errno));
        return 0;
    }

    app->config = 0;

    app->eventbase = 0;

    app->sigterm_event = 0;
    app->sigint_event = 0;
    app->sighup_event = 0;

    app->tun_readevent = 0;
    app->tun_writeevent = 0;
    app->udp_readevent = 0;
    app->udp_writeevent = 0;

    app->retry_interval = 1;

    app->reconnect_event = 0;

    app->dont_reconnect = 0;

    TAILQ_INIT(&(app->conns));

    app->conn_timeout_oracle[NEW_0] = 10;
    app->conn_timeout_oracle[CONNECTED_1] = 10;
    /* this timeout is actually keepalive timeout, if the time since last keepalive from peer
     * is greater than this, we will disconnect.
     * set to SB_KEEPALIVE_INTERVAL * 5 means if we miss 5 keepalives from peer, we will disconnect
     */
    app->conn_timeout_oracle[ESTABLISHED_2] = SB_KEEPALIVE_INTERVAL * 10;
    app->conn_timeout_oracle[CLOSING_3] = 10;
    app->conn_timeout_oracle[TERMINATED_4] = 10;

    return app;
}

void sb_app_del(struct sb_app * app) {
    struct sb_connection * conn, * conn2;
    conn = TAILQ_FIRST(&(app->conns));
    while(conn) {
        conn2 = TAILQ_NEXT(conn, entries);
        sb_connection_del(conn);
        conn = conn2;
    }

    if (app->reconnect_event) {
        event_del(app->reconnect_event);
        event_free(app->reconnect_event);
        app->reconnect_event = 0;
    }
    if (app->udp_writeevent) {
        event_del(app->udp_writeevent);
        event_free(app->udp_writeevent);
        app->udp_writeevent = 0;
    }
    if (app->udp_readevent) {
        event_del(app->udp_readevent);
        event_free(app->udp_readevent);
        app->udp_readevent = 0;
    }
    if (app->tun_writeevent) {
        event_del(app->tun_writeevent);
        event_free(app->tun_writeevent);
        app->tun_writeevent = 0;
    }
    if (app->tun_readevent) {
        event_del(app->tun_readevent);
        event_free(app->tun_readevent);
        app->tun_readevent = 0;
    }
    if (app->sigterm_event) {
        event_del(app->sigterm_event);
        event_free(app->sigterm_event);
        app->sigterm_event = 0;
    }
    if (app->sigint_event) {
        event_del(app->sigint_event);
        event_free(app->sigint_event);
        app->sigint_event = 0;
    }
    if (app->sighup_event) {
        event_del(app->sighup_event);
        event_free(app->sighup_event);
        app->sighup_event = 0;
    }

    app->eventbase = 0;

    if (app->config) {
        free(app->config);
        app->config = 0;
    }
    free(app);
    app = 0;
}

void sb_stop_app(struct sb_app * app, int immiedately) {
    app->dont_reconnect = 1;
    if (immiedately) {
        event_base_loopbreak(app->eventbase);
    } else {
        struct timeval tv;
        memset(&tv, 0, sizeof(struct timeval));
        tv.tv_sec = SB_STOP_WAITING;
        event_base_loopexit(app->eventbase, &tv);

        struct sb_connection * conn;
        TAILQ_FOREACH(conn, &(app->conns), entries) {
            sb_connection_say_bye(conn);
            /* here we enable net write, give a chance to net to send bye pkgs to clients
             * the same for udp below
             */
            if (conn->net_mode == SB_NET_MODE_TCP) {
                log_debug("enable net write for %s", conn->desc);
                event_add(conn->net_writeevent, 0);
            }
        }
        if (app->config->net_mode == SB_NET_MODE_UDP && app->udp_writeevent) {
            log_debug("enable udp write");
            event_add(app->udp_writeevent, 0);
        }
    }
}

void sb_dump_status(struct sb_app * app) {
    log_info("dumping status to %s", app->config->statusfile);
    /* write status file */
    FILE * statusf = fopen(app->config->statusfile, "w");
    if (!statusf) {
        log_error("failed to open status file %s", app->config->statusfile);
    } else {
        fprintf(statusf, "Connections\n");
        unsigned int conn_num = 0;
        struct sb_connection * conn;
        char time_buf[128];
        TAILQ_FOREACH(conn, &(app->conns), entries) {
            conn_num++;
            strftime(time_buf, sizeof(time_buf), "%y/%m/%d:%H:%M:%S", localtime( &(conn->conn_time)));
            fprintf(statusf, "----------------------\n");
            fprintf(statusf, "desc: %s\n", conn->desc);
            fprintf(statusf, "conn_time: %s\n", time_buf);
            fprintf(statusf, "net_fd: %d\n", conn->net_fd);
            fprintf(statusf, "net_mode: %u\n", conn->net_mode);
            fprintf(statusf, "net_state: %d\n", conn->net_state);
            /* fprintf(statusf, "cookie: %d", conn->cookie); */
            fprintf(statusf, "n2t_pkg_count: %d\n", conn->n2t_pkg_count);
            fprintf(statusf, "t2n_pkg_count: %d\n", conn->t2n_pkg_count);
            /* fprintf(statusf, "rt_tag: %d", conn->rt_tag); */
            struct sb_conn_stat * start_stat, * end_stat;
            start_stat = &(conn->sample_start_stat);
            end_stat = &(conn->sample_end_stat);

            fprintf(statusf, "net_ingress_pkgs: %"PRIu64"\n", end_stat->net_ingress_pkgs);
            fprintf(statusf, "net_ingress_bytes: %"PRIu64"\n", end_stat->net_ingress_bytes);
            fprintf(statusf, "net_egress_pkgs: %"PRIu64"\n", end_stat->net_egress_pkgs);
            fprintf(statusf, "net_egress_bytes: %"PRIu64"\n", end_stat->net_egress_bytes);
            fprintf(statusf, "tun_ingress_pkgs: %"PRIu64"\n", end_stat->tun_ingress_pkgs);
            fprintf(statusf, "tun_ingress_bytes: %"PRIu64"\n", end_stat->tun_ingress_bytes);
            fprintf(statusf, "tun_egress_pkgs: %"PRIu64"\n", end_stat->tun_egress_pkgs);
            fprintf(statusf, "tun_egress_bytes: %"PRIu64"\n", end_stat->tun_egress_bytes);
            if (conn->sample_start_stat.time.tv_sec != 0) {
                uint64_t net_ingress_pkgs;
                uint64_t net_ingress_bytes;
                uint64_t net_egress_pkgs;
                uint64_t net_egress_bytes;
                uint64_t tun_ingress_pkgs;
                uint64_t tun_ingress_bytes;
                uint64_t tun_egress_pkgs;
                uint64_t tun_egress_bytes;

                int64_t nsec_span = (end_stat->time.tv_sec - start_stat->time.tv_sec) * 1000000000 + (end_stat->time.tv_nsec - start_stat->time.tv_nsec);

                net_ingress_pkgs = max(end_stat->net_ingress_pkgs - start_stat->net_ingress_pkgs, 0);
                net_ingress_bytes = max(end_stat->net_ingress_bytes - start_stat->net_ingress_bytes, 0);
                net_egress_pkgs = max(end_stat->net_egress_pkgs - start_stat->net_egress_pkgs, 0);
                net_egress_bytes = max(end_stat->net_egress_bytes - start_stat->net_egress_bytes, 0);
                tun_ingress_pkgs = max(end_stat->tun_ingress_pkgs - start_stat->tun_ingress_pkgs, 0);
                tun_ingress_bytes = max(end_stat->tun_ingress_bytes - start_stat->tun_ingress_bytes, 0);
                tun_egress_pkgs = max(end_stat->tun_egress_pkgs - start_stat->tun_egress_pkgs, 0);
                tun_egress_bytes = max(end_stat->tun_egress_bytes - start_stat->tun_egress_bytes, 0);

                if (nsec_span != 0) {
                    fprintf(statusf, "net_ingress_pkgs: %"PRIu64" pkg per second\n", net_ingress_pkgs * 1000000000 / nsec_span);
                    fprintf(statusf, "net_ingress_bytes: %"PRIu64" bytes per second\n", net_ingress_bytes * 1000000000 / nsec_span);
                    fprintf(statusf, "net_egress_pkgs: %"PRIu64" pkg per second\n", net_egress_pkgs * 1000000000 / nsec_span);
                    fprintf(statusf, "net_egress_bytes: %"PRIu64" bytes per second\n", net_egress_bytes * 1000000000 / nsec_span);
                    fprintf(statusf, "tun_ingress_pkgs: %"PRIu64" pkg per second\n", tun_ingress_pkgs * 1000000000 / nsec_span);
                    fprintf(statusf, "tun_ingress_bytes: %"PRIu64" bytes per second\n", tun_ingress_bytes * 1000000000 / nsec_span);
                    fprintf(statusf, "tun_egress_pkgs: %"PRIu64" pkg per second\n", tun_egress_pkgs * 1000000000 / nsec_span);
                    fprintf(statusf, "tun_egress_bytes: %"PRIu64" bytes per second\n", tun_egress_bytes * 1000000000 / nsec_span);
                } else {
                    fprintf(statusf, "net_ingress_pkgs: - \n");
                    fprintf(statusf, "net_ingress_bytes: - \n");
                    fprintf(statusf, "net_egress_pkgs: - \n");
                    fprintf(statusf, "net_egress_bytes: - \n");
                    fprintf(statusf, "tun_ingress_pkgs: - \n");
                    fprintf(statusf, "tun_ingress_bytes: - \n");
                    fprintf(statusf, "tun_egress_pkgs: - \n");
                    fprintf(statusf, "tun_egress_bytes: - \n");
                }
            }
        }
        fprintf(statusf, "\ntotal connections: %u\n", conn_num);
        fclose(statusf);
        statusf = 0;
    }
}

void sb_sigterm_handler(evutil_socket_t sig, short what, void * data) {
    SB_NOT_USED(sig);
    SB_NOT_USED(what);
    log_info("SIGTERM received");
    sb_stop_app((struct sb_app *)data, 0);
}

void sb_sigint_handler(evutil_socket_t sig, short what, void * data) {
    SB_NOT_USED(sig);
    SB_NOT_USED(what);
    log_info("SIGINT received");
    sb_dump_status((struct sb_app*)data);
}

void sb_sighup_handler(evutil_socket_t sig, short what, void * data) {
    SB_NOT_USED(sig);
    SB_NOT_USED(what);
    log_info("SIGHUP received");
    struct sb_app * app = data;
    struct sb_config * config = app->config;
    /* if any error just ignore */
    if (config->app_mode == SB_SERVER && strlen(config->routefile) != 0) {
        log_info("reloading route file %s", config->routefile);
        if (sb_parse_rt_file(config) == 0) {
            /* broadcast that we have new route info to all clients */
            struct sb_connection * conn;
            TAILQ_FOREACH(conn, &(app->conns), entries) {
                log_debug("sending new route information tag to client %s", conn->desc);
                sb_try_send_route_tag(config, conn);
                log_debug("enabling net write for %s", conn->desc);
                if (conn->net_mode == SB_NET_MODE_TCP && conn->net_writeevent) {
                    event_add(conn->net_writeevent, 0);
                } else if (conn->net_mode == SB_NET_MODE_UDP && app->udp_writeevent) {
                    event_add(app->udp_writeevent, 0);
                }
            }
        }
    }
}

int sb_daemonize() {
    int pid;

    pid = fork();
    if (pid < 0) {
        log_error("failed 1st fork: %s", sb_util_strerror(errno));
        return -1;
    } else if (pid > 0) {
        exit(0);
        /* will not reach here */
        return 0;
    }
    pid = fork();
    if (pid < 0) {
        log_error("failed 2nd fork: %s", sb_util_strerror(errno));
        /* we don't return -1 here, b/c we will not open tty, fail this fork doesn't matter */
    } else if (pid > 0) {
        exit(0);
        /* will not reach here */
        return 0;
    }

    setsid();

    if (chdir("/") < 0) {
        log_error("failed to chdir to /, %s", sb_util_strerror(errno));
    }

    umask(0);

    closelog();
    /* close c runtime stdios, otherwise it will ruin memory
     * when closing the underlying fds.
     * I am looking at you, uclibc
     */
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);
    log_set_fp(0);
    log_set_quiet(1);
    for (int fd = sysconf(_SC_OPEN_MAX); fd>=0; fd--)
    {
        close(fd);
    }
    /* log to syslog before log file is open */
    openlog("sbwdn", LOG_PID, LOG_DAEMON);

    return 0;
}

int main(int argc, char ** argv) {
    /* init logger */
    log_init(&sb_logger);
    /* set fp to NULL, so that logs goes to syslog before log file is open */
    openlog("sbwdn", LOG_PID, LOG_DAEMON);

    if (argc != 3 || strlen(argv[1]) != 2 || strncmp(argv[1], "-f", 2) != 0) {
        log_error("Usage: %s -f [config file path]\n", argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        log_fatal("only root can run, exiting");
        return 1;
    }

    /* read config file before daemonize, since the path could be a relative path */
    char * config_file = argv[2];
    log_trace("reading config file %s", config_file);
    struct sb_config * config = sb_config_read(config_file);
    if(!config) {
        log_fatal("failed to read config file %s", config_file);
        return 0;
    }

#ifdef SB_DEBUG
    mtrace();
#else
    log_info("mutating to a daemon, a happy daemon");
    if (sb_daemonize() < 0) {
        log_fatal("failed to mutate to a daemon: %s, are you oric?", sb_util_strerror(errno));
        return 1;
    }
    log_info("hello, I am now a daemon");
#endif

    {
        /* write pid file */
        FILE * pidf = fopen(config->pidfile, "w");
        if (!pidf) {
            log_error("failed to open pid file %s", config->pidfile);
        } else {
            log_info("writing pid %d to %s", getpid(), config->pidfile);
            fprintf(pidf, "%d", getpid());
            fclose(pidf);
            pidf = 0;
        }
    }

    struct sb_app * app = sb_app_new();
    if (!app) {
        log_fatal("faied to init sb_app");
        return 1;
    }
    log_info("applying config");
    if (sb_config_apply(app, config) < 0) {
        free(config);
        config = 0;
        free(app);
        app = 0;
        return 0;
    }


    /* setup libevent */
    log_info("setting up libevent");
    /* setup libevent log */
    event_set_log_callback(libevent_log);

    struct event_config * event_cfg = event_config_new();
    struct event_base * eventbase = event_base_new_with_config(event_cfg);
#ifdef __APPLE__
    /* apple's tun don't support kqueue*/
    log_info("we are on mac, use select or poll");
    event_config_avoid_method(event_cfg, "kqueue");
#endif
    event_config_free(event_cfg);

    eventbase = event_base_new();
    if (!eventbase) {
        log_fatal("failed to init eventbase: %s", sb_util_strerror(errno));
        return 1;
    }

    app->eventbase = eventbase;

    /* setup signal handlers */
    log_info("setting up signal handlers");
    app->sigterm_event = evsignal_new(eventbase, SIGTERM, sb_sigterm_handler, app);
    app->sigint_event = evsignal_new(eventbase, SIGINT, sb_sigint_handler, app);
    app->sighup_event = evsignal_new(eventbase, SIGHUP, sb_sighup_handler, app);
    event_add(app->sigterm_event, 0);
    event_add(app->sigint_event, 0);
    event_add(app->sighup_event, 0);

    log_info("setting up tun device");
    if (strncmp(app->config->dev, "auto", IFNAMSIZ) == 0) {
        log_info("dev in config file is auto, will allow system allocate name");
        app->tunname[0] = 0;
    } else if (strncmp(app->config->dev, "", IFNAMSIZ) == 0 ) {
        log_info("dev in config file is not set, will use "SB_TUN_DEV_NAME);
        strncpy(app->tunname, SB_TUN_DEV_NAME, sizeof(app->tunname));
    } else {
        log_info("dev in config file is %s", app->config->dev);
        strncpy(app->tunname, app->config->dev, sizeof(app->tunname));
    }
    int tun_fd = sb_setup_tun(app);
    if (tun_fd < 0) {
        log_fatal("failed to setup tun device");
        return 1;
    }
    log_info("tun device created with fd %d", tun_fd);

    if (evutil_make_socket_nonblocking(tun_fd) < 0) {
        log_fatal("failed to set tun_fd to nonblock: %s", sb_util_strerror(errno));
        return 1;
    }
    app->tun_fd = tun_fd;

    log_info("starting tun IO");
    struct event * tun_readevent = event_new(eventbase, tun_fd, EV_READ|EV_PERSIST, sb_do_tun_read, app);
    struct event * tun_writeevent = event_new(eventbase, tun_fd, EV_WRITE|EV_PERSIST, sb_do_tun_write, app);
    event_add(tun_readevent, 0);
    event_add(tun_writeevent, 0);

    app->tun_readevent = tun_readevent;
    app->tun_writeevent = tun_writeevent;

    if (app->config->app_mode == SB_SERVER) {
        log_info("run as server");
        log_info("setting up vpn address for server");
        if (sb_config_tun_addr(app->tunname, &app->config->addr, &app->config->mask, app->config->mtu) < 0) {
            log_fatal("failed to setup tun address");
            return 1;
        }
        struct sockaddr_in listen_addr;
        int server_fd;
        memset(&listen_addr, 0, sizeof(listen_addr));
        listen_addr.sin_family = AF_INET;
        listen_addr.sin_addr = app->config->bind;
        listen_addr.sin_port = htons(app->config->port);
        server_fd = sb_server_socket(app->config->net_mode, &listen_addr, sizeof(listen_addr));
        if (server_fd < 0) {
            log_fatal("failed to setup server socket for ipv4.");
            return 1;
        } else {
            log_info("listening on %s %s:%d",
                    (app->config->net_mode == SB_NET_MODE_TCP ? "TCP" : "UDP"),
                    sb_util_human_addr(AF_INET, &app->config->bind),
                    app->config->port);

            if (app->config->net_mode == SB_NET_MODE_TCP) {
                struct event *accept_ev;
                accept_ev = event_new(eventbase, server_fd, EV_READ|EV_PERSIST, sb_do_tcp_accept, app);
                event_add(accept_ev, 0);
            } else {
                struct event * udp_readevent;
                struct event * udp_writeevent;

                udp_readevent = event_new(eventbase, server_fd, EV_READ|EV_PERSIST, sb_do_udp_read, app);
                udp_writeevent = event_new(eventbase, server_fd, EV_WRITE|EV_PERSIST, sb_do_udp_write, app);
                event_add(udp_readevent, 0);
                event_add(udp_writeevent, 0);
                app->udp_readevent = udp_readevent;
                app->udp_writeevent = udp_writeevent;
            }
        }
    } else {
        log_info("run as client");
        /* client mode */
        sb_try_client_connect(-1, 0, app);
    }

    /* Start the event loop. */
    event_base_dispatch(eventbase);

    event_base_free(eventbase);

    log_info("destroying myself, bye");

    sb_app_del(app);

    return 0;
}

