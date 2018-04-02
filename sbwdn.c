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

#include "sb_log.h"
#include "sb_config.h"
#include "sb_util.h"
#include "sb_tun.h"
#include "sb_net.h"
#include "sb_proto.h"
#include "sbwdn.h"


static void libevent_log(int severity, const char *msg) {
    int lvl;
    switch (severity) {
        case EVENT_LOG_DEBUG:
            lvl = LOG_DEBUG; break;
        case EVENT_LOG_MSG:
            lvl = LOG_INFO;  break;
        case EVENT_LOG_WARN:
            lvl = LOG_WARN;  break;
        case EVENT_LOG_ERR:
            lvl = LOG_ERROR; break;
        default:
            lvl = LOG_INFO;  break;
    }
    log_log(lvl, "", 0, "libevent: %s", msg);
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
        struct in_addr saddr = *(struct in_addr *)&(iphdr->saddr);
        struct in_addr daddr = *(struct in_addr *)&(iphdr->daddr);
        unsigned int ipdatalen = tun_frame_size - sizeof(struct sb_tun_pi);
        log_trace("src addr: %s", sb_util_human_addr(AF_INET, &saddr));
        log_trace("dst addr: %s", sb_util_human_addr(AF_INET, &daddr));
        log_trace("ip pkg len: %d", ipdatalen);

        struct sb_connection * conn;
        TAILQ_FOREACH(conn, &(app->conns), entries) {
            bool enable_net_write = false;
            log_trace("conn addr: %d, pkg addr: %d", conn->peer_vpn_addr.s_addr, daddr.s_addr);
            if (app->config->app_mode == SB_CLIENT || conn->peer_vpn_addr.s_addr == daddr.s_addr) {
                if (conn->net_state != ESTABLISHED_2) {
                    log_debug("received pkg from tun, but connection is not in established state for %s", conn->desc);
                } else if (conn->t2n_pkg_count >= SB_PKG_BUF_MAX) {
                    /* should I send a ICMP or something? */
                    log_debug("connection queue full %s", conn->desc);
                } else {
                    struct sb_package * pkg = sb_package_new(SB_PKG_TYPE_DATA_2, (char *)buf, tun_frame_size);
                    if (!pkg) {
                        log_error("failed to create a sb_package for %s, dropping", conn->desc);
                        break;
                    }
                    log_trace("queue a pkg from tun for connection %s", conn->desc);
                    TAILQ_INSERT_TAIL(&(conn->packages_t2n), pkg, entries);
                    conn->t2n_pkg_count++;
                    enable_net_write = true;
                }
            }
            enable_udp_write |= enable_net_write;
            if(enable_net_write && app->config->net_mode == SB_NET_MODE_TCP) {
                log_debug("enabling write for %s", conn->desc);
                event_add(conn->net_writeevent, 0);
            }
        }
        if (enable_udp_write && app->config->net_mode == SB_NET_MODE_UDP) {
            log_debug("enabling write for udp");
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
            disable_tun_write = true;
            break;
        }
        /* send that package into tun */
        log_trace("sending a pkg with length %d to tun", pkg->ipdatalen);
        int ret = write(fd, pkg->ipdata, pkg->ipdatalen);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                log_error("failed to write to tun device: %s", sb_util_strerror(errno));
                break;
            }
        } else {
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

struct sb_app * sb_app_new(struct event_base * eventbase, const char * config_file) {
    struct sb_app * app = malloc(sizeof(struct sb_app));
    if (!app) {
        log_error("failed to allocate memory for sb_app: %s", sb_util_strerror(errno));
        return 0;
    }

    app->config = 0;

    log_info("reading config file %s", config_file);
    struct sb_config * config = sb_config_read(config_file);
    if(!config) {
        log_fatal("failed to read config file %s", config_file);
        return 0;
    }
    log_info("applying config");
    if (sb_config_apply(app, config) < 0) {
        free(config);
        config = 0;
        free(app);
        app = 0;
        return 0;
    }

    app->eventbase = eventbase;

    app->sigterm_event = 0;
    app->sigint_event = 0;

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
    app->conn_timeout_oracle[ESTABLISHED_2] = SB_KEEPALIVE_INTERVAL * 5;
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

    app->eventbase = 0;

    free(app->config);
    app->config = 0;
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
            if (conn->net_mode == SB_NET_MODE_TCP) {
                log_debug("enable net write for %s", conn->desc);
                event_add(conn->net_writeevent, 0);
            }
        }
        if (app->config->net_mode & SB_NET_MODE_UDP) {
            event_add(app->udp_writeevent, 0);
        }
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
    sb_stop_app((struct sb_app *)data, 0);
}

int main(int argc, char ** argv) {
    if (argc != 3 || strlen(argv[1]) != 2 || strncmp(argv[1], "-f", 2) != 0) {
        dprintf(STDERR_FILENO, "Usage: %s -f [config file path]\n", argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        log_fatal("only root can run, exiting");
        return 1;
    }

#ifndef SB_DEBUG
    log_info("mutating to a daemon, a happy daemon");
    if (daemon(0, 0) < 0) {
        log_fatal("failed to mutate to a daemon, are you oric?");
        return 1;
    }
    log_info("hello, I am a daemon");
#endif

    FILE * pidf = fopen(SB_PID_FILE, "w");
    if (!pidf) {
        log_error("failed to open pid file %s", SB_PID_FILE);
    } else {
        log_info("written pid %d to %s", getpid(), SB_PID_FILE);
        fprintf(pidf, "%d", getpid());
        fclose(pidf);
        pidf = 0;
    }

    /* default log level */
    sb_logger.lvl = LOG_INFO;
    sb_logger.fp = fopen(SB_DEFAULT_LOG_PATH, "ae");
    if (!sb_logger.fp) {
        log_fatal("failed to open default log file %s", SB_DEFAULT_LOG_PATH);
        return 1;
    }
    if (setvbuf(sb_logger.fp, 0, _IONBF, 0) != 0) {
        log_error("failed to set default log file as unbuffered %s", SB_DEFAULT_LOG_PATH);
        return -1;
    }

    /* setup libevent */
    // setup libevent log
    event_set_log_callback(libevent_log);

    log_info("setting up libevent");
    struct event_config * event_cfg = event_config_new();
    struct event_base * eventbase = event_base_new_with_config(event_cfg);
#ifdef __APPLE__
    /* apple's tun don't support kqueue*/
    event_config_avoid_method(event_cfg, "kqueue");
#endif
    event_config_free(event_cfg);

    eventbase = event_base_new();
    if (!eventbase) {
        log_fatal("failed to init eventbase: %s", sb_util_strerror(errno));
        return 1;
    }

    char * config_file = argv[2];
    struct sb_app * app = sb_app_new(eventbase, config_file);
    if (!app) {
        log_fatal("faied to init sb_app");
        return 1;
    }

    /* setup signal handlers */
    /* call sighup_function on a HUP signal */
    log_info("setting up signal handlers");
    app->sigterm_event = evsignal_new(eventbase, SIGTERM, sb_sigterm_handler, app);
    app->sigint_event = evsignal_new(eventbase, SIGINT, sb_sigint_handler, app);
    event_add(app->sigterm_event, 0);
    event_add(app->sigint_event, 0);

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
        /* client mode */
        sb_try_client_connect(-1, 0, app);
    }

    /* Start the event loop. */
    event_base_dispatch(eventbase);

    event_base_free(eventbase);
    sb_app_del(app);
    return 0;
}

