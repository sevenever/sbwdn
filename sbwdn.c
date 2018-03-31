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
                log_error("failed to receive package from tun: %d %s", errno, strerror(errno));
            }
            break;
        }
        log_trace("read %d bytes from tun", tun_frame_size);

        struct sb_tun_pi pi = *(struct sb_tun_pi *)buf;
        pi.flags = ntohs(pi.flags);
        pi.proto = ntohs(pi.proto);
        log_trace("flags in tun_pi:%04x", pi.flags);
        log_trace("proto in tun_pi:%04x", pi.proto);
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
        char srcbuf[INET_ADDRSTRLEN];
        char dstbuf[INET_ADDRSTRLEN];
        log_trace("src addr: %s, dest addr: %s, ip pkg len: %d",
                inet_ntop(AF_INET, (const void *)&saddr, srcbuf, sizeof(srcbuf)),
                inet_ntop(AF_INET, (const void *)&daddr, dstbuf, sizeof(dstbuf)),
                ipdatalen);

        struct sb_connection * conn;
        TAILQ_FOREACH(conn, &(app->conns), entries) {
            bool enable_net_write = false;
            log_trace("conn addr: %d, pkg addr: %d", conn->peer_vpn_addr.s_addr, daddr.s_addr);
            if (conn->net_state != ESTABLISHED_2) {
                log_debug("received pkg from tun, but connection is not in established state for %s", conn->desc);
            } else if (app->config->app_mode == CLIENT || conn->peer_vpn_addr.s_addr == daddr.s_addr) {
                if (conn->t2n_pkg_count >= SB_PKG_BUF_MAX) {
                    /* should I send a ICMP or something? */
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
                log_error("failed to write to tun device: %d %s", errno, strerror(errno));
                break;
            }
        } else {
            log_trace("sent a pkg with length %d to tun", ret);
            TAILQ_REMOVE(&(conn->packages_n2t), pkg, entries);
            conn->n2t_pkg_count--;
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
        log_error("failed to allocate memory for sb_app: %s", strerror(errno));
        return 0;
    }

    struct sb_config * config = sb_config_read(config_file);
    if(!config) {
        log_fatal("failed to read config file %s", config_file);
        return 0;
    }
    sb_config_apply(app, config);

    app->eventbase = eventbase;

    app->sigterm_event = 0;
    app->sigint_event = 0;

    app->tun_readevent = 0;
    app->tun_writeevent = 0;
    app->udp_readevent = 0;
    app->udp_writeevent = 0;

    TAILQ_INIT(&(app->conns));

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
    app->udp_writeevent = 0;
    app->udp_readevent = 0;
    app->tun_writeevent = 0;
    app->tun_readevent = 0;

    app->sigterm_event = 0;
    app->sigint_event = 0;

    app->eventbase = 0;

    app->config = 0;

    free(app->config);
    app->config = 0;
    free(app);
}

void sb_stop_app(struct sb_app * app, int immiedately) {
    if (immiedately) {
        event_base_loopbreak(app->eventbase);
    } else {
        struct timeval tv;
        memset(&tv, 0, sizeof(struct timeval));
        tv.tv_sec = 5;
        event_base_loopexit(app->eventbase, &tv);

        struct sb_connection * conn;
        TAILQ_FOREACH(conn, &(app->conns), entries) {
            sb_connection_say_bye(conn);
            if (conn->net_mode == SB_NET_MODE_TCP) {
                event_add(conn->net_readevent, 0);
            }
        }
        if (app->config->net_mode & SB_NET_MODE_UDP) {
            event_add(app->udp_writeevent, 0);
        }
    }
}

void sb_sigterm_handler(evutil_socket_t sig, short what, void * data) {
    log_info("SIGTERM received");
    sb_stop_app((struct sb_app *)data, 0);
}

void sb_sigint_handler(evutil_socket_t sig, short what, void * data) {
    log_info("SIGINT received");
    sb_stop_app((struct sb_app *)data, 0);
}

int main(int argc, char ** argv) {
    if (argc != 3 || strlen(argv[1]) != 2 || strncmp(argv[1], "-f", 2) != 0) {
        dprintf(STDERR_FILENO, "Usage: %s -f [config file path]\n", argv[0]);
        return 1;
    }

    /* default log level */
    sb_logger.lvl = LOG_INFO;

    /* setup libevent */
    struct event_base * eventbase;
    // setup libevent log
    event_set_log_callback(libevent_log);

    eventbase = event_base_new();
    if (!eventbase) {
        log_fatal("failed to init eventbase: %s", strerror(errno));
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
    app->sigterm_event = evsignal_new(eventbase, SIGTERM, sb_sigterm_handler, app);
    app->sigint_event = evsignal_new(eventbase, SIGINT, sb_sigint_handler, app);
    event_add(app->sigterm_event, 0);
    event_add(app->sigint_event, 0);

    int tun_fd = setup_tun(&app->config->addr, &app->config->paddr, &app->config->mask, app->config->mtu);
    if (tun_fd < 0) {
        log_fatal("failed to setup tun device");
        return 1;
    }
    if (evutil_make_socket_nonblocking(tun_fd) < 0) {
        log_fatal("failed to set tun_fd to nonblock: %s", strerror(errno));
        return -1;
    }
    app->tun_fd = tun_fd;

    struct event * tun_readevent = event_new(eventbase, tun_fd, EV_READ|EV_PERSIST, sb_do_tun_read, app);
    struct event * tun_writeevent = event_new(eventbase, tun_fd, EV_WRITE|EV_PERSIST, sb_do_tun_write, app);
    event_add(tun_readevent, 0);
    event_add(tun_writeevent, 0);

    app->tun_readevent = tun_readevent;
    app->tun_writeevent = tun_writeevent;

    if (app->config->app_mode == SERVER) {
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
        int client_fd;
        /* client mode */
        log_info("connecting to %s:%d", app->config->remote, app->config->port);
        struct addrinfo hint, *ai, *ai0;
        memset(&hint, 0, sizeof(hint));
        hint.ai_family = AF_INET;
        hint.ai_socktype = (app->config->net_mode == SB_NET_MODE_TCP ? SOCK_STREAM : SOCK_DGRAM);
        if (getaddrinfo(app->config->remote, 0, &hint, &ai0)) {
            log_error("failed to resolve server address %s", app->config->remote);
            return 1;
        }
        client_fd = -1;
        struct sockaddr_in peer_addr;
        for(ai=ai0;ai;ai = ai->ai_next) {
            if (ai->ai_family == AF_INET) {
                ((struct sockaddr_in *)(ai->ai_addr))->sin_port = htons(app->config->port);
                if ((client_fd = sb_client_socket(app->config->net_mode, (struct sockaddr_in *)ai->ai_addr, ai->ai_addrlen)) < 0) {
                    log_fatal("failed to setup client socket");
                } else {
                    peer_addr = *((struct sockaddr_in *)(ai->ai_addr));
                }
            }
        }
        if (client_fd < 0) {
            return 1;
        }
        log_info("connected to %s:%d", app->config->remote, app->config->port);
        struct sb_connection * conn = sb_connection_new(app, client_fd, app->config->net_mode, peer_addr);
        if (!conn) {
            log_error("failed to init connection for net fd %d", client_fd);
            return 1;
        }
        sb_connection_set_vpn_peer(conn, app->config->paddr);
        /* put a initial package into packages_t2n, so that it can be send to server */
        struct sb_package * init_pkg = sb_package_new(SB_PKG_TYPE_INIT_1, (char *)&app->config->addr, sizeof(app->config->addr));
        if (!init_pkg) {
            log_error("failed to create init pkg");
            return 1;
        }
        TAILQ_INSERT_TAIL(&(conn->packages_t2n), init_pkg, entries);
        conn->t2n_pkg_count++;
        conn->net_state = CONNECTED_1;
        log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
        if (app->config->net_mode == SB_NET_MODE_TCP) {
            event_add(conn->net_readevent, 0);
            event_add(conn->net_writeevent, 0);
        } else {
            struct event * udp_readevent;
            struct event * udp_writeevent;

            udp_readevent = event_new(eventbase, client_fd, EV_READ|EV_PERSIST, sb_do_udp_read, app);
            udp_writeevent = event_new(eventbase, client_fd, EV_WRITE|EV_PERSIST, sb_do_udp_write, app);
            event_add(udp_readevent, 0);
            event_add(udp_writeevent, 0);
            app->udp_readevent = udp_readevent;
            app->udp_writeevent = udp_writeevent;
        }
    }

    /* Start the event loop. */
    event_base_dispatch(eventbase);

    event_base_free(eventbase);
    sb_app_del(app);
    return 0;
}

