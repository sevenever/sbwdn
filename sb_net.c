#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/route.h>

#include "sb_log.h"
#include "sb_util.h"
#include "sb_config.h"
#include "sb_net.h"
#include "sb_proto.h"

#include "sbwdn.h"

int sb_client_socket(unsigned int mode, struct sockaddr_in * server_addr, socklen_t addr_len) {
    int fd = -1;
    int fail = 0;

    do {
        /* Create our listening socket. */
        fd = socket(server_addr->sin_family, (mode == SB_NET_MODE_TCP ? SOCK_STREAM : SOCK_DGRAM), 0);
        if (fd < 0) {
            log_fatal("failed to create client socket: %s", errno, sb_util_strerror(errno));
            fail = 1;
            break;
        }
        if (mode == SB_NET_MODE_TCP) {
            int ret = connect(fd, (struct sockaddr *)server_addr, addr_len);
            if (ret<0) {
                log_fatal("failed to connect to server %s", sb_util_strerror(errno));
                fail = 1;
                break;
            }
        } else {
            if (sb_set_no_frament(fd) < 0) {
                log_error("failed to set no fragment");
                fail = 1;
                break;
            }
        }
        if (evutil_make_socket_closeonexec(fd) < 0) {
            log_fatal("failed to set client socket to closeonexec: %s", sb_util_strerror(errno));
            fail = 1;
            break;
        }
        /* Set the socket to non-blocking, this is essential in event
         * based programming with libevent. */
        if (evutil_make_socket_nonblocking(fd) < 0) {
            log_fatal("failed to set client socket to nonblock: %s", sb_util_strerror(errno));
            fail = 1;
            break;
        }
    } while(0);

    if (fail && fd >= 0) {
        close(fd);
        fd = -1;
    }
    return fd;

    return fd;
}

int sb_server_socket(unsigned int mode, struct sockaddr_in * listen_addr, socklen_t addr_len) {
    int server_fd = -1;
    int fail = 0;
    /* Create our listening socket. */
    do {
        server_fd = socket(listen_addr->sin_family, (mode == SB_NET_MODE_TCP ? SOCK_STREAM : SOCK_DGRAM), 0);
        if (server_fd < 0) {
            log_fatal("failed to create server socket: %s", sb_util_strerror(errno));
            fail = 1;
            break;
        }
        if (evutil_make_listen_socket_reuseable(server_fd) < 0) {
            log_fatal("failed to set server socket to reuseable: %s", sb_util_strerror(errno));
            fail = 1;
            break;
        }
        if (bind(server_fd, (struct sockaddr *)listen_addr, addr_len) < 0) {
            log_fatal("failed to bind: %s", sb_util_strerror(errno));
            fail = 1;
            break;
        }
        if (mode == SB_NET_MODE_TCP) {
            if (listen(server_fd, 5) < 0) {
                log_fatal("failed to listen: %s", sb_util_strerror(errno));
                fail = 1;
                break;
            }
        } else {
            if (sb_set_no_frament(server_fd) < 0) {
                log_error("failed to set no fragment");
                fail = 1;
                break;
            }
        }
        if (evutil_make_socket_closeonexec(server_fd) < 0) {
            log_fatal("failed to set server socket to closeonexec: %s", sb_util_strerror(errno));
            fail = 1;
            break;
        }
        /* Set the socket to non-blocking, this is essential in event
         * based programming with libevent. */
        if (evutil_make_socket_nonblocking(server_fd) < 0) {
            log_fatal("failed to set server socket to nonblock: %s", sb_util_strerror(errno));
            fail = 1;
            break;
        }

    } while (0);
    if (fail && server_fd >= 0) {
        close(server_fd);
        server_fd = -1;
    }
    return server_fd;
}

int sb_set_no_frament(int fd) {
#if defined(IP_DONTFRAG)
    int val = 1;

    log_debug("setting IP_DONTFRAG");
    if (setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &val, sizeof(int)) < 0) {
        log_error("failed to set IP_DONTFRAG for fd %d", fd);
        return -1;
    }
#elif defined(IP_MTU_DISCOVER)
    int val = 1;

    log_debug("setting IP_MTU_DISCOVER");
    if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(int)) < 0) {
        log_error("failed to set IP_DONTFRAG for fd %d", fd);
        return -1;
    }
#else
    /* really don't know how to do this on mac, just shut compiler up*/
    SB_NOT_USED(fd);
#endif
    return 0;
}

int sb_net_io_buf_init(struct sb_net_io_buf * io_buf, struct sb_connection * conn) {
    io_buf->buf = malloc(sizeof(struct sb_net_buf));
    if (!io_buf->buf) {
        log_error("failed to allocate a sb_net_buf %s", sb_util_strerror(errno));
        return -1;
    }
    io_buf->state = HDR;
    io_buf->cur_pkg = 0;
    io_buf->cur_p = (char *)io_buf->buf;
    io_buf->pkg_len = 0;
    io_buf->conn = conn;

    return 0;
}

void sb_net_io_buf_del(struct sb_net_io_buf * io_buf) {
    io_buf->conn = 0;
    io_buf->pkg_len = 0;
    io_buf->cur_p = (char *)io_buf->buf;
    io_buf->cur_pkg = 0;
    io_buf->state = HDR;
    if (io_buf->buf) {
        free(io_buf->buf);
        io_buf->buf = 0;
    }

    return;
}

int sb_net_io_buf_read(struct sb_net_io_buf * read_buf, int fd) {
    int buflen;
    if (read_buf->state == HDR) {
        buflen = SB_NET_BUF_HEADER_SIZE - (read_buf->cur_p - (const char *)read_buf->buf);
    } else if (read_buf->state == PKG) {
        buflen = read_buf->pkg_len - (read_buf->cur_p - read_buf->buf->pkg_buf);
    } else {
        log_warn("invalid read_buf->state: %d", read_buf->state);
        return -1;
    }
    log_trace("trying to read %d bytes from %s", buflen, read_buf->conn->desc);
    int ret = recv(fd, read_buf->cur_p, buflen, 0);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            log_trace("no more data available from %s", read_buf->conn->desc);
            return 0;
        } else {
            /* error */
            log_error("failed to receive data from connection %s: %s", read_buf->conn->desc, sb_util_strerror(ret));
            return -1;
        }
    } else if (ret == 0) {
        /* EOF */
        return 2;
    } else {
        log_trace("read %d bytes from %s", ret, read_buf->conn->desc);
        /* some bytes were read */
        if (ret < buflen) {
            /* read less than we want */
            read_buf->cur_p += ret;
        } else if (ret > buflen) {
            log_warn("read from %s more bytes than request, impossible", read_buf->conn->desc);
            return -1;
        } else {
            /* read equals we want */
            if (read_buf->state == HDR) {
                read_buf->pkg_len = ntohl(read_buf->buf->len_buf);
                read_buf->cur_p = read_buf->buf->pkg_buf;
                read_buf->state = PKG;
            } else if (read_buf->state == PKG) {
                log_trace("a full package of length %d is read from %s", read_buf->pkg_len, read_buf->conn->desc);
                /* full package is read, construct a sb_package, put into conn->packages_n2t */
                struct sb_package * pkg = sb_package_new(ntohl(read_buf->buf->type_buf), read_buf->buf->pkg_buf, read_buf->pkg_len);
                if (!pkg) {
                    log_error("failed to create a sb_package for %s", read_buf->conn->desc);
                    return -1;
                } else {
                    read_buf->cur_pkg = pkg;
                }
                read_buf->cur_p = (char *)read_buf->buf;
                read_buf->state = HDR;
            } else {
                log_warn("invalid read_buf->state: %d", read_buf->state);
                return -1;
            }
        }
        return 1;
    }
}

int sb_net_io_buf_write(struct sb_net_io_buf * write_buf, int fd) {
    int buflen = SB_NET_BUF_HEADER_SIZE + write_buf->pkg_len - (write_buf->cur_p - (const char *)write_buf->buf);
    log_trace("writing %d bytes to %s", buflen, write_buf->conn->desc);
    int ret = send(fd, write_buf->cur_p, buflen, 0);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            log_trace("net is not writable to %s", write_buf->conn->desc);
            return 0;
        }
        /* error */
        log_error("failed to send to net %s, %s", write_buf->conn->desc, sb_util_strerror(errno));
        return -1;
    } else {
        log_trace("written %d bytes to %s", ret, write_buf->conn->desc);
        write_buf->cur_p += ret;
        if (ret == buflen) {
            write_buf->cur_pkg = 0;
            write_buf->cur_p = (char *)write_buf->buf;
        }
        return 1;
    }
}

void sb_do_tcp_accept(evutil_socket_t listen_fd, short what, void * data) {
    SB_NOT_USED(what);
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, (socklen_t*)&addr_len);
    if (client_fd < 0) {
        log_error("failed to accept: %s", sb_util_strerror(errno));
        return;
    } else {
        log_info("accepted connection from %s.", sb_util_human_endpoint((struct sockaddr *)&client_addr));

        if (evutil_make_socket_nonblocking(client_fd) < 0) {
            log_error("failed to set client socket to nonblock: %s", sb_util_strerror(errno));
            close(client_fd);
            return;
        }
        if (sb_set_no_frament(client_fd) < 0) {
            log_error("failed to set no fragment");
            return;
        }
        struct sb_app * app = data;
        struct sb_connection * conn = sb_connection_new(app, client_fd, SB_NET_MODE_TCP, *((struct sockaddr_in *)&client_addr));
        if (!conn) {
            log_error("failed to init connection for net fd %d", client_fd);
            return;
        }
        event_add(conn->net_readevent, 0);
    }
}

void sb_try_client_connect(evutil_socket_t notused, short what, void * data) {
    SB_NOT_USED(notused);
    SB_NOT_USED(what);

    struct sb_app * app = data;
    struct sb_connection * conn = 0;

    do {
        int client_fd = -1;

        log_info("connecting to %s:%d", app->config->remote, app->config->port);
        struct addrinfo hint, *ai, *ai0;
        memset(&hint, 0, sizeof(hint));
        hint.ai_family = AF_INET;
        hint.ai_socktype = (app->config->net_mode == SB_NET_MODE_TCP ? SOCK_STREAM : SOCK_DGRAM);
        if (getaddrinfo(app->config->remote, 0, &hint, &ai0)) {
            log_error("failed to resolve server address %s", app->config->remote);
            break;
        }
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
            break;
        }
        log_info("connected to %s:%d", app->config->remote, app->config->port);
        conn = sb_connection_new(app, client_fd, app->config->net_mode, peer_addr);
        if (!conn) {
            log_error("failed to init connection for net fd %d", client_fd);
            break;
        }

        log_info("saying hello to server");
        sb_connection_say_hello(conn);

        log_debug("starting network IO");
        if (app->config->net_mode == SB_NET_MODE_TCP) {
            event_add(conn->net_readevent, 0);
            event_add(conn->net_writeevent, 0);
        } else {
            struct event * udp_readevent;
            struct event * udp_writeevent;

            /* client_fd may be the same as previous one, so we need to ensure event_free previous event before event_add new event */
            if (app->udp_readevent) {
                event_del(app->udp_readevent);
                event_free(app->udp_readevent);
            }
            if (app->udp_writeevent) {
                event_del(app->udp_writeevent);
                event_free(app->udp_writeevent);
            }
            udp_readevent = event_new(app->eventbase, client_fd, EV_READ|EV_PERSIST, sb_do_udp_read, app);
            udp_writeevent = event_new(app->eventbase, client_fd, EV_WRITE|EV_PERSIST, sb_do_udp_write, app);
            event_add(udp_readevent, 0);
            event_add(udp_writeevent, 0);
            app->udp_readevent = udp_readevent;
            app->udp_writeevent = udp_writeevent;
        }
    } while(0);

    if (!conn) {
        sb_schedule_reconnect(app);
    }
}

void sb_schedule_reconnect(struct sb_app * app) {
    if (app->dont_reconnect) {
        log_info("app dont_reconnect is set, will not reconnect");
        return;
    }
    /* failed, retry later */
    if(!app->reconnect_event) {
        log_trace("creating reconnect_event");
        app->reconnect_event = event_new(app->eventbase, -1, 0, sb_try_client_connect, app);
    }
    struct timeval interval;
    memset(&interval, 0, sizeof(struct timeval));
    interval.tv_sec = app->retry_interval;
    log_warn("failed to connect to server, will retry in %d seconds", app->retry_interval);
    event_add(app->reconnect_event, &interval);

    if (app->retry_interval < SB_CLIENT_RETRY_INTERVAL_MAX) {
        app->retry_interval *= 2;
        app->retry_interval = app->retry_interval > SB_CLIENT_RETRY_INTERVAL_MAX ? SB_CLIENT_RETRY_INTERVAL_MAX : app->retry_interval;
    }
}

void sb_stop_reconnect(struct sb_app * app) {
    if (app->reconnect_event) {
        event_del(app->reconnect_event);
        event_free(app->reconnect_event);
        app->reconnect_event = 0;
    }
    app->retry_interval = 1;
}

void sb_do_tcp_read(evutil_socket_t fd, short what, void * data) {
    SB_NOT_USED(what);
    struct sb_connection * conn = data;
    struct sb_net_io_buf * read_buf = &conn->net_read_io_buf;
    struct sb_app * app = conn->app;

    /* read net fd, until error/EOF/EAGAIN */
    log_enter_func();
    while (1) {
        int ret = sb_net_io_buf_read(read_buf, fd);
        if (ret < 0) {
            log_error("failed to read from %s", conn->desc);
        } else if (ret == 0) {
            /* fd not readable, wait */
            break;
        } else if (ret == 1) {
            if (read_buf->cur_pkg) {
                if (!sb_conn_net_received_pkg(conn, read_buf->cur_pkg)) {
                    free(read_buf->cur_pkg->ipdata);
                    read_buf->cur_pkg->ipdata = 0;
                    free(read_buf->cur_pkg);
                    read_buf->cur_pkg = 0;
                }
                read_buf->cur_pkg = 0;
                if (conn->net_state == TERMINATED_4) {
                    break;
                }
            }
        } else if (ret == 2) {
            /* EOF */
            log_info("net peer closed connection, closing net connection for %s",  conn->desc);
            sb_connection_change_net_state(conn, TERMINATED_4);
            if (conn->net_state == TERMINATED_4) {
                break;
            }
            break;
        }
    }

    if (conn && conn->net_state != TERMINATED_4) {
        if (conn->n2t_pkg_count > 0) {
            log_debug("enabling tun write for %s", conn->desc);
            event_add(app->tun_writeevent, 0);

        }
        if (conn->t2n_pkg_count > 0) {
            log_debug("enabling net write for %s", conn->desc);
            event_add(conn->net_writeevent, 0);
        }
    }
    log_exit_func();
    return;
}

void sb_do_udp_read(evutil_socket_t fd, short what, void * data) {
    SB_NOT_USED(what);
    /* read an udp package */
    struct sb_app * app = data;
    struct sb_net_buf buf;
    struct sockaddr_in peer_addr;
    unsigned int addrlen;

    bool enable_tun_write = false;
    bool enable_net_write = false;

    int ret;
    log_enter_func();
    while(1) {
        addrlen = sizeof(peer_addr);
        ret = recvfrom(fd, &buf, sizeof(struct sb_net_buf), 0, (struct sockaddr *)&peer_addr, &addrlen);
        if (ret < 0) {
            if (errno == EAGAIN && errno == EWOULDBLOCK) {
                /* not readable, just wait */
            } else {
                log_error("failed to receive a udp package from net %s", sb_util_strerror(errno));
            }
            break;
        }
        if (ret == 0) {
            log_warn("received a 0 length udp package from %s", sb_util_human_endpoint((struct sockaddr *)&peer_addr));
            continue;
        }
        if (peer_addr.sin_family != AF_INET || addrlen != sizeof(struct sockaddr_in)) {
            log_warn("received a package from unsupported address: sa_family %d, addrlen %d", peer_addr.sin_family, addrlen);
            continue;
        }
        unsigned short pkg_len = ntohl(buf.len_buf);
        if (pkg_len != ret - SB_NET_BUF_HEADER_SIZE) {
            log_warn("received udp package length(%d) != declared length(%d) from %s", ret - SB_NET_BUF_HEADER_SIZE, pkg_len, sb_util_human_endpoint((struct sockaddr *)&peer_addr));
            continue;
        }
        /* full package is read */
        struct sb_connection * conn, * existing_conn = 0;
        TAILQ_FOREACH(conn, &(app->conns), entries) {
            if (sb_util_sockaddr_cmp((struct sockaddr *)&conn->peer_addr, (struct sockaddr *)&peer_addr) == 0) {
                existing_conn = conn;
                break;
            }
        }
        unsigned int type = ntohl(buf.type_buf);
        if (type == SB_PKG_TYPE_INIT_1) {
            if (existing_conn) {
                log_debug("received INIT pkg from %s, ignoring", existing_conn->desc);
                continue;
            }
            conn = sb_connection_new(app, fd, SB_NET_MODE_UDP, peer_addr);
            if (!conn) {
                log_error("failed to init connection for client %s", sb_util_human_endpoint((struct sockaddr *)&peer_addr));
                continue;
            }
            /* queue a cookie to send to client */
            if (sb_util_random(conn->cookie, SB_COOKIE_SIZE) < 0) {
                log_error("failed to generate cookie data for connection %s", conn->desc);
                continue;
            }
        } else {
            if (existing_conn) {
                conn = existing_conn;
            } else {
                log_warn("no connection for incoming pkg from %s", sb_util_human_endpoint((struct sockaddr *)&peer_addr));
                continue;
            }
        }
        struct sb_package * pkg = sb_package_new(type, (char *)buf.pkg_buf, pkg_len);
        if (!pkg) {
            log_error("failed to create a sb_package for %s, dropping", conn->desc);
            continue;
        }
        if (!sb_conn_net_received_pkg(conn, pkg)) {
            free(pkg->ipdata);
            pkg->ipdata = 0;
            free(pkg);
            pkg = 0;
        }
        if (conn && conn->net_state != TERMINATED_4 && conn->n2t_pkg_count > 0) {
            enable_tun_write = true;
        }
        if (conn && conn->net_state != TERMINATED_4 && conn->t2n_pkg_count > 0) {
            enable_net_write = true;
        }
    }
    if (enable_tun_write) {
        log_debug("enabling tun write");
        event_add(app->tun_writeevent, 0);
    }
    if (enable_net_write) {
        log_debug("enabling net write");
        event_add(app->udp_writeevent, 0);
    }
    log_exit_func();
    return;
}

void sb_do_tcp_write(evutil_socket_t fd, short what, void * data) {
    SB_NOT_USED(what);
    struct sb_connection * conn = data;
    struct sb_app * app = conn->app;
    struct sb_net_io_buf * write_buf = &conn->net_write_io_buf;
    bool disable_net_write = false;

    log_enter_func();
    while (1) {
        if (!(write_buf->cur_pkg)) {
            /* prepare data for write_buf */
            write_buf->cur_pkg = TAILQ_FIRST(&(conn->packages_t2n));
            if (!write_buf->cur_pkg) {
                log_trace("no pkg ready to be sent to net %s", conn);
                disable_net_write = true;
                break;
            }
            write_buf->buf->type_buf = htonl(write_buf->cur_pkg->type);
            write_buf->buf->len_buf = htonl(write_buf->cur_pkg->ipdatalen);
            memcpy(write_buf->buf->pkg_buf, write_buf->cur_pkg->ipdata, write_buf->cur_pkg->ipdatalen);
            write_buf->cur_p = (char *)write_buf->buf;
            write_buf->pkg_len = write_buf->cur_pkg->ipdatalen;
        }
        struct sb_package * writing_pkg = write_buf->cur_pkg;
        int ret = sb_net_io_buf_write(&(conn->net_write_io_buf), fd);
        if (ret < 0) {
            log_error("failed to write to %s", conn->desc);
            /* close connection? */
        } else if (ret == 0) {
            /* fd not writable, wait */
            break;
        } else if (ret == 1) {
            if (!write_buf->cur_pkg) {
                /* a full package is written */
                if (writing_pkg->type == SB_PKG_TYPE_BYE_3 && app->config->app_mode == SB_CLIENT) {
                    sb_connection_change_net_state(conn, TERMINATED_4);
                    if (conn->net_state == TERMINATED_4) {
                        break;
                    }
                } else {
                    /* statistics */
                    conn->stat.net_egress_pkgs++;
                    conn->stat.net_egress_bytes += writing_pkg->ipdatalen;
                    TAILQ_REMOVE(&(conn->packages_t2n), writing_pkg, entries);
                    conn->t2n_pkg_count--;
                    free(writing_pkg->ipdata);
                    writing_pkg->ipdata = 0;
                    free(writing_pkg);
                    writing_pkg = 0;
                }
            }
        }
    }

    if (conn && disable_net_write) {
        log_debug("disabling tcp write of %s", conn->desc);
        event_del(conn->net_writeevent);
    }
    log_exit_func();
    return;
}

void sb_do_udp_write(evutil_socket_t fd, short what, void * data) {
    SB_NOT_USED(what);
    struct sb_app * app = data;
    struct sb_net_buf buf;

    int ret;
    bool disable_net_write = false;

    log_enter_func();
    while(1) {
        /* prepare a buf */
        struct sb_connection * conn;
        struct sb_package * pkg = 0;
        TAILQ_FOREACH(conn, &(app->conns), entries) {
            pkg = TAILQ_FIRST(&(conn->packages_t2n));
            if (pkg) {
                break;
            }
        }
        if (!pkg) {
            log_trace("no pkg available in any connection");
            disable_net_write = true;
            break;
        }
        buf.type_buf = htonl(pkg->type);
        buf.len_buf = htonl(pkg->ipdatalen);
        memcpy(buf.pkg_buf, pkg->ipdata, pkg->ipdatalen);
        int frame_size = SB_NET_BUF_HEADER_SIZE + pkg->ipdatalen;
        log_debug("writing a pkg with length %d to %s", frame_size, conn->desc);
        ret = sendto(fd, &buf, frame_size, 0, (const struct sockaddr *)&conn->peer_addr, sizeof(conn->peer_addr));
        if (ret < 0) {
            log_debug("failed to send package to %s: %s, dropping", sb_util_human_endpoint((struct sockaddr *)&conn->peer_addr), sb_util_strerror(errno));
        } else {
            if (ret < frame_size) {
                log_warn("send truncated package to %s", sb_util_human_endpoint((struct sockaddr *)&conn->peer_addr));
            }
        }
        if (pkg->type == SB_PKG_TYPE_BYE_3) {
            sb_connection_change_net_state(conn, TERMINATED_4);
            if (conn->net_state == TERMINATED_4) {
                continue;
            }
        } else {
            /* statistics */
            conn->stat.net_egress_pkgs++;
            conn->stat.net_egress_bytes += pkg->ipdatalen;
            TAILQ_REMOVE(&conn->packages_t2n, pkg, entries);
            conn->t2n_pkg_count--;
            free(pkg->ipdata);
            pkg->ipdata = 0;
            free(pkg);
            pkg = 0;
        }
    }
    if (disable_net_write) {
        log_debug("disabling udp write");
        event_del(app->udp_writeevent);
    }
    log_exit_func();
    return;
}

int sb_modify_route(unsigned int op, struct in_addr * dst, struct in_addr * netmask, struct in_addr * gw) {
#if defined(__linux__)
    int s, ret, fail = 0;
    struct rtentry route;
    struct sockaddr_in *addr;


    do {
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
            log_error("failed to create socket %s", sb_util_strerror(errno));
            fail = 1;
            break;
        }

        addr = (struct sockaddr_in*) &route.rt_gateway;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = gw->s_addr;
        addr = (struct sockaddr_in*) &route.rt_dst;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = dst->s_addr;
        addr = (struct sockaddr_in*) &route.rt_genmask;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = netmask->s_addr;
        route.rt_dev = 0;
        route.rt_flags = RTF_UP | RTF_GATEWAY;
        route.rt_metric = 0;
        unsigned long req;
        switch(op) {
            case SB_RT_OP_ADD: req = SIOCADDRT; break;
            case SB_RT_OP_DEL: req = SIOCDELRT; break;
        }
        if ((ret = ioctl(s, req, &route)) != 0) {
            log_error("failed to use ioctl to modify routing %s", sb_util_strerror(errno));
            log_error("dst: %s", sb_util_human_addr(AF_INET, dst));
            log_error("mask: %s", sb_util_human_addr(AF_INET, netmask));
            fail = 1;
            break;
        }
    }while(0);

    close(s);

    return fail ? -1 : 0;
#elif defined(__APPLE__)
    SB_NOT_USED(op);
    SB_NOT_USED(dst);
    SB_NOT_USED(netmask);
    SB_NOT_USED(gw);
    return 0;
#endif
}
