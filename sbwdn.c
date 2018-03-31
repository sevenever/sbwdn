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
#include "sbwdn.h"
#include "sb_tun.h"
#include "sb_util.h"


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

static int sb_client_socket(unsigned int mode, struct sockaddr_in * server_addr, socklen_t addr_len) {
    int fd;
    /* Create our listening socket. */
    fd = socket(server_addr->sin_family, (mode == SB_NET_MODE_TCP ? SOCK_STREAM : SOCK_DGRAM), 0);
    if (fd < 0) {
        log_fatal("failed to create client socket: %d %s", errno, strerror(errno));
        return -1;
    }
    if (mode == SB_NET_MODE_TCP) {
        int ret = connect(fd, (struct sockaddr *)server_addr, addr_len);
        if (ret<0) {
            log_fatal("failed to connect to server %d %s", errno, strerror(errno));
            return -1;
        }
    }
    if (evutil_make_socket_closeonexec(fd) < 0) {
        log_fatal("failed to set client socket to closeonexec: %d %s", errno, strerror(errno));
        return -1;
    }
    /* Set the socket to non-blocking, this is essential in event
     * based programming with libevent. */
    if (evutil_make_socket_nonblocking(fd) < 0) {
        log_fatal("failed to set client socket to nonblock: %d %s", errno, strerror(errno));
        return -1;
    }

    return fd;
}

static int sb_server_socket(unsigned int mode, struct sockaddr_in * listen_addr, socklen_t addr_len) {
    int server_fd;
    /* Create our listening socket. */
    server_fd = socket(listen_addr->sin_family, (mode == SB_NET_MODE_TCP ? SOCK_STREAM : SOCK_DGRAM), 0);
    if (server_fd < 0) {
        log_fatal("failed to create server socket: %s", strerror(errno));
        return -1;
    }
    if (evutil_make_listen_socket_reuseable(server_fd) < 0) {
        log_fatal("failed to set server socket to reuseable: %s", strerror(errno));
        return -1;
    }
    if (bind(server_fd, (struct sockaddr *)listen_addr, addr_len) < 0) {
        log_fatal("failed to bind: %s", strerror(errno));
        return -1;
    }
    if (mode == SB_NET_MODE_TCP && listen(server_fd, 5) < 0) {
        log_fatal("failed to listen: %s", strerror(errno));
        return -1;
    }
    if (evutil_make_socket_closeonexec(server_fd) < 0) {
        log_fatal("failed to set server socket to closeonexec: %s", strerror(errno));
        return -1;
    }
    /* Set the socket to non-blocking, this is essential in event
     * based programming with libevent. */
    if (evutil_make_socket_nonblocking(server_fd) < 0) {
        log_fatal("failed to set server socket to nonblock: %s", strerror(errno));
        return -1;
    }

    return server_fd;
}

void sb_do_tcp_accept(evutil_socket_t listen_fd, short what, void * data) {
    if (what & EV_READ) {
        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, (socklen_t*)&addr_len);
        if (client_fd < 0) {
            log_error("failed to accept: %s", strerror(errno));
            return;
        } else {
            char addr[INET_ADDRSTRLEN];
            log_info("accepted connection from %s.", inet_ntop(client_addr.ss_family, (const void*)&(((struct sockaddr_in *)&client_addr)->sin_addr), addr, sizeof(addr)));

            if (evutil_make_socket_nonblocking(client_fd) < 0) {
                log_error("failed to set client socket to nonblock: %s", strerror(errno));
                close(client_fd);
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
}

struct sb_package * sb_package_new(unsigned int type, void * ipdata, int ipdatalen) {
    struct sb_package * p = malloc(sizeof(struct sb_package));
    if (!p) {
        log_error("fail to allocate memory for sb_package, %s", strerror(errno));
        return 0;
    }
    p->ipdata = malloc(ipdatalen);
    if (!p->ipdata) {
        log_error("fail to allocate memory for sb_package->ipdata, %s", strerror(errno));
        return 0;
    }

    p->type = type;
    p->ipdatalen = ipdatalen;
    memcpy(p->ipdata, ipdata, ipdatalen);

    return p;
}

struct sb_connection * sb_connection_new(struct sb_app * app, int client_fd, unsigned int mode, struct sockaddr_in peer) {
    struct sb_connection * conn = malloc(sizeof(struct sb_connection));
    if (!conn) {
        log_error("failed to allocate connection object %s", strerror(errno));
        return 0;
    }
    memset(conn, 0, sizeof(struct sb_connection));

    conn->net_fd = client_fd;
    conn->net_mode = mode;
    conn->net_state = NEW_0;

    conn->peer_addr = peer;
    /*peer_vpn_addr is set to 0 by memset above */

    conn->seconds_connected = 0;

    conn->app = app;
    conn->eventbase = app->eventbase;

    struct event * net_readevent = event_new(conn->eventbase, conn->net_fd, EV_READ | EV_PERSIST, sb_do_tcp_read, conn);
    conn->net_readevent = net_readevent;
    struct event * net_writeevent = event_new(conn->eventbase, conn->net_fd, EV_WRITE | EV_PERSIST, sb_do_tcp_write, conn);
    conn->net_writeevent = net_writeevent;

    TAILQ_INIT(&(conn->packages_n2t));
    conn->n2t_pkg_count = 0;
    TAILQ_INIT(&(conn->packages_t2n));
    conn->t2n_pkg_count = 0;

    if (sb_net_io_buf_init(&(conn->net_read_io_buf), conn) < 0) {
        log_error("failed init net read io buffer");
        return 0;
    }
    if (sb_net_io_buf_init(&(conn->net_write_io_buf), conn) < 0) {
        log_error("failed init net write io buffer");
        return 0;
    }

    char buf[INET_ADDRSTRLEN];
    snprintf(conn->desc, SB_CONN_DESC_MAX, "%s[%s:%d(%s)]",
            (conn->app->config->net_mode == SB_NET_MODE_TCP ? "TCP" : "UDP"),
            inet_ntop(AF_INET, &conn->peer_addr.sin_addr, buf, sizeof(buf)),
            conn->peer_addr.sin_port,
            "-");

    TAILQ_INSERT_TAIL(&(app->conns), conn, entries);

    return conn;
}

void sb_connection_set_vpn_peer(struct sb_connection * conn, struct in_addr peer_vpn_addr) {
    conn->peer_vpn_addr = peer_vpn_addr;
    char buf[INET_ADDRSTRLEN];
    char vpnbuf[INET_ADDRSTRLEN];
    snprintf(conn->desc,
            SB_CONN_DESC_MAX,
            "%s[%s:%d(%s)]",
            (conn->app->config->net_mode == SB_NET_MODE_TCP ? "TCP" : "UDP"),
            inet_ntop(AF_INET, &conn->peer_addr.sin_addr, buf, sizeof(buf)),
            ntohs(conn->peer_addr.sin_port),
            inet_ntop(AF_INET, &conn->peer_vpn_addr, vpnbuf, sizeof(vpnbuf)));
}

void sb_connection_del(struct sb_connection * conn) {
    struct sb_app * app = conn->app;

    TAILQ_REMOVE(&(app->conns), conn, entries);

    sb_net_io_buf_del(&(conn->net_write_io_buf));
    sb_net_io_buf_del(&(conn->net_read_io_buf));

    struct sb_package * buf, * buf2;
    buf = TAILQ_FIRST(&(conn->packages_n2t));
    while(buf) {
        buf2 = TAILQ_NEXT(buf, entries);
        free(buf->ipdata);
        buf->ipdata = 0;
        free(buf);
        buf = buf2;
    }
    conn->t2n_pkg_count = 0;

    buf = TAILQ_FIRST(&(conn->packages_t2n));
    while(buf) {
        buf2 = TAILQ_NEXT(buf, entries);
        free(buf->ipdata);
        buf->ipdata = 0;
        free(buf);
        buf = buf2;
    }
    conn->n2t_pkg_count = 0;

    event_free(conn->net_writeevent);
    event_free(conn->net_readevent);

    conn->eventbase = 0;
    conn->app = 0;

    memset(&conn->peer_vpn_addr, 0, sizeof(conn->peer_vpn_addr));

    conn->net_state = TERMINATED_4;
    log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
    if (conn->net_mode == SB_NET_MODE_TCP) {
        close(conn->net_fd);
    }
    log_info("connection disconnected %s", conn->desc);
    conn->net_fd = -1;

    free(conn);
}

int sb_conn_net_received_pkg(struct sb_connection * conn, struct sb_package * pkg) {
    struct sb_app * app = conn->app;
    int queued = 0;

    log_enter_func();
    switch(conn->net_state) {
        case NEW_0:
            /* client */
            if (conn->app->config->app_mode == CLIENT) {
                log_warn("received a package with type %d from %s in state %d, ignoring", pkg->type, conn->desc, conn->net_state);
                break;
            }
            /* server */
            if (pkg->type != SB_PKG_TYPE_INIT_1) {
                log_warn("received a package with type %d from %s in state %d, expecting %d, disconnecting", pkg->type, conn->desc, conn->net_state, SB_PKG_TYPE_INIT_1);
                conn->net_state = TERMINATED_4;
                log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
                break;
            }
            log_trace("received init pkg from %s", conn->desc);
            /* generate a cookie package and send to client */
            struct sb_cookie_pkg_data cookie_data;
            memcpy(&cookie_data.cookie, &conn->cookie, SB_COOKIE_SIZE);
            cookie_data.vpn_addr = app->config->addr;
            struct sb_package * cookie_pkg = sb_package_new(SB_PKG_TYPE_COOKIE_4, &cookie_data, sizeof(struct sb_cookie_pkg_data));
            if (!cookie_pkg) {
                log_error("failed to create cookie package for %s, disconnecting", conn->desc);
                conn->net_state = TERMINATED_4;
                log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
                break;
            }
            TAILQ_INSERT_TAIL(&(conn->packages_t2n), cookie_pkg, entries);
            queued = 1;
            conn->t2n_pkg_count++;
            conn->net_state = CONNECTED_1;
            log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
            break;
        case CONNECTED_1:
            if (pkg->type != SB_PKG_TYPE_COOKIE_4) {
                log_warn("received a package with type %d from %s in state %d, expecting %d, disconnecting", pkg->type, conn->desc, conn->net_state, SB_PKG_TYPE_COOKIE_4);
                conn->net_state = TERMINATED_4;
                log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
                break;
            }
            if (pkg->ipdatalen < sizeof(struct sb_cookie_pkg_data)) {
                log_warn("invalide cookie package length %d from %s", pkg->ipdatalen, conn->desc);
                conn->net_state = TERMINATED_4;
                log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
                break;
            }
            struct sb_cookie_pkg_data * cookie = (struct sb_cookie_pkg_data *)pkg->ipdata;
            /* client */
            if (conn->app->config->app_mode == CLIENT) {
                log_info("received a cookie package, replying cookie to %s", conn->desc);

                /* save to conn */
                sb_connection_set_vpn_peer(conn, cookie->vpn_addr);
                memcpy(conn->cookie, cookie->cookie, SB_COOKIE_SIZE);

                /* send back to server, with vpn_addr set to mine */
                cookie->vpn_addr = app->config->addr;
                TAILQ_INSERT_TAIL(&(conn->packages_t2n), pkg, entries);
                queued = 1;
                conn->t2n_pkg_count++;
                conn->net_state = ESTABLISHED_2;
                log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);

                break;
            }
            /* server */
            if (memcmp(cookie->cookie, conn->cookie, SB_COOKIE_SIZE) != 0) {
                log_warn("invalid cookie from %s, disconnecting", conn->desc);
                conn->net_state = TERMINATED_4;
                log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
                break;
            }
            if (sb_vpn_addr_used(conn->app, cookie->vpn_addr)) {
                log_warn("requested vpn address %s is in use, disconnecting %s", sb_util_human_addr(AF_INET, &cookie->vpn_addr), conn->desc);
                break;
                conn->net_state = TERMINATED_4;
                log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
            }
            /* cookie is valid, now set client vpn_addr */
            sb_connection_set_vpn_peer(conn, cookie->vpn_addr);
            log_info("vpn peer addr is %s", sb_util_human_addr(AF_INET, &conn->peer_vpn_addr));
            conn->net_state = ESTABLISHED_2;
            log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
            break;
        case ESTABLISHED_2:
            if (pkg->type == SB_PKG_TYPE_DATA_2) {
                if (conn->n2t_pkg_count >= SB_PKG_BUF_MAX) {
                    // packages_n2t full
                    log_warn("queue full for %s, dropping", conn->desc);
                    break;
                }
                log_trace("queue a pkg from net %s", conn->desc);
                TAILQ_INSERT_TAIL(&(conn->packages_n2t), pkg, entries);
                queued = 1;
                conn->n2t_pkg_count++;
                log_trace("n2t_pkg_count is %d after insert %s", conn->n2t_pkg_count, conn->desc);
                break;
            } else if (pkg->type == SB_PKG_TYPE_KEEPALIVE_6) {
                sb_conn_handle_keepalive(conn, pkg);
                break;
            } else if (pkg->type == SB_PKG_TYPE_ROUTE_5) {
                if (app->config->app_mode == SERVER) {
                    log_warn("received a route package from client %s, ignoring", conn->desc);
                    break;
                }
                /* client */
                log_warn("received a route package from server %s, adding route", conn->desc);
                sb_conn_handle_route(conn, pkg);
                break;
            } else if (pkg->type == SB_PKG_TYPE_BYE_3) {
                if (app->config->app_mode == SERVER) {
                    log_info("received a bye package from client %s", conn->desc);
                    if (conn->net_mode == SB_NET_MODE_TCP) {
                        /* TCP, will wait for client to close connection or timeout */
                        conn->net_state = CLOSING_3;
                    } else {
                        conn->net_state = TERMINATED_4;
                    }
                    log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
                    break;
                } else {
                    /* client */
                    log_info("received a bye package from server %s", conn->desc);
                    sb_connection_say_bye(conn);
                    break;
                }
            } else {
                log_warn("received a package with type %d from %s in state %d, disconnecting", pkg->type, conn->desc, conn->net_state, SB_PKG_TYPE_COOKIE_4);
                conn->net_state = TERMINATED_4;
                log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
                break;
            }
            break;
        case CLOSING_3:
            log_warn("received a package with type %d from %s in state %d, disconnecting", pkg->type, conn->desc, conn->net_state, SB_PKG_TYPE_COOKIE_4);
            conn->net_state = TERMINATED_4;
            log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
            break;
        case TERMINATED_4:
            log_warn("received a pkg in %d state from %s", conn->net_state, conn->desc);
            break;
        default:
            log_warn("invalid state %d of %s", conn->net_state, conn->desc);
            break;
    }
    log_exit_func();
    return queued;
}

void sb_conn_handle_keepalive(struct sb_connection * conn, struct sb_package * pkg) {

}

void sb_conn_handle_route(struct sb_connection * conn, struct sb_package * pkg) {

}

int sb_vpn_addr_used(struct sb_app * app, struct in_addr vpn_addr) {
    return 0;
}

int sb_net_io_buf_init(struct sb_net_io_buf * io_buf, struct sb_connection * conn) {
    io_buf->buf = malloc(sizeof(struct sb_net_buf));
    if (!io_buf->buf) {
        log_error("failed to allocate a sb_net_buf %d %s", errno, strerror(errno));
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
    free(io_buf->buf);

    return;
}

void sb_connection_say_bye(struct sb_connection * conn) {
    if (conn->net_state == TERMINATED_4) {
        log_warn("will not say bye in terinated state for %s", conn->desc);
    } else {
        log_info("saying bye to %s", conn->desc);
        /* put a bye package into packages_t2n, so that it can be send to peer */
        struct sb_package * bye_pkg = sb_package_new(SB_PKG_TYPE_BYE_3, 0, 0);
        if (!bye_pkg) {
            log_error("failed to create bye pkg");
        }
        TAILQ_INSERT_TAIL(&(conn->packages_t2n), bye_pkg, entries);
        conn->t2n_pkg_count++;
        if (conn->app->config->app_mode == CLIENT) {
            conn->net_state = CLOSING_3;
        }
        log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
    }
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
            // error
            log_error("failed to receive data from connection %s: %d %s", read_buf->conn->desc, ret, strerror(ret));
            return -1;
        }
    } else if (ret == 0) {
        // EOF
        return 2;
    } else {
        log_trace("read %d bytes from %s", ret, read_buf->conn->desc);
        // some bytes were read
        if (ret < buflen) {
            // read less than we want
            read_buf->cur_p += ret;
        } else if (ret > buflen) {
            log_warn("read from %s more bytes than request, impossible", read_buf->conn->desc);
            return -1;
        } else {
            // read equals we want
            if (read_buf->state == HDR) {
                read_buf->pkg_len = ntohl(read_buf->buf->len_buf);
                read_buf->cur_p = read_buf->buf->pkg_buf;
                read_buf->state = PKG;
            } else if (read_buf->state == PKG) {
                // full package is read, construct a sb_package, put into conn->packages_n2t
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
            return 0;
        }
        // error
        log_error("failed to send to net %s", write_buf->conn->desc);
        return -1;
    } else {
        write_buf->cur_p += ret;
        if (ret == buflen) {
            write_buf->cur_pkg = 0;
            write_buf->cur_p = (char *)write_buf->buf;
        }
        return 1;
    }
}

void sb_do_tcp_read(evutil_socket_t fd, short what, void * data) {
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
                    free(read_buf->cur_pkg);
                    read_buf->cur_pkg = 0;
                }
                read_buf->cur_pkg = 0;
                if (conn->net_state == TERMINATED_4) {
                    sb_connection_del(conn);
                    conn = 0;
                    break;
                }
            }
        } else if (ret == 2) {
            // EOF
            log_info("net peer closed connection, closing net connection for %s",  conn->desc);
            conn->net_state = TERMINATED_4;
            log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
            if (conn->net_state == TERMINATED_4) {
                sb_connection_del(conn);
                conn = 0;
                break;
            }
            break;
        }
    }

    if (conn) {
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
    /* read an udp package */
    struct sb_app * app = data;
    struct sb_net_buf buf;
    struct sockaddr_in peer_addr;
    unsigned int addrlen;

    char addrstr[INET_ADDRSTRLEN];
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
                log_error("failed to receive a udp package from net %d %s", errno, strerror(errno));
            }
            break;
        }
        inet_ntop(AF_INET, &peer_addr, addrstr, sizeof(addrstr));
        if (ret == 0) {
            log_warn("received a 0 length udp package from %s", addrstr);
            break;
        }
        if (peer_addr.sin_family != AF_INET || addrlen != sizeof(struct sockaddr_in)) {
            log_warn("received a package from unsupported address: sa_family %d, addrlen %d", peer_addr.sin_family, addrlen);
            break;
        }
        unsigned short pkg_len = ntohl(buf.len_buf);
        if (pkg_len != ret - SB_NET_BUF_HEADER_SIZE) {
            log_warn("received udp package length(%d) != declared length(%d) from %s", ret - SB_NET_BUF_HEADER_SIZE, pkg_len, addrstr);
            break;
        }
        // full package is read
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
                log_warn("received INIT pkg from %s, resetting", existing_conn->desc);
                sb_connection_del(existing_conn);
                existing_conn = 0;
            }
            conn = sb_connection_new(app, fd, SB_NET_MODE_UDP, peer_addr);
            if (!conn) {
                log_error("failed to init connection for client %s", addrstr);
                break;
            }
            /* queue a cookie to send to client */
            if (sb_util_random(conn->cookie, SB_COOKIE_SIZE) < 0) {
                log_error("failed to generate cookie data for connection %s", conn->desc);
                break;
            }
        } else {
            if (existing_conn) {
                conn = existing_conn;
            } else {
                log_warn("no connection for incoming pkg from %s", sb_util_human_endpoint((struct sockaddr *)&peer_addr));
                break;
            }
        }
        struct sb_package * pkg = sb_package_new(type, (char *)buf.pkg_buf, pkg_len);
        if (!pkg) {
            log_error("failed to create a sb_package for %s, dropping", conn->desc);
            break;
        }
        if (!sb_conn_net_received_pkg(conn, pkg)) {
            free(pkg);
            pkg = 0;
        }
        if (conn->net_state == TERMINATED_4) {
            sb_connection_del(conn);
            conn = 0;
            break;
        }
        if (conn->n2t_pkg_count > 0) {
            enable_tun_write = true;
        }
        if (conn->t2n_pkg_count > 0) {
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
    struct sb_connection * conn = data;
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
            // close connection?
        } else if (ret == 0) {
            /* fd not writable, wait */
            break;
        } else if (ret == 1) {
            if (!write_buf->cur_pkg) {
                /* a full package is written */
                if (writing_pkg->type == SB_PKG_TYPE_BYE_3) {
                conn->net_state = TERMINATED_4;
                log_trace("connection net_state change to %d: %s", conn->net_state, conn->desc);
                if (conn->net_state == TERMINATED_4) {
                    sb_connection_del(conn);
                    conn = 0;
                    break;
                }
                } else {
                TAILQ_REMOVE(&(conn->packages_t2n), writing_pkg, entries);
                conn->t2n_pkg_count--;
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
        log_debug("writing a pkg with legnth %d to %s", frame_size, conn->desc);
        ret = sendto(fd, &buf, frame_size, 0, (const struct sockaddr *)&conn->peer_addr, sizeof(conn->peer_addr));
        if (ret < 0) {
            log_error("failed to send package to %s: %s, dropping", sb_util_human_endpoint((struct sockaddr *)&conn->peer_addr), sb_util_strerror(errno));
        } else {
            if (ret < frame_size) {
                log_warn("send truncated package to %s", sb_util_human_endpoint((struct sockaddr *)&conn->peer_addr));
            }
        }
        TAILQ_REMOVE(&conn->packages_t2n, pkg, entries);
        conn->t2n_pkg_count--;
        free(pkg);
        pkg = 0;
    }
    if (disable_net_write) {
        log_debug("disabling udp write");
        event_del(app->udp_writeevent);
    }
    log_exit_func();
    return;
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
        app->udp_writeevent = 0;
    }
    if (app->udp_readevent) {
        event_del(app->udp_readevent);
        app->udp_readevent = 0;
    }
    if (app->tun_writeevent) {
        event_del(app->tun_writeevent);
        app->tun_writeevent = 0;
    }
    if (app->tun_readevent) {
        event_del(app->tun_readevent);
        app->tun_readevent = 0;
    }
    if (app->sigterm_event) {
        event_del(app->sigterm_event);
        app->sigterm_event = 0;
    }
    if (app->sigint_event) {
        event_del(app->sigint_event);
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

