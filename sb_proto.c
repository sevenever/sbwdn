#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#include "sb_log.h"
#include "sb_util.h"
#include "sb_proto.h"
#include "sb_net.h"
#include "sbwdn.h"


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
    conn->last_net_state = NEW_0;

    conn->since_net_state_changed = 0;

    conn->peer_addr = peer;
    /*peer_vpn_addr is set to 0 by memset above */

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

    sb_connection_change_net_state(conn, TERMINATED_4);
    if (conn->net_mode == SB_NET_MODE_TCP) {
        close(conn->net_fd);
    }
    log_info("connection disconnected %s", conn->desc);
    conn->net_fd = -1;

    free(conn);
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
                sb_connection_change_net_state(conn, TERMINATED_4);
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
                sb_connection_change_net_state(conn, TERMINATED_4);
                break;
            }
            TAILQ_INSERT_TAIL(&(conn->packages_t2n), cookie_pkg, entries);
            queued = 1;
            conn->t2n_pkg_count++;
            sb_connection_change_net_state(conn, CONNECTED_1);
            break;
        case CONNECTED_1:
            if (pkg->type != SB_PKG_TYPE_COOKIE_4) {
                log_warn("received a package with type %d from %s in state %d, expecting %d, disconnecting", pkg->type, conn->desc, conn->net_state, SB_PKG_TYPE_COOKIE_4);
                sb_connection_change_net_state(conn, TERMINATED_4);
                break;
            }
            if (pkg->ipdatalen < sizeof(struct sb_cookie_pkg_data)) {
                log_warn("invalide cookie package length %d from %s", pkg->ipdatalen, conn->desc);
                sb_connection_change_net_state(conn, TERMINATED_4);
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
                sb_connection_change_net_state(conn, ESTABLISHED_2);

                sb_stop_reconnect(app);

                break;
            }
            /* server */
            if (memcmp(cookie->cookie, conn->cookie, SB_COOKIE_SIZE) != 0) {
                log_warn("invalid cookie from %s, disconnecting", conn->desc);
                sb_connection_change_net_state(conn, TERMINATED_4);
                break;
            }
            if (sb_vpn_addr_used(conn->app, cookie->vpn_addr)) {
                log_warn("requested vpn address %s is in use, disconnecting %s", sb_util_human_addr(AF_INET, &cookie->vpn_addr), conn->desc);
                sb_connection_change_net_state(conn, TERMINATED_4);
                break;
            }
            /* cookie is valid, now set client vpn_addr */
            sb_connection_set_vpn_peer(conn, cookie->vpn_addr);
            log_info("vpn peer addr is %s", sb_util_human_addr(AF_INET, &conn->peer_vpn_addr));
            sb_connection_change_net_state(conn, ESTABLISHED_2);
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
                        sb_connection_change_net_state(conn, CLOSING_3);
                    } else {
                        sb_connection_change_net_state(conn, TERMINATED_4);
                    }
                    break;
                } else {
                    /* client */
                    log_info("received a bye package from server %s", conn->desc);
                    sb_connection_say_bye(conn);
                    break;
                }
            } else {
                log_warn("received a package with type %d from %s in state %d, disconnecting", pkg->type, conn->desc, conn->net_state, SB_PKG_TYPE_COOKIE_4);
                sb_connection_change_net_state(conn, TERMINATED_4);
                break;
            }
            break;
        case CLOSING_3:
            log_warn("received a package with type %d from %s in state %d, disconnecting", pkg->type, conn->desc, conn->net_state, SB_PKG_TYPE_COOKIE_4);
            sb_connection_change_net_state(conn, TERMINATED_4);
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
    SB_NOT_USED(conn);
    SB_NOT_USED(pkg);
}

void sb_conn_handle_route(struct sb_connection * conn, struct sb_package * pkg) {
    SB_NOT_USED(conn);
    SB_NOT_USED(pkg);
}

int sb_vpn_addr_used(struct sb_app * app, struct in_addr vpn_addr) {
    SB_NOT_USED(app);
    SB_NOT_USED(vpn_addr);
    return 0;
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
            sb_connection_change_net_state(conn, CLOSING_3);
        }
    }
}

void sb_connection_say_hello(struct sb_connection * conn) {
    struct sb_app * app = conn->app;
    if (conn->net_state != NEW_0) {
        log_error("connection is not in new state %s", conn->desc);
        return;
    }

    /* put a initial package into packages_t2n, so that it can be send to server */
    struct sb_package * init_pkg = sb_package_new(SB_PKG_TYPE_INIT_1, (char *)&app->config->addr, sizeof(app->config->addr));
    if (!init_pkg) {
        log_error("failed to create init pkg");
        return;
    }
    TAILQ_INSERT_TAIL(&(conn->packages_t2n), init_pkg, entries);
    conn->t2n_pkg_count++;
    sb_connection_change_net_state(conn, CONNECTED_1);
    return;
}
