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
#include "sb_tun.h"
#include "sbwdn.h"


struct sb_package * sb_package_new(unsigned int type, void * ipdata, int ipdatalen) {
    struct sb_package * p = malloc(sizeof(struct sb_package));
    if (!p) {
        log_error("fail to allocate memory for sb_package, %s", sb_util_strerror(errno));
        return 0;
    }
    p->ipdata = malloc(ipdatalen);
    if (!p->ipdata) {
        log_error("fail to allocate memory for sb_package->ipdata, %s", sb_util_strerror(errno));
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
        log_error("failed to allocate connection object %s", sb_util_strerror(errno));
        return 0;
    }
    memset(conn, 0, sizeof(struct sb_connection));

    conn->app = app;
    conn->eventbase = app->eventbase;

    conn->net_fd = client_fd;
    conn->net_mode = mode;

    conn->timeout_timer = event_new(conn->eventbase, -1, EV_PERSIST, sb_do_conn_timeout, conn);

    conn->keepalive_timer = event_new(conn->eventbase, -1, EV_PERSIST, sb_do_conn_send_keepalive, conn);

    conn->net_state = NEW_0;

    conn->peer_addr = peer;
    /*peer_vpn_addr is set to 0 by memset above */

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

    snprintf(conn->desc, SB_CONN_DESC_MAX, "%s[%s(%s)]",
            (conn->app->config->net_mode == SB_NET_MODE_TCP ? "TCP" : "UDP"),
            sb_util_human_endpoint((struct sockaddr *)&conn->peer_addr),
            "-");

    TAILQ_INSERT_TAIL(&(app->conns), conn, entries);

    return conn;
}

void sb_connection_del(struct sb_connection * conn) {
    struct sb_app * app = conn->app;
    struct sb_config * config = app->config;

    if (config->app_mode == SB_CLIENT) {
        for(int i = config->rt_cnt; i > 0; i--, config->rt_cnt--) {
            struct sb_rt * rt = &config->rt[i - 1];
            log_debug("remove routing for %s", sb_util_human_addr(AF_INET, &rt->dst));
            sb_modify_route(SB_RT_OP_DEL, &rt->dst, &rt->mask, &conn->peer_vpn_addr);
        }
    }

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

    event_del(conn->net_writeevent);
    event_free(conn->net_writeevent);
    conn->net_writeevent = 0;
    event_del(conn->net_readevent);
    event_free(conn->net_readevent);
    conn->net_readevent = 0;

    memset(&conn->peer_vpn_addr, 0, sizeof(conn->peer_vpn_addr));

    event_del(conn->timeout_timer);
    event_free(conn->timeout_timer);
    conn->timeout_timer = 0;

    event_del(conn->keepalive_timer);
    event_free(conn->keepalive_timer);
    conn->keepalive_timer = 0;

    conn->net_state = TERMINATED_4;

    if (conn->net_mode == SB_NET_MODE_TCP) {
        close(conn->net_fd);
    }
    
    conn->eventbase = 0;
    conn->app = 0;

    log_info("connection disconnected %s", conn->desc);
    conn->net_fd = -1;

    free(conn);
    conn = 0;
}

void sb_connection_set_vpn_peer(struct sb_connection * conn, struct in_addr peer_vpn_addr) {
    conn->peer_vpn_addr = peer_vpn_addr;
    static char peer_vpn_addr_buf[INET6_ADDRSTRLEN];
    strncpy(peer_vpn_addr_buf, sb_util_human_addr(AF_INET, &conn->peer_vpn_addr), sizeof(peer_vpn_addr_buf));
    snprintf(conn->desc,
            SB_CONN_DESC_MAX,
            "%s[%s(%s)]",
            (conn->app->config->net_mode == SB_NET_MODE_TCP ? "TCP" : "UDP"),
            sb_util_human_endpoint((struct sockaddr *)&conn->peer_addr),
            peer_vpn_addr_buf);
    log_info("peer vpn address is set to %s", peer_vpn_addr_buf);
}

void sb_connection_say_bye(struct sb_connection * conn) {
    if (conn->net_state == TERMINATED_4) {
        log_warn("will not say bye in terminated state for %s", conn->desc);
    } else {
        log_info("saying bye to %s", conn->desc);
        /* put a bye package into packages_t2n, so that it can be send to peer */
        struct sb_package * bye_pkg = sb_package_new(SB_PKG_TYPE_BYE_3, SB_DUMMY_PKG_DATA, SB_DUMMY_PKG_DATA_LEN);
        if (!bye_pkg) {
            log_error("failed to create bye pkg");
        }
        TAILQ_INSERT_TAIL(&(conn->packages_t2n), bye_pkg, entries);
        conn->t2n_pkg_count++;
        if (conn->app->config->app_mode == SB_CLIENT) {
            sb_connection_change_net_state(conn, CLOSING_3);
        }
    }
}

void sb_connection_say_hello(struct sb_connection * conn) {
    if (conn->net_state != NEW_0) {
        log_error("connection is not in new state %s", conn->desc);
        return;
    }

    /* send 3 syncs if UDP, in case of dropping */
    int pkg_cnt = conn->net_mode == SB_NET_MODE_UDP ? SB_PROTO_MULTI_SYNC_NUM : 1;
    for (int i = 0; i< pkg_cnt; i++) {
        /* put a initial package into packages_t2n, so that it can be send to server */
        struct sb_package * init_pkg = sb_package_new(SB_PKG_TYPE_INIT_1, SB_DUMMY_PKG_DATA, SB_DUMMY_PKG_DATA_LEN);
        if (!init_pkg) {
            log_error("failed to create init pkg");
            return;
        }
        TAILQ_INSERT_TAIL(&(conn->packages_t2n), init_pkg, entries);
        conn->t2n_pkg_count++;
    }
    sb_connection_change_net_state(conn, CONNECTED_1);
    return;
}

int sb_conn_net_received_pkg(struct sb_connection * conn, struct sb_package * pkg) {
    struct sb_app * app = conn->app;
    int queued = 0;

    log_enter_func();
    switch(conn->net_state) {
        case NEW_0:
            /* client */
            if (conn->app->config->app_mode == SB_CLIENT) {
                log_warn("received a package with type %d from %s in state %d, ignoring", pkg->type, conn->desc, conn->net_state);
                break;
            }
            /* server */
            if (pkg->type != SB_PKG_TYPE_INIT_1) {
                log_warn("received a package with type %d from %s in state %d, expecting %d, disconnecting", pkg->type, conn->desc, conn->net_state, SB_PKG_TYPE_INIT_1);
                sb_connection_change_net_state(conn, TERMINATED_4);
                break;
            }
            log_info("hello init pkg from %s", conn->desc);
            struct in_addr client_vpn_addr;
            client_vpn_addr = sb_find_a_addr_lease(app);
            if (client_vpn_addr.s_addr == 0) {
                log_warn("can not find a vpn address for %s", conn->desc);
                sb_connection_change_net_state(conn, TERMINATED_4);
                break;
            }
            log_info("letting client use %s %s", sb_util_human_addr(AF_INET, &client_vpn_addr), conn->desc);
            /* generate a cookie package and send to client */
            struct sb_cookie_pkg_data cookie_data;
            memcpy(&cookie_data.cookie, &conn->cookie, SB_COOKIE_SIZE);
            cookie_data.server_vpn_addr = app->config->addr;
            cookie_data.client_vpn_addr = client_vpn_addr;
            cookie_data.netmask = app->config->mask;
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
            if (conn->app->config->app_mode == SB_CLIENT) {
                log_info("received a cookie package, replying cookie to %s", conn->desc);

                /* save to conn */
                sb_connection_set_vpn_peer(conn, cookie->server_vpn_addr);
                memcpy(conn->cookie, cookie->cookie, SB_COOKIE_SIZE);

                /* save server vpn addr, will use when setting route */
                conn->vpn_addr = cookie->server_vpn_addr;

                log_info("configuring IP of tun device addr to %s", sb_util_human_addr(AF_INET, &cookie->client_vpn_addr));
                log_info("configuring netmask of tun device addr to %s", sb_util_human_addr(AF_INET, &cookie->netmask));
                if(sb_config_tun_addr(app->tunname, &cookie->client_vpn_addr, &cookie->netmask, app->config->mtu) < 0) {
                    log_warn("failed to configure tun device address, will disconnect");
                    sb_connection_change_net_state(conn, TERMINATED_4);
                    break;
                }
                /* send back to server*/
                TAILQ_INSERT_TAIL(&(conn->packages_t2n), pkg, entries);
                queued = 1;
                conn->t2n_pkg_count++;
                sb_connection_change_net_state(conn, ESTABLISHED_2);
                /* we are now indeed connected, stop reconnect here,
                 * instead in sb_try_client_connect
                 */
                sb_stop_reconnect(app);

                break;
            }
            /* server */
            if (memcmp(cookie->cookie, conn->cookie, SB_COOKIE_SIZE) != 0) {
                log_warn("invalid cookie from %s, disconnecting", conn->desc);
                sb_connection_change_net_state(conn, TERMINATED_4);
                break;
            }
            /* check if client vpn addr is valid, again */
            if (sb_vpn_addr_used(conn->app, cookie->client_vpn_addr)) {
                log_warn("requested vpn address %s is in use, disconnecting %s", sb_util_human_addr(AF_INET, &cookie->client_vpn_addr), conn->desc);
                sb_connection_change_net_state(conn, TERMINATED_4);
                break;
            }
            /* cookie is valid, now set client vpn_addr */
            sb_connection_set_vpn_peer(conn, cookie->client_vpn_addr);
            log_info("vpn peer addr is %s", sb_util_human_addr(AF_INET, &conn->peer_vpn_addr));
            sb_connection_change_net_state(conn, ESTABLISHED_2);
            sb_send_route_info(conn);
            break;
        case ESTABLISHED_2:
            if (pkg->type == SB_PKG_TYPE_DATA_2) {
                if (conn->n2t_pkg_count >= SB_PKG_BUF_MAX) {
                    /* packages_n2t full */
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
                if (app->config->app_mode == SB_SERVER) {
                    log_warn("received a route package from client %s, ignoring", conn->desc);
                    break;
                }
                /* client */
                log_warn("received a route package from server %s, adding route", conn->desc);
                sb_conn_handle_route(conn, pkg);
                break;
            } else if (pkg->type == SB_PKG_TYPE_BYE_3) {
                if (app->config->app_mode == SB_SERVER) {
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

int sb_conn_state_change_hook(struct sb_connection * conn, int newstate) {
    struct sb_app * app = conn->app;
    struct sb_config * config = app->config;
    int ret;
    char cmd[SB_CMD_MAX];
    char vpn_addr[INET6_ADDRSTRLEN];
    char peer_vpn_addr[INET6_ADDRSTRLEN];
    char peer_addr[INET6_ADDRSTRLEN];

    if (newstate == ESTABLISHED_2 && strlen(config->if_up_script) > 0) {
        strncpy(vpn_addr, sb_util_human_addr(AF_INET, &conn->vpn_addr), sizeof(vpn_addr));
        strncpy(peer_vpn_addr, sb_util_human_addr(AF_INET, &conn->peer_vpn_addr), sizeof(peer_vpn_addr));
        strncpy(peer_addr, sb_util_human_addr(AF_INET, &conn->peer_addr), sizeof(peer_addr));
        snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %d %d ", config->if_up_script, app->tunname, vpn_addr, peer_vpn_addr, peer_addr, conn->net_mode, newstate);
        log_info("executing if_up_script: %s", cmd);
        ret = system(cmd);
        if (ret != 0) {
            log_error("failed to execute if_up_script: %s, ret is %d, error is %s", cmd, ret, sb_util_strerror(errno));
        }
    } else if (newstate == TERMINATED_4 && strlen(config->if_down_script) > 0) {
        strncpy(vpn_addr, sb_util_human_addr(AF_INET, &conn->vpn_addr), sizeof(vpn_addr));
        strncpy(peer_vpn_addr, sb_util_human_addr(AF_INET, &conn->peer_vpn_addr), sizeof(peer_vpn_addr));
        strncpy(peer_addr, sb_util_human_addr(AF_INET, &conn->peer_addr), sizeof(peer_addr));
        snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %d %d ", config->if_down_script, app->tunname, vpn_addr, peer_vpn_addr, peer_addr, conn->net_mode, newstate);
        log_info("executing if_down_script: %s", cmd);
        ret = system(cmd);
        if (ret != 0) {
            log_error("failed to execute if_down_script: %s, ret is %d, error is %s", cmd, ret, sb_util_strerror(errno));
        }

    }

    return 0;
}

void sb_do_conn_timeout(evutil_socket_t fd, short what, void * data) {
    SB_NOT_USED(fd);
    SB_NOT_USED(what);
    struct sb_connection * conn = (struct sb_connection *)data;

    log_error("connection timeout in state %d %s", conn->net_state, conn->desc);
    sb_connection_change_net_state(conn, TERMINATED_4);
}

void sb_do_conn_send_keepalive(evutil_socket_t fd, short what, void * data) {
    SB_NOT_USED(fd);
    SB_NOT_USED(what);
    struct sb_connection * conn = (struct sb_connection *)data;
    struct sb_app * app = (struct sb_app *)conn->app;

    struct sb_package * ka_pkg = (struct sb_package *)sb_package_new(SB_PKG_TYPE_KEEPALIVE_6, SB_DUMMY_PKG_DATA, SB_DUMMY_PKG_DATA_LEN);
    if (!ka_pkg) {
        log_error("failed to create a keepalive package");
        return;
    }

    log_trace("queuing a keepalive pkg to %s", conn->desc);
    TAILQ_INSERT_TAIL(&(conn->packages_t2n), ka_pkg, entries);
    conn->t2n_pkg_count++;
    if (conn->net_mode == SB_NET_MODE_TCP && conn->net_writeevent) {
        event_add(conn->net_writeevent, 0);
    } else if (conn->net_mode == SB_NET_MODE_UDP && app->udp_writeevent) {
        event_add(app->udp_writeevent, 0);
    }
}

void sb_conn_handle_keepalive(struct sb_connection * conn, struct sb_package * pkg) {
    SB_NOT_USED(conn);
    SB_NOT_USED(pkg);
    log_trace("received a keepalive pkg from %s", conn->desc);

    if (conn->net_state != ESTABLISHED_2) {
        log_error("received a keepalive pkg but not in established state, instead in %d, %s", conn->net_state, conn->desc);
    } else {
        if (conn->keepalive_timer) {
            unsigned int timeout = conn->app->conn_timeout_oracle[conn->net_state];
            log_debug("setting a timeout %d seconds in state of %d on %s", timeout, conn->net_state, conn->desc);
            sb_util_set_timeout(conn->timeout_timer, timeout);
        }
    }
}

void sb_conn_set_timeout(struct sb_connection * conn, int newstate) {
    /* keepalive */
    if (newstate == ESTABLISHED_2) {
        if (conn->keepalive_timer) {
            sb_util_set_timeout(conn->keepalive_timer, SB_KEEPALIVE_INTERVAL);
        }
    }

    /* connection abnormal */
    if (conn->timeout_timer) {
        unsigned int timeout = conn->app->conn_timeout_oracle[newstate];
        log_debug("setting a timeout %d seconds in state of %d on %s", timeout, conn->net_state, conn->desc);
        sb_util_set_timeout(conn->timeout_timer, timeout);
    }
}

void sb_send_route_info(struct sb_connection * conn) {
    struct sb_config * config = conn->app->config;
    unsigned int mtu = config->mtu;

    log_info("%d routing info to be sent to client %s", config->rt_cnt, conn->desc);
    for (unsigned int i = 0; i < config->rt_cnt;) {
        int n = min(mtu / sizeof(struct sb_rt), config->rt_cnt - i);
        for (int j = 0; j < SB_PROTO_MULTI_RT_NUM; j++) {
            log_info("sending %d routing info to client %s", n, conn->desc);
            struct sb_package * rt_pkg = sb_package_new(SB_PKG_TYPE_ROUTE_5, &config->rt[i], n * sizeof(struct sb_rt));
            if (!rt_pkg) {
                log_error("failed to create a route package");
                continue;
            }
            TAILQ_INSERT_TAIL(&(conn->packages_t2n), rt_pkg, entries);
            conn->t2n_pkg_count++;
        }
        i += n;
    }
}

void sb_conn_handle_route(struct sb_connection * conn, struct sb_package * pkg) {
    SB_NOT_USED(conn);
    struct sb_config * config = conn->app->config;
    if (config->app_mode == SB_SERVER) {
        log_warn("received a route package from client, ignoring");
        return;
    }
    log_warn("received a route package from server");
    struct sb_rt * rt = (struct sb_rt *)pkg->ipdata;
    int n = pkg->ipdatalen / sizeof(struct sb_rt);
    for (int i = 0; i < n; i++, rt++) {
        if (config->rt_cnt < SB_RT_MAX) {
            log_trace("adding routing for %s %s", sb_util_human_addr(AF_INET, &rt->dst), conn->desc);
            if (sb_modify_route(SB_RT_OP_ADD, &rt->dst, &rt->mask, &conn->vpn_addr) == 0) {
                /* save, delete when disconnect */
                config->rt[config->rt_cnt++] = *rt;
            }
            log_trace("added routing for %s %s", sb_util_human_addr(AF_INET, &rt->dst), conn->desc);
        } else {
            log_warn("max route info reached, ignoring %s %s", sb_util_human_addr(AF_INET, &rt->dst), conn->desc);
        }
    }
}

struct in_addr sb_find_a_addr_lease(struct sb_app * app) {
    struct in_addr ret;
    uint32_t server_addr = app->config->addr.s_addr;
    uint32_t mask = ntohl(app->config->mask.s_addr);
    uint32_t cand = ntohl(app->config->addr.s_addr & app->config->mask.s_addr) + 1;
    int found = 0;

    while((cand | mask) != 0xFFFFFFFF) {
        ret.s_addr = htonl(cand);
        if (ret.s_addr != server_addr && !sb_vpn_addr_used(app, ret)) {
            found = 1;
            break;
        }
        cand++;
    }

    if (!found) {
        ret.s_addr = 0;
    }
    return ret;
}

int sb_vpn_addr_used(struct sb_app * app, struct in_addr vpn_addr) {
    struct sb_connection * conn;
    TAILQ_FOREACH(conn, &(app->conns), entries) {
        if (conn->peer_vpn_addr.s_addr == vpn_addr.s_addr) {
            log_debug("%s is used by %s", sb_util_human_addr(AF_INET, &vpn_addr), conn->desc);
            return 1;
        }
    }
    return 0;
}

