#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#include "sb_log.h"
#include "sb_util.h"
#include "sb_config.h"
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

    conn->route_timer = event_new(conn->eventbase, -1, EV_PERSIST, sb_do_route_timeout, conn);

    conn->statistic_timer = event_new(conn->eventbase, -1, EV_PERSIST, sb_do_conn_statstic, conn);
    /* setup time-out callback */
    sb_util_set_timeout(conn->statistic_timer, SB_CONN_STAT_TIMEOUT);

    clock_gettime(CLOCK_MONOTONIC, &(conn->sample_end_stat.time));

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
        /* reset route infomation */
        memset(config->rt_tag, 0, SB_RT_TAG_SIZE);
        config->rt_total = 0;
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

    event_del(conn->route_timer);
    event_free(conn->route_timer);
    conn->route_timer = 0;

    event_del(conn->statistic_timer);
    event_free(conn->statistic_timer);
    conn->statistic_timer = 0;

    conn->net_state = TERMINATED_4;

    if (conn->net_mode == SB_NET_MODE_TCP || config->app_mode == SB_CLIENT) {
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
    /* statistics */
    conn->stat.net_ingress_pkgs++;
    conn->stat.net_ingress_bytes += pkg->ipdatalen;

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

                log_info("configuring IP of tun device addr to %s", sb_util_human_addr(AF_INET, &cookie->client_vpn_addr));
                log_info("configuring netmask of tun device addr to %s", sb_util_human_addr(AF_INET, &cookie->netmask));
                if(sb_config_tun_addr(app->tunname, &cookie->client_vpn_addr, &cookie->netmask, app->config->mtu) < 0) {
                    log_warn("failed to configure tun device address, will disconnect");
                    sb_connection_change_net_state(conn, TERMINATED_4);
                    break;
                }

                /* save server vpn addr, will use when setting route */
                conn->vpn_addr = cookie->client_vpn_addr;

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
            sb_try_send_route_tag(app->config, conn);
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
            } else if (pkg->type == SB_PKG_TYPE_ROUTE_TAG_7) {
                if (app->config->app_mode == SB_SERVER) {
                    log_warn("received a route information tag package from client %s, ignoring", conn->desc);
                    break;
                }
                /* client */
                log_info("received a route information tag package from server %s, refresh route", conn->desc);
                sb_conn_handle_route_tag(app->config, conn, pkg);
                break;
            } else if (pkg->type == SB_PKG_TYPE_ROUTE_REQ_8) {
                if (app->config->app_mode == SB_CLIENT) {
                    log_warn("received a route req package from server %s, ignoring", conn->desc);
                    break;
                }
                /* server */
                log_debug("received a route req package from client %s", conn->desc);
                sb_conn_handle_route_req(app->config, conn, pkg);
                break;
            } else if (pkg->type == SB_PKG_TYPE_ROUTE_RESP_9) {
                if (app->config->app_mode == SB_SERVER) {
                    log_warn("received a route resp package from client %s, ignoring", conn->desc);
                    break;
                }
                /* client */
                log_warn("received a route resp package from server %s", conn->desc);
                sb_conn_handle_route_resp(app->config, conn, pkg);
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

    if (newstate == ESTABLISHED_2) {
        conn->conn_time = time(NULL);
        if (strlen(config->if_up_script) > 0) {
            strncpy(vpn_addr, sb_util_human_addr(AF_INET, &conn->vpn_addr), sizeof(vpn_addr));
            strncpy(peer_vpn_addr, sb_util_human_addr(AF_INET, &conn->peer_vpn_addr), sizeof(peer_vpn_addr));
            strncpy(peer_addr, sb_util_human_addr(AF_INET, &((struct sockaddr_in*)&conn->peer_addr)->sin_addr), sizeof(peer_addr));
            snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %d %d %d ",
                    config->if_up_script,
                    app->tunname,
                    vpn_addr,
                    peer_vpn_addr,
                    peer_addr,
                    ntohs(conn->peer_addr.sin_port),
                    conn->net_mode,
                    newstate) < 0 ? abort() : (void) 0; /* to suppress gcc's -Wformat-truncation= */
            log_info("executing if_up_script: %s", cmd);
            ret = system(cmd);
            if (ret != 0) {
                log_error("failed to execute if_up_script: %s, ret is %d, error is %s", cmd, ret, sb_util_strerror(errno));
            }
        }
    } else if (newstate == TERMINATED_4 && strlen(config->if_down_script) > 0) {
        strncpy(vpn_addr, sb_util_human_addr(AF_INET, &conn->vpn_addr), sizeof(vpn_addr));
        strncpy(peer_vpn_addr, sb_util_human_addr(AF_INET, &conn->peer_vpn_addr), sizeof(peer_vpn_addr));
        strncpy(peer_addr, sb_util_human_addr(AF_INET, &((struct sockaddr_in*)&conn->peer_addr)->sin_addr), sizeof(peer_addr));
        snprintf(cmd, sizeof(cmd), "%s %s %s %s %s %d %d %d ",
                config->if_down_script,
                app->tunname,
                vpn_addr,
                peer_vpn_addr,
                peer_addr,
                ntohs(conn->peer_addr.sin_port),
                conn->net_mode,
                newstate) < 0 ? abort() : (void) 0;/* to suppress gcc's -Wformat-truncation= */
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
    log_info("received a route package from server");
    char all_zero[SB_RT_TAG_SIZE];
    memset(all_zero, 0, SB_RT_TAG_SIZE);
    if (memcmp(config->rt_tag, all_zero, SB_RT_TAG_SIZE) != 0) {
        log_warn("we have received a route tag from server, will drop this old style route package");
        return;
    }
    struct sb_rt * rt = (struct sb_rt *)pkg->ipdata;
    int n = pkg->ipdatalen / sizeof(struct sb_rt);
    for (int i = 0; i < n; i++, rt++) {
        if (config->rt_cnt < SB_RT_MAX) {
            log_trace("adding routing for %s %s", sb_util_human_addr(AF_INET, &rt->dst), conn->desc);
            if (sb_modify_route(SB_RT_OP_ADD, &rt->dst, &rt->mask, &conn->peer_vpn_addr) == 0) {
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

void sb_try_send_route_tag(struct sb_config * config, struct sb_connection * conn) {
    if (memcmp(config->rt_tag, conn->rt_tag, SB_RT_TAG_SIZE) != 0) {
        sb_send_route_tag(config, conn);
        /* setup time-out callback */
        log_debug("setting a timeout %d seconds for route tag to %s", SB_RT_REQ_TIMEOUT, conn->desc);
        sb_util_set_timeout(conn->route_timer, SB_RT_REQ_TIMEOUT);
    } else {
        sb_util_clear_timeout(conn->route_timer);
    }
}

int sb_send_route_tag(struct sb_config * config, struct sb_connection * conn) {
    log_warn("sending route tag to %s", conn->desc);
    struct sb_route_tag_data rt_tag_data;
    memcpy(&rt_tag_data.rt_tag, config->rt_tag, SB_RT_TAG_SIZE);
    rt_tag_data.rt_total = htonl(config->rt_total);
    struct sb_package * rt_tag_pkg = sb_package_new(SB_PKG_TYPE_ROUTE_TAG_7, &rt_tag_data, sizeof(struct sb_route_tag_data));
    if (!rt_tag_pkg) {
        log_error("failed to create a route tag package");
        return -1;
    }
    log_info("sending a route tag of %u entries to %s", ntohl(rt_tag_data.rt_total), conn->desc);
    TAILQ_INSERT_TAIL(&(conn->packages_t2n), rt_tag_pkg, entries);
    conn->t2n_pkg_count++;

    return 0;
}

int sb_conn_handle_route_tag(struct sb_config * config, struct sb_connection * conn, struct sb_package * pkg) {
    struct sb_route_tag_data * tag_data = (struct sb_route_tag_data *)pkg->ipdata;
    tag_data->rt_total = ntohl(tag_data->rt_total);
    /* if tag is the same as we have, ignore it */
    if (memcmp(config->rt_tag, tag_data->rt_tag, SB_RT_TAG_SIZE) == 0) {
        log_warn("received a tag which we already have from %s", conn->desc);
        return 0;
    }

    log_info("received a tag pkg with rt_total %u from %s", tag_data->rt_total, conn->desc);

    /* remove old route info */
    for(int i = config->rt_cnt; i > 0; i--, config->rt_cnt--) {
        struct sb_rt * rt = &config->rt[i - 1];
        log_debug("remove routing for %s", sb_util_human_addr(AF_INET, &rt->dst));
        sb_modify_route(SB_RT_OP_DEL, &rt->dst, &rt->mask, &conn->peer_vpn_addr);
    }
    /* otherwise save the tag and rt_total */
    memcpy(config->rt_tag, tag_data->rt_tag, SB_RT_TAG_SIZE);
    config->rt_total = tag_data->rt_total;

    /* initiate route req for this new tag */
    sb_try_send_route_req(config, conn);

    return 0;
}

void sb_try_send_route_req(struct sb_config * config, struct sb_connection * conn) {
    if (config->rt_total > config->rt_cnt) {
        sb_send_route_req(config, conn);
        /* setup time-out callback */
        log_debug("setting a timeout %d seconds for route req to %s", SB_RT_REQ_TIMEOUT, conn->desc);
        sb_util_set_timeout(conn->route_timer, SB_RT_REQ_TIMEOUT);
    } else {
        log_info("all log entries(config->rt_total) has been received");
        sb_util_clear_timeout(conn->route_timer);
    }
}

int sb_send_route_req(struct sb_config * config, struct sb_connection * conn) {
    struct sb_route_req_data req;
    memcpy(req.rt_tag, config->rt_tag, SB_RT_TAG_SIZE);
    req.rt_total = htonl(config->rt_total);
    req.offset = htonl(config->rt_cnt);
    req.count = htonl(SB_RT_COUNT_PER_REQ);
    struct sb_package * rt_req_pkg = sb_package_new(SB_PKG_TYPE_ROUTE_REQ_8, &req, sizeof(struct sb_route_req_data));
    if (!rt_req_pkg) {
        log_error("failed to create a route req package");
        return -1;
    }
    log_info("sending a route req of %u entries with offset of %u to %s", ntohl(req.count), ntohl(req.offset), conn->desc);
    TAILQ_INSERT_TAIL(&(conn->packages_t2n), rt_req_pkg, entries);
    conn->t2n_pkg_count++;

    return 0;
}

int sb_conn_handle_route_req(struct sb_config * config, struct sb_connection * conn, struct sb_package * pkg) {
    struct sb_route_req_data * req = (struct sb_route_req_data *)pkg->ipdata;
    req->rt_total = ntohl(req->rt_total);
    req->offset = ntohl(req->offset);
    req->count = ntohl(req->count);
    log_info("received route req (rt_total: %u, offset: %u, count: %u) from %s.", req->rt_total, req->offset, req->count, conn->desc);
    /* sanity check */
    if (memcmp(config->rt_tag, req->rt_tag, SB_RT_TAG_SIZE) != 0) {
        log_warn("received a mismatch route tag from %s", conn->desc);
        return -1;
    }
    if (config->rt_total != req->rt_total) {
        log_warn("received a mismatch rt_total from %s", conn->desc);
        return -1;
    }
    if (req->offset >= config->rt_total) {
        log_warn("received a invalid req offset from %s", conn->desc);
        return -1;
    }
    if (req->count == 0) {
        log_warn("received a zero req count from %s", conn->desc);
        return -1;
    }
    /* now we know this client has latest route tag */
    memcpy(conn->rt_tag, req->rt_tag, SB_RT_TAG_SIZE);
    sb_util_clear_timeout(conn->route_timer);

    /* send resp */
    uint32_t count = req->count;
    if (req->offset + count > config->rt_total) {
        count = config->rt_total - req->offset;
        log_info("number of route entries in resp is limited by rt_total to %u for %s", count, conn->desc);
    }
    unsigned int mtu = config->mtu;
    unsigned int max_len = (mtu + sizeof(struct sb_tun_pi) - SB_RT_TAG_SIZE - 3 /* rt_total, offset, count */ * sizeof(uint32_t));
    if (count * sizeof(struct sb_rt) > max_len) {
        count = max_len / sizeof(struct sb_rt);
        log_info("number of route entries in resp is limited by mtu to %u for %s", count, conn->desc);
    }

    unsigned int pkglen = sizeof(struct sb_route_resp_data) + (count - 1/* sb_route_resp_data already has one instance of sb_rt */) * sizeof(struct sb_rt);
    struct sb_route_resp_data * resp = malloc(pkglen);
    if (!resp) {
        log_error("failed t allocate memory for resp");
        return -1;
    }
    memcpy(resp->rt_tag, config->rt_tag, SB_RT_TAG_SIZE);
    resp->rt_total = htonl(config->rt_total);
    resp->offset = htonl(req->offset);
    resp->count = htonl(count);
    memcpy(&(resp->rt), &(config->rt[req->offset]), count * sizeof(struct sb_rt));

    log_info("sending %d routing info to client %s", count, conn->desc);
    struct sb_package * resp_pkg = sb_package_new(SB_PKG_TYPE_ROUTE_RESP_9, resp, pkglen);
    if (!resp_pkg) {
        log_error("failed to create a route resp package");
        return -1;
    }
    TAILQ_INSERT_TAIL(&(conn->packages_t2n), resp_pkg, entries);
    conn->t2n_pkg_count++;

    return 0;
}

int sb_conn_handle_route_resp(struct sb_config * config, struct sb_connection * conn, struct sb_package * pkg) {
    struct sb_route_resp_data * resp = (struct sb_route_resp_data *)pkg->ipdata;
    resp->rt_total = ntohl(resp->rt_total);
    resp->offset = ntohl(resp->offset);
    resp->count = ntohl(resp->count);
    log_info("received route resp (rt_total: %u, offset: %u, count: %u) from %s.", resp->rt_total, resp->offset, resp->count, conn->desc);
    /* sanity check */
    if (memcmp(config->rt_tag, resp->rt_tag, SB_RT_TAG_SIZE) != 0) {
        log_warn("received a mismatch route tag from %s", conn->desc);
        return -1;
    }
    if (config->rt_total != resp->rt_total) {
        log_warn("received a mismatch rt_total from %s", conn->desc);
        return -1;
    }
    if (resp->offset >= config->rt_total) {
        log_warn("received a invalid resp offset(> config->rt_total) from %s", conn->desc);
        return -1;
    }
    if (resp->offset != config->rt_cnt) {
        log_warn("received a invalid resp offset(!= config->rt_cnt) from %s", conn->desc);
        return -1;
    }
    if (resp->count == 0) {
        log_warn("received a zero resp count from %s", conn->desc);
        return -1;
    }
    if ((sizeof(struct sb_route_resp_data) + (resp->count - 1) * sizeof(struct sb_rt)) > pkg->ipdatalen) {
        log_warn("received a invalid resp count %u, ipdatalen is %u, from %s", resp->count, pkg->ipdatalen, conn->desc);
        return -1;

    }

    struct sb_rt * rt = (struct sb_rt *)&(resp->rt);
    for (unsigned int i = 0; i < resp->count; i++, rt++) {
        if (config->rt_cnt < SB_RT_MAX) {
            log_trace("adding routing for %s %s", sb_util_human_addr(AF_INET, &rt->dst), conn->desc);
            sb_modify_route(SB_RT_OP_ADD, &rt->dst, &rt->mask, &conn->peer_vpn_addr);
            /* save, delete when disconnect */
            config->rt[config->rt_cnt++] = *rt;
            log_trace("added routing for %s %s", sb_util_human_addr(AF_INET, &rt->dst), conn->desc);
        } else {
            log_warn("max route info reached, ignoring %s %s", sb_util_human_addr(AF_INET, &rt->dst), conn->desc);
        }
    }

    sb_try_send_route_req(config, conn);

    return 0;
}

void sb_do_route_timeout(evutil_socket_t fd, short what, void * data) {
    SB_NOT_USED(fd);
    SB_NOT_USED(what);
    struct sb_connection * conn = (struct sb_connection *) data;
    struct sb_config * config = conn->app->config;

    log_info("route timeout");
    if (config->app_mode == SB_CLIENT) {
        sb_try_send_route_req(config, conn);
    } else {
        /* server */
        sb_try_send_route_tag(config, conn);
    }
}

void sb_do_conn_statstic(evutil_socket_t fd, short what, void * data) {
    SB_NOT_USED(fd);
    SB_NOT_USED(what);
    struct sb_connection * conn = (struct sb_connection *) data;

    conn->sample_start_stat = conn->sample_end_stat;
    conn->sample_end_stat = conn->stat;
    clock_gettime(CLOCK_MONOTONIC, &(conn->sample_end_stat.time));
}
