#ifndef _SB_PROTO_H_
#define _SB_PROTO_H_

#include <sys/queue.h>

#include "sb_net.h"

#define SB_PROTO_MULTI_SYNC_NUM 3

/* seconds between send keepalive */
#define SB_KEEPALIVE_INTERVAL (60 * 10)

#define SB_PKG_TYPE_INIT_1 1
#define SB_PKG_TYPE_DATA_2 2
#define SB_PKG_TYPE_BYE_3 3
#define SB_PKG_TYPE_COOKIE_4 4
#define SB_PKG_TYPE_ROUTE_5 5
#define SB_PKG_TYPE_KEEPALIVE_6 6

/* this represent an IP package */
struct sb_package {
    uint32_t type;
    unsigned int ipdatalen;
    char * ipdata;
    TAILQ_ENTRY(sb_package) entries;
};

struct sb_package * sb_package_new(unsigned int type, void * ipdata, int ipdatalen);

struct sb_connection * sb_connection_new(struct sb_app * app, int client_fd, unsigned int net_mode, struct sockaddr_in peer);

void sb_connection_del(struct sb_connection * conn);

void sb_connection_set_vpn_peer(struct sb_connection * conn, struct in_addr peer_vpn_addr);

void sb_connection_say_bye(struct sb_connection * conn);

void sb_connection_say_hello(struct sb_connection * conn);

/* process a package.
 * return 1 if pkg is queued into connection's packages_n2t or packages_t2n(cookie pkg from server)
 * return 0 if pkg is not queued, so caller will need to free pkg in this case.
 */
int sb_conn_net_received_pkg(struct sb_connection * conn, struct sb_package * pkg);

void sb_do_conn_timeout(evutil_socket_t fd, short what, void * data);

void sb_do_conn_send_keepalive(evutil_socket_t fd, short what, void * data);

void sb_conn_handle_keepalive(struct sb_connection * conn, struct sb_package * pkg);

void sb_conn_set_timeout(struct sb_connection * conn, int newstate);

#define sb_connection_change_net_state(conn, newstate) \
    do { \
        log_trace("connection net_state changing from %d to %d: %s", conn->net_state, newstate, conn->desc); \
        sb_conn_set_timeout(conn, newstate); \
        conn->net_state = newstate; \
        if (conn->net_state == TERMINATED_4) { \
            if (conn->app->config->app_mode == SB_CLIENT) { \
                sb_schedule_reconnect(conn->app); \
            } \
            sb_connection_del(conn); \
        } \
    } while(0);

void sb_conn_handle_route(struct sb_connection * conn, struct sb_package * pkg);

void sb_send_route_info(struct sb_connection * conn);

/*
 * find a available vpn addr as client addr
 * if not found, return 0.0.0.0
 */
struct in_addr sb_find_a_addr_lease(struct sb_app * app);

/*
 * check if a vpn addr is used by a connection
 * return 1 if used, 0 if not used
 */
int sb_vpn_addr_used(struct sb_app * app, struct in_addr vpn_addr);

#endif
