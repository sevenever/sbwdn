#ifndef _SBWDN_H_
#define _SBWDN_H_

#include <sys/queue.h>
#include <event2/event.h>
#include <stdint.h>

#include "sb_config.h"

#define PROTO_IPV4 0x0800
#define PROTO_IPV6 0x08dd

#define IP_PKG_SIZE_MAX 65536

#define SB_PKG_BUF_MAX 1024
#define SB_CONN_DESC_MAX 1024

#define SB_COOKIE_SIZE 8

struct iphdr {
    uint8_t    ihl:4,
        version:4;
    uint8_t    tos;
    uint16_t    tot_len;
    uint16_t    id;
    uint16_t    frag_off;
    uint8_t    ttl;
    uint8_t    protocol;
    uint16_t    check;
    uint32_t    saddr;
    uint32_t    daddr;
    /*The options start here. */
};

/* ------------------------------------------------------------------------------------------------
 * package on wire - all integer should be in net order
 * ------------------------------------------------------------------------------------------------ */
struct __attribute__ ((packed)) sb_tun_pi {
    uint16_t flags;
    uint16_t proto;
};

struct __attribute__ ((packed)) sb_tun_pkg {
    struct sb_tun_pi pi;
    struct iphdr iphdr;
};

struct __attribute__ ((packed)) sb_net_buf {
    uint32_t type_buf;      /* sb_net_pkg_type */
    uint32_t len_buf;    /* the length of valid data in pkg_buf */
    char pkg_buf[sizeof(struct sb_tun_pi) + IP_PKG_SIZE_MAX];
};

struct __attribute__ ((packed)) sb_cookie_pkg_data {
    char cookie[SB_COOKIE_SIZE];
    struct in_addr vpn_addr;
};

#define SB_NET_BUF_HEADER_SIZE offsetof(struct sb_net_buf, pkg_buf)

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

/* ------------------------------------------------------------------------------------------------
 * sb_net_io_buf
 * ------------------------------------------------------------------------------------------------ */
enum net_io_state {HDR, PKG};
struct sb_net_io_buf {
    struct sb_net_buf * buf;

    enum net_io_state state;

    struct sb_package * cur_pkg;

    char * cur_p;

    unsigned int pkg_len;

    struct sb_connection * conn;
};
int sb_net_io_buf_init(struct sb_net_io_buf * io_buf, struct sb_connection * conn);
void sb_net_io_buf_del(struct sb_net_io_buf * io_buf);

/* Read package from fd using the io_buf.
 * If full package is not available yet, save data that read so far into io_buf's buffer.
 *
 * return -1 if error
 * return 0 if fd is not readable any more
 * return 1 if read succeed. If pkg is fully read, io_buf->cur_pkg is the package.
 * return 2 if read EOF
 */
int sb_net_io_buf_read(struct sb_net_io_buf * io_buf, int fd);

/* Write packages into fd.
 * If sb_package is not fully written, remaining data will be in the io_buf
 *
 * return -1 if error, errno is set
 * return 0 if fd is not writable any more
 * return 1 if write succeed. If pkg is fully written, io_buf>cur_pkg is set to 0.
 */
int sb_net_io_buf_write(struct sb_net_io_buf * io_buf, int fd);

/* ------------------------------------------------------------------------------------------------
 * sb_connection
 * ------------------------------------------------------------------------------------------------ */
/* ------------------------------------------------------------------------------------------------
 * NEW:
 *      server: tcp connection accepted, udp first package received but not processed yet
 *          expecting:
 *              init package, send cookie package -> CONNECTED
 *              any other package -> TERMINATED
 *      client: tcp connected(tcp)
 *          expecting:
 *              any package -> NEW (ignore)
 *          send:
 *              init package -> CONNECTED
 * CONNECTED:
 *      server:
 *          expecting:
 *              cookie package -> ESTABLISHED
 *      client:
 *          expecting:
 *              cookie package -> ESTABLISHED
 * ESTABLISHED:
 *      server:
 *          expecting:
 *              data package
 *              keepalive package
 *              bye package -> CLOSING
 *      client: cookie package received and cookie package sent back
 *          expecting:
 *              data package
 *              keepalive package
 *              route package
 *              bye package -> CLOSING
 * CLOSING:
 *      server: received bye package
 *          expecting:
 *              EOF -> TERMINATED (tcp)
 *              none -> TERMINATED (udp)
 *      client: sent bye or received bye
 *          expecting:
 *              close -> TERMINATED (tcp)
 *              none -> TERMINATED (udp)
 *
 * TERMINATED:
 *      only thing can do is delete connection
 */
enum sb_conn_state { NEW_0 = 0, CONNECTED_1 = 1, ESTABLISHED_2 = 2, CLOSING_3 = 3, TERMINATED_4 = 4 };
struct sb_connection {
    int net_fd;
    unsigned int net_mode;
    enum sb_conn_state net_state;

    struct sockaddr_in peer_addr;    /* the address of net peer */
    struct in_addr peer_vpn_addr;    /* the address of vpn peer */

    /* seconds since connected (tcp) or init pkg received (udp) */
    unsigned int seconds_connected;

    /* this is only valid for udp */
    char cookie[SB_COOKIE_SIZE];

    struct sb_app * app;
    struct event_base * eventbase;

    /* this two events are only valid if TCP, they are 0 if UDP */
    struct event * net_readevent;
    struct event * net_writeevent;

    TAILQ_HEAD(, sb_package) packages_n2t;
    TAILQ_HEAD(, sb_package) packages_t2n;
    unsigned int n2t_pkg_count;
    unsigned int t2n_pkg_count;

    struct sb_net_io_buf net_read_io_buf;
    struct sb_net_io_buf net_write_io_buf;

    char desc[SB_CONN_DESC_MAX];
    TAILQ_ENTRY(sb_connection) entries;
};

void sb_do_tcp_accept(evutil_socket_t listen_fd, short what, void * app);
void sb_do_tcp_read(evutil_socket_t fd, short what, void * conn);
void sb_do_tcp_write(evutil_socket_t fd, short what, void * conn);
void sb_do_udp_read(evutil_socket_t fd, short what, void * app);
void sb_do_udp_write(evutil_socket_t fd, short what, void * app);
void sb_do_tun_read(evutil_socket_t fd, short what, void * app);
void sb_do_tun_write(evutil_socket_t fd, short what, void * app);
struct sb_connection * sb_connection_new(struct sb_app * app, int client_fd, unsigned int net_mode, struct sockaddr_in peer);
void sb_connection_del(struct sb_connection * conn);
void sb_connection_say_bye(struct sb_connection * conn);
/* process a package.
 * return 1 if pkg is queued into connection's packages_n2t or packages_t2n(cookie pkg from server)
 * return 0 if pkg is not queued, so caller will need to free pkg in this case.
 */
int sb_conn_net_received_pkg(struct sb_connection * conn, struct sb_package * pkg);

void sb_conn_handle_keepalive(struct sb_connection * conn, struct sb_package * pkg);

void sb_conn_handle_route(struct sb_connection * conn, struct sb_package * pkg);

int sb_vpn_addr_used(struct sb_app * app, struct in_addr vpn_addr);

/* ------------------------------------------------------------------------------------------------
 * sb_app
 * ------------------------------------------------------------------------------------------------ */
struct sb_app {
    struct sb_config * config;
    int tun_fd;
    int udp_fd;

    struct event_base * eventbase;

    struct event * sigterm_event;
    struct event * sigint_event;

    struct event * tun_readevent;
    struct event * tun_writeevent;
    struct event * udp_readevent;
    struct event * udp_writeevent;

    TAILQ_HEAD(, sb_connection) conns;
};
struct sb_app * sb_app_new(struct event_base * eventbase, const char * config_file);
#endif
