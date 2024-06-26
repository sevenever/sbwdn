#ifndef _SB_NET_H
#define _SB_NET_H

#include <stdint.h>
#include <sys/queue.h>
#include <event2/event.h>

#define PROTO_IPV4 0x0800
#define PROTO_IPV6 0x08dd

#define SB_NET_MODE_TCP 0x01
#define SB_NET_MODE_UDP 0x02

#define IP_PKG_SIZE_MAX 65536

#define SB_PKG_BUF_MAX 1024

#define SB_CONN_DESC_MAX 1024

#define SB_COOKIE_SIZE 8
#define SB_RT_TAG_SIZE 8
#define SB_RND_DATA_SIZE 8

/* how long should we wait before next reconnect, max value*/
#define SB_CLIENT_RETRY_INTERVAL_INC_LINEAR 32
#define SB_CLIENT_RETRY_INTERVAL_MAX 300

#define SB_RT_OP_ADD 1
#define SB_RT_OP_DEL 2

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

struct sb_rt {
    struct in_addr dst;
    struct in_addr mask;
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

#define SB_NET_BUF_HEADER_SIZE offsetof(struct sb_net_buf, pkg_buf)

struct __attribute__ ((packed)) sb_hello_pkg_data {
    uint8_t version;
    uint8_t padding1;
    uint8_t padding2;
    uint8_t padding3;
    char    data[4];
};

struct __attribute__ ((packed)) sb_cookie_pkg_data {
    char cookie[SB_COOKIE_SIZE];
    struct in_addr server_vpn_addr;
    struct in_addr client_vpn_addr;
    struct in_addr netmask;
};

struct __attribute__ ((packed)) sb_route_tag_data {
    char rt_tag[SB_RT_TAG_SIZE];
    uint32_t rt_total;
};

struct __attribute__ ((packed)) sb_route_req_data {
    char rt_tag[SB_RT_TAG_SIZE];
    uint32_t rt_total;
    uint32_t offset;
    uint32_t count;
    char rnd[SB_RND_DATA_SIZE];
};

struct __attribute__ ((packed)) sb_route_resp_data {
    char rt_tag[SB_RT_TAG_SIZE];
    uint32_t rt_total;
    uint32_t offset;
    uint32_t count;
    struct sb_rt rt;
};

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

int sb_client_socket(unsigned int mode, struct sockaddr_in * server_addr, socklen_t addr_len);

int sb_server_socket(unsigned int mode, struct sockaddr_in * listen_addr, socklen_t addr_len);

int sb_set_no_frament(int fd);

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

struct sb_conn_stat {
    struct timespec time;
    uint64_t net_ingress_pkgs;
    uint64_t net_ingress_bytes;
    uint64_t net_egress_pkgs;
    uint64_t net_egress_bytes;
    uint64_t tun_ingress_pkgs;
    uint64_t tun_ingress_bytes;
    uint64_t tun_egress_pkgs;
    uint64_t tun_egress_bytes;
};

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
enum sb_conn_state { NEW_0 = 0, CONNECTED_1 = 1, ESTABLISHED_2 = 2, CLOSING_3 = 3, TERMINATED_4 = 4, CONN_STATE_MAX};

struct sb_connection {
    int net_fd;
    unsigned int net_mode;

    struct event * timeout_timer;

    struct event * keepalive_timer;

    struct event * statistic_timer;

    struct event * route_timer;

    enum sb_conn_state net_state;

    struct sockaddr_in peer_addr;    /* the address of net peer */
    struct in_addr peer_vpn_addr;    /* the address of vpn peer */
    struct in_addr vpn_addr;         /* the address of vpn */

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

    /* only used to send tag to client, if we know this client get
     * the latest route tag, we set this the same as config->rt_tag */
    char rt_tag[SB_RT_TAG_SIZE];

    time_t conn_time; /* when the connection started */
    struct sb_conn_stat stat;
    struct sb_conn_stat sample_start_stat;
    struct sb_conn_stat sample_end_stat;

    TAILQ_ENTRY(sb_connection) entries;
};

void sb_do_tcp_accept(evutil_socket_t listen_fd, short what, void * app);

/* try to connect to server
 * return 0 if connection is created
 * return -1 if failed
 */
void sb_try_client_connect(evutil_socket_t notused, short what, void * data);

void sb_schedule_reconnect(struct sb_app * app);

void sb_stop_reconnect(struct sb_app * app);

void sb_do_tcp_read(evutil_socket_t fd, short what, void * conn);

void sb_do_tcp_write(evutil_socket_t fd, short what, void * conn);

void sb_do_udp_read(evutil_socket_t fd, short what, void * app);

void sb_do_udp_write(evutil_socket_t fd, short what, void * app);

int sb_modify_route(unsigned int op, struct in_addr * dst, struct in_addr * netmask, struct in_addr * gw);

#endif
