#ifndef _SBWDN_H_
#define _SBWDN_H_

#include <sys/queue.h>
#include <event2/event.h>
#include <stdint.h>

#include "sb_config.h"

#define PROTO_IPV4 0x0800
#define PROTO_IPV6 0x08dd

#define SB_PKG_BUF_MAX 1024
#define SB_CONN_DESC_MAX 1024


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
 * package on wire
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
    char len_buf[2];
    char pkg_buf[65536];
};

/* this represent an IP package */
struct sb_package {
    unsigned int ipdatalen;
    char * ipdata;
    TAILQ_ENTRY(sb_package) entries;
};
struct sb_package * sb_package_new(char * ipdata, int ipdatalen);

/* ------------------------------------------------------------------------------------------------
 * sb_net_io_buf
 * ------------------------------------------------------------------------------------------------ */
enum net_io_state {LEN, PKG};
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
enum sb_net_mode { TCP, UDP };
enum sb_conn_state { CONNECTED, ESTABLISHED, TERMINATED };
struct sb_connection {
    int net_fd;
    enum sb_net_mode net_mode;
    enum sb_conn_state net_state;

    struct in_addr peer_addr;

    struct sb_app * app;
    struct event_base * eventbase;

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

void sb_do_net_accept(evutil_socket_t listen_fd, short what, void * data);
void sb_do_net_read(evutil_socket_t fd, short what, void * data);
void sb_do_net_write(evutil_socket_t fd, short what, void * data);
void sb_do_tun_read(evutil_socket_t fd, short what, void * data);
void sb_do_tun_write(evutil_socket_t fd, short what, void * data);
struct sb_connection * sb_connection_new(struct sb_app * app, int client_fd);
void sb_connection_del(struct sb_connection * conn);
void sb_conn_net_received_pkg(struct sb_connection * conn, struct sb_package * pkg);

/* ------------------------------------------------------------------------------------------------
 * sb_app
 * ------------------------------------------------------------------------------------------------ */
struct sb_app {
    struct sb_config config;
    int tun_fd;

    struct event_base * eventbase;
    struct event * tun_readevent;
    struct event * tun_writeevent;

    TAILQ_HEAD(, sb_connection) conns;
};
struct sb_app * sb_app_new(struct event_base * eventbase);
#endif
