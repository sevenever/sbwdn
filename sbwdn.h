#ifndef _SBWDN_H_
#define _SBWDN_H_

#include <sys/queue.h>
#include <event2/event.h>
#include <linux/ip.h>

#define PROTO_IPV4 0x0800
#define PROTO_IPV6 0x08dd

#define SB_PKG_BUF_MAX 1024
#define SB_CONN_DESC_MAX 1024

/* ------------------------------------------------------------------------------------------------
 * package on wire
 * ------------------------------------------------------------------------------------------------ */
struct __attribute__ ((packed)) sb_tun_pi {
    unsigned short flags;
    unsigned short proto;
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
 * sb_net_reader
 * ------------------------------------------------------------------------------------------------ */
enum net_read_state {LEN, PKG};
struct sb_net_reader {
    struct sb_net_buf * buf;

    enum net_read_state state;
    char * cur_p;

    unsigned int pkg_len;

    struct sb_connection * conn;
};
int sb_net_reader_init(struct sb_net_reader * reader, struct sb_connection * conn);
/* Read package from network using the reader until error happen or EOF or no more data available.
 * If full package is read, construct sb_package and queue into conn->packages_n2t.
 * If full package is not available yet, save data that read so far into reader's buffer.
 *
 * Return -1 if error
 * Return 0 if read EOF
 * return 1 no more data available
 * return 2 if packages_n2t is full
 */
int sb_net_reader_read(struct sb_net_reader * reader, int fd);
void sb_net_reader_del(struct sb_net_reader * reader);

/* ------------------------------------------------------------------------------------------------
 * sb_net_writer
 * ------------------------------------------------------------------------------------------------ */
struct sb_net_writer {
    struct sb_net_buf * buf;

    char * cur_p;

    unsigned int pkg_len;

    struct sb_package * cur_pkg;

    struct sb_connection * conn;
};
int sb_net_writer_init(struct sb_net_writer * writer, struct sb_connection * conn);
int sb_net_writer_write(struct sb_net_writer * writer, int fd);
void sb_net_writer_del(struct sb_net_writer * writer);

/* ------------------------------------------------------------------------------------------------
 * sb_connection
 * ------------------------------------------------------------------------------------------------ */
enum sb_net_mode { TCP, UDP };
struct sb_connection {
    int net_fd;
    enum sb_net_mode net_mode;

    struct in_addr peer_addr;

    struct sb_app * app;
    struct event_base * eventbase;

    struct event * net_readevent;
    struct event * net_writeevent;

    TAILQ_HEAD(, sb_package) packages_n2t;
    TAILQ_HEAD(, sb_package) packages_t2n;
    unsigned int n2t_pkg_count;
    unsigned int t2n_pkg_count;

    struct sb_net_reader net_reader;
    struct sb_net_writer net_writer;

    char desc[SB_CONN_DESC_MAX];
    TAILQ_ENTRY(sb_connection) entries;
};

void sb_do_net_accept(evutil_socket_t listen_fd, short what, void * data);
void sb_do_net_read(evutil_socket_t fd, short what, void * data);
void sb_do_net_write(evutil_socket_t fd, short what, void * data);
struct sb_connection * sb_connection_new(struct sb_app * app, int client_fd);
void sb_connection_del(struct sb_connection * conn);

/* ------------------------------------------------------------------------------------------------
 * sb_app
 * ------------------------------------------------------------------------------------------------ */
struct sb_app {
    int tun_fd;
    unsigned int mtu;

    struct event_base * eventbase;
    struct event * tun_readevent;
    struct event * tun_writeevent;


    TAILQ_HEAD(, sb_connection) conns;
};
struct sb_app * sb_app_new(int tun_fd, struct event_base * eventbase);
#endif
