#ifndef _SBWDN_H_
#define _SBWDN_H_

#include <sys/queue.h>
#include <event2/event.h>
#include <net/if.h>

#include "sb_config.h"
#include "sb_net.h"

/* how long we wait for sending bye to peer before exit, in seconds*/
#define SB_STOP_WAITING 1

#define max(a,b) ((a) > (b) ? (a) : (b))
#define min(a,b) ((a) < (b) ? (a) : (b))

void sb_do_tun_read(evutil_socket_t fd, short what, void * app);

void sb_do_tun_write(evutil_socket_t fd, short what, void * app);

/* ------------------------------------------------------------------------------------------------
 * sb_app
 * ------------------------------------------------------------------------------------------------ */
struct sb_app {
    struct sb_config * config;
    int tun_fd;
    int udp_fd;

    char tunname[IFNAMSIZ];

    struct event_base * eventbase;

    struct event * sigterm_event;
    struct event * sigint_event;

    struct event * tun_readevent;
    struct event * tun_writeevent;
    struct event * udp_readevent;
    struct event * udp_writeevent;

    unsigned int retry_interval;

    struct event * reconnect_event;

    int dont_reconnect;

    int conn_timeout_oracle[CONN_STATE_MAX];

    TAILQ_HEAD(, sb_connection) conns;
};

struct sb_app * sb_app_new();

void sb_app_del(struct sb_app * app);

void sb_stop_app(struct sb_app * app, int immiedately);

void setup_watchdog(struct sb_app * app);

void sb_watchdog(evutil_socket_t fd, short what, void * data);

void sb_sigterm_handler(evutil_socket_t sig, short what, void * data);

void sb_sigint_handler(evutil_socket_t sig, short what, void * data);

int sb_daemonize();
#endif
