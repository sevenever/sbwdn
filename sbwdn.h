#ifndef _SBWDN_H_
#define _SBWDN_H_

#include <sys/queue.h>
#include <event2/event.h>

#define SB_BUFFER_SIZE 4096
#define SB_BUFFER_MAX 4096
#define SB_CONN_DESC_MAX 1024

struct sb_buffer {
    size_t len;
    char * head;
    char data[SB_BUFFER_SIZE - sizeof(size_t) - sizeof(char *) - sizeof(TAILQ_ENTRY(sb_buffer))];
    TAILQ_ENTRY(sb_buffer) entries;
};

struct sb_connection {
    int net_fd;
    struct event_base * eventbase;

    struct event * readevent;
    struct event * writeevent;

    TAILQ_HEAD(, sb_buffer) buffers;
    int buffer_count;

    char desc[SB_CONN_DESC_MAX];
};

void sb_do_net_accept(evutil_socket_t listen_fd, short what, void * data);
void sb_do_net_read(evutil_socket_t fd, short what, void * data);
void sb_do_net_write(evutil_socket_t fd, short what, void * data);
struct sb_connection * sb_connection_new(struct event_base * eventbase, int client_fd);
void sb_connection_del(struct sb_connection * conn);


#endif
