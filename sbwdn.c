#include <event2/event.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>

#include "log.h"
#include "sbwdn.h"


static void libevent_log(int severity, const char *msg) {
    int lvl;
    switch (severity) {
        case EVENT_LOG_DEBUG:
            lvl = LOG_DEBUG; break;
        case EVENT_LOG_MSG:
            lvl = LOG_INFO;  break;
        case EVENT_LOG_WARN:
            lvl = LOG_WARN;  break;
        case EVENT_LOG_ERR:
            lvl = LOG_ERROR; break;
        default:
            lvl = LOG_INFO;  break;
    }
    log_log(lvl, "", 0, "libevent: %s", msg);
}

static int sb_server_socket(int af, struct sockaddr * listen_addr, socklen_t addr_len) {
    int listen_fd;
    /* Create our listening socket. */
    listen_fd = socket(af, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        log_fatal("failed to create server socket: %s", strerror(errno));
        return -1;
    }
    if (evutil_make_listen_socket_reuseable(listen_fd) < 0) {
        log_fatal("failed to set server socket to reuseable: %s", strerror(errno));
        return -1;
    }
    if (bind(listen_fd, (struct sockaddr *)listen_addr, addr_len) < 0) {
        log_fatal("failed to bind: %s", strerror(errno));
        return -1;
    }
    if (listen(listen_fd, 5) < 0) {
        log_fatal("failed to listen: %s", strerror(errno));
        return -1;
    }
    if (evutil_make_socket_closeonexec(listen_fd) < 0) {
        log_fatal("failed to set server socket to reuseable: %s", strerror(errno));
        return -1;
    }
    /* Set the socket to non-blocking, this is essential in event
     * based programming with libevent. */
    if (evutil_make_socket_nonblocking(listen_fd) < 0) {
        log_fatal("failed to set server socket to nonblock: %s", strerror(errno));
        return -1;
    }

    return listen_fd;
}

void sb_do_net_accept(evutil_socket_t listen_fd, short what, void * data) {
    if (what & EV_READ) {
        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, (socklen_t*)&addr_len);
        if (client_fd < 0) {
            log_error("failed to accept: %s", strerror(errno));
            return;
        } else {
            const char * client_addr_p;
            if (client_addr.ss_family == AF_INET) {
                char addr[INET_ADDRSTRLEN];
                inet_ntop(client_addr.ss_family, (const void*)&(((struct sockaddr_in *)&client_addr)->sin_addr), addr, sizeof(addr));
                client_addr_p = addr;
            } else if (client_addr.ss_family == AF_INET6) {
                char addr[INET6_ADDRSTRLEN];
                inet_ntop(client_addr.ss_family, (const void*)&(((struct sockaddr_in *)&client_addr)->sin_addr), addr, sizeof(addr));
                client_addr_p = addr;
            }
            log_info("accepted connection from %s.", client_addr_p);
            
            struct event_base * eventbase = data;
            struct sb_connection * conn = sb_connection_new(eventbase, client_fd);
            if (!conn) {
                log_error("failed to init connection for net fd %d", client_fd);
                return;
            }
            event_add(conn->readevent, NULL);
        }
    }
}

struct sb_connection * sb_connection_new(struct event_base * eventbase, int client_fd) {
    struct sb_connection * conn = malloc(sizeof(struct sb_connection));
    if (!conn) {
        log_error("failed to allocate connection object %s", strerror(errno));
        return NULL;
    }
    conn->net_fd = client_fd;
    conn->eventbase = eventbase;

    struct event * readevent = event_new(conn->eventbase, conn->net_fd, EV_READ | EV_PERSIST, sb_do_net_read, conn);
    conn->readevent = readevent;
    struct event * writeevent = event_new(conn->eventbase, conn->net_fd, EV_WRITE | EV_PERSIST, sb_do_net_write, conn);
    conn->writeevent = writeevent;

    TAILQ_INIT(&(conn->buffers));
    conn->buffer_count = 0;

    snprintf(conn->desc, SB_CONN_DESC_MAX, "[net_fd: %d]", conn->net_fd);

    return conn;
}

void sb_connection_del(struct sb_connection * conn) {
    struct sb_buffer * buf, * buf2;
    buf = TAILQ_FIRST(&(conn->buffers));
    while(buf) {
        buf2 = TAILQ_NEXT(buf, entries);
        free(buf);
        buf = buf2;
    }
    conn->buffer_count = 0;
    event_del(conn->writeevent);
    event_del(conn->readevent);

    free(conn);

    
}

void sb_do_net_read(evutil_socket_t fd, short what, void * data) {
    struct sb_connection * conn = data;
    if (what & EV_READ) {
        log_debug("EV_READ");

        struct sb_buffer * buf = malloc(sizeof(struct sb_buffer));
        if (!buf) {
            log_error("failed to allocate a buffer");
            return;
        }
        int ret = recv(fd, buf->data, sizeof(buf->data), 0);
        if (ret < 0) {
            // error
            log_error("failed to receive data from connection: %s", conn->desc);
            return;
        } else if (ret == 0) {
            // EOF
            event_del(conn->readevent);
            log_info("net peer closed connection, closing net connection for %s",  conn->desc);
            close(fd);
            sb_connection_del(conn);
        } else {
            buf->len = ret;
            buf->head = buf->data;
            // put data into queue, will send to client
            TAILQ_INSERT_TAIL(&(conn->buffers), buf, entries);
            conn->buffer_count++;
            event_add(conn->writeevent, NULL);
            // if buffer full, disable read
            if (conn->buffer_count == SB_BUFFER_MAX) {
                event_del(conn->readevent);
            }
        }
    }
}

void sb_do_net_write(evutil_socket_t fd, short what, void * data) {
    struct sb_connection * conn = data;
    if (what & EV_WRITE) {
        log_debug("EV_WRITE");

        struct sb_buffer * buf;
        while(1) {
            buf = TAILQ_FIRST(&conn->buffers);
            if (!buf) { break; }
            int tosend = ((char *)buf->data) + buf->len - buf->head;
            int ret = send(fd, buf->head, tosend, 0);
            if (ret < 0) {
                if (errno != EAGAIN) {
                    // error
                    log_error("failed to send data to connection: %s", conn->desc);
                }
                return;
            } else if (ret == 0) {
                log_warn("sent 0 byte to connection %s", conn->desc);
                return;
            } else {
                if (ret == tosend) {
                    // all sent, remove buf from buffers
                    TAILQ_REMOVE(&(conn->buffers), buf, entries);
                    conn->buffer_count--;
                    event_add(conn->readevent, NULL);
                } else if (ret < tosend) {
                    buf->head += ret;
                } else {
                    log_warn("sent to %s more bytes than request, impossible", conn->desc);
                }
            }
        }
        if (TAILQ_EMPTY(&(conn->buffers))) {
            log_debug("no data in buffers, disabling write for %s",  conn->desc);
            event_del(conn->writeevent);
        }
    }
}

int main(int argc, char ** argv) {
    struct event_base * eventbase;

    // setup libevent log
    event_set_log_callback(libevent_log);

    eventbase = event_base_new();
    if (!eventbase) {
        log_fatal("failed to init eventbase: %s", strerror(errno));
        return 1;
    }

    struct sockaddr_in listen_addr;
    int listen_fd;
    struct event *accept_ev;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(8888);
    listen_fd = sb_server_socket(AF_INET, (struct sockaddr *)&listen_addr, sizeof(listen_addr));
    if (listen_fd < 0) {
        log_fatal("failed to setup server socket for ipv4.");
        return 1;
    } else {
        accept_ev = event_new(eventbase, listen_fd, EV_READ|EV_PERSIST, sb_do_net_accept, eventbase);
        event_add(accept_ev, NULL);
    }
#ifndef __linux__
    struct sockaddr_in6 listen_addr6;
    int listen_fd6;
    struct event *accept_ev6;
    memset(&listen_addr6, 0, sizeof(listen_addr6));
    listen_addr6.sin6_family = AF_INET6;
    listen_addr6.sin6_addr = in6addr_any;
    listen_addr6.sin6_port = htons(8888);
    listen_fd6 = sb_server_socket(AF_INET6, (struct sockaddr *)&listen_addr6, sizeof(listen_addr6));
    if (listen_fd6 < 0) {
        log_fatal("failed to setup server socket for ipv6.");
        return 1;
    } else {
        accept_ev6 = event_new(eventbase, listen_fd6, EV_READ|EV_PERSIST, sb_do_net_accept, eventbase);
        event_add(accept_ev6, NULL);
    }
#endif


    /* Start the event loop. */
    event_base_dispatch(eventbase);

    return 0;
}

