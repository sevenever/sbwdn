#include <event2/event.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdbool.h>

#include "log.h"
#include "sbwdn.h"
#include "sb_tun.h"


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
            struct sb_app * app = data;
            struct sb_connection * conn = sb_connection_new(app, client_fd);
            if (!conn) {
                log_error("failed to init connection for net fd %d", client_fd);
                return;
            }
            event_add(conn->net_readevent, 0);
        }
    }
}

struct sb_package * sb_package_new(char * ipdata, int ipdatalen) {
    struct sb_package * p = malloc(sizeof(struct sb_package));
    if (!p) {
        log_error("fail to allocate memory for sb_package, %s", strerror(errno));
        return 0;
    }
    p->ipdata = malloc(ipdatalen);
    if (!p->ipdata) {
        log_error("fail to allocate memory for sb_package->ipdata, %s", strerror(errno));
        return 0;
    }

    p->ipdatalen = ipdatalen;
    memcpy(p->ipdata, ipdata, ipdatalen);

    return p;
}
struct sb_connection * sb_connection_new(struct sb_app * app, int client_fd) {
    struct sb_connection * conn = malloc(sizeof(struct sb_connection));
    if (!conn) {
        log_error("failed to allocate connection object %s", strerror(errno));
        return 0;
    }
    conn->net_fd = client_fd;
    inet_pton(AF_INET, "192.168.255.2", &conn->peer_addr.s_addr);
    conn->net_mode = TCP;
    conn->eventbase = app->eventbase;
    conn->app = app;

    struct event * net_readevent = event_new(conn->eventbase, conn->net_fd, EV_READ | EV_PERSIST, sb_do_net_read, conn);
    conn->net_readevent = net_readevent;
    struct event * net_writeevent = event_new(conn->eventbase, conn->net_fd, EV_WRITE | EV_PERSIST, sb_do_net_write, conn);
    conn->net_writeevent = net_writeevent;

    TAILQ_INIT(&(conn->packages_n2t));
    conn->n2t_pkg_count = 0;
    TAILQ_INIT(&(conn->packages_t2n));
    conn->t2n_pkg_count = 0;

    if (sb_net_reader_init(&(conn->net_reader), conn) < 0) {
        log_error("failed init net reader");
        return 0;
    }
    if (sb_net_writer_init(&(conn->net_writer), conn) < 0) {
        log_error("failed init net writer");
        return 0;
    }

    snprintf(conn->desc, SB_CONN_DESC_MAX, "[net_fd: %d]", conn->net_fd);

    TAILQ_INSERT_TAIL(&(app->conns), conn, entries);

    return conn;
}

void sb_connection_del(struct sb_connection * conn) {
    struct sb_app * app = conn->app;

    TAILQ_REMOVE(&(app->conns), conn, entries);

    sb_net_writer_del(&(conn->net_writer));
    sb_net_reader_del(&(conn->net_reader));

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
    event_del(conn->net_readevent);

    free(conn);
}

int sb_net_reader_init(struct sb_net_reader * reader, struct sb_connection * conn) {
    reader->buf = malloc(sizeof(struct sb_net_buf));
    if (!reader->buf) {
        log_error("failed to allocate a sb_net_buf %d %s", errno, strerror(errno));
        return -1;
    }
    reader->state = LEN;
    reader->cur_p = reader->buf->len_buf;
    reader->conn = conn;

    return 0;
}

void sb_net_reader_del(struct sb_net_reader * reader) {
    reader->conn = 0;
    reader->cur_p = reader->buf->len_buf;
    reader->state = LEN;
    free(reader->buf);

    return;
}

int sb_net_reader_read(struct sb_net_reader * reader, int fd) {
    while(1) {
        int buflen;
        if (reader->state == LEN) {
            buflen = sizeof(reader->buf->len_buf) - (reader->cur_p - reader->buf->len_buf);
        } else if (reader->state == PKG) {
            buflen = reader->pkg_len - (reader->cur_p - reader->buf->pkg_buf);
        } else {
            log_warn("invalid reader->state: %d", reader->state);
            return -1;
        }
        log_debug("tring to read %d bytes from %s", buflen, reader->conn->desc);
        int ret = recv(fd, reader->cur_p, buflen, 0);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 1;
            } else {
                // error
                log_error("failed to receive data from connection %s: %d %s", reader->conn->desc, ret, strerror(ret));
                return -1;
            }
        } else if (ret == 0) {
            // EOF
            return 0;
        } else {
            // some bytes were read
            if (ret < buflen) {
                // read less than we want
                reader->cur_p += ret;
            } else if (ret > buflen) {
                log_warn("read from %s more bytes than request, impossible", reader->conn->desc);
            } else {
                // read equals we want, ipdatalen is fully read or ipdata is fully read
                if (reader->state == LEN) {
                    reader->pkg_len = ntohs(*((uint16_t*)reader->buf->len_buf));
                    reader->cur_p = reader->buf->pkg_buf;
                    reader->state = PKG;
                } else if (reader->state == PKG) {
                    // full package is read, construct a sb_package, put into conn->packages_n2t
                    struct sb_package * pkg = sb_package_new(reader->buf->pkg_buf, reader->pkg_len);
                    if (!pkg) {
                        log_error("failed to create a sb_package for %s", reader->conn->desc);
                        return -1;
                    } else {
                        struct sb_connection * conn = reader->conn;
                        TAILQ_INSERT_TAIL(&(conn->packages_n2t), pkg, entries);
                        conn->n2t_pkg_count++;
                        if (conn->n2t_pkg_count >= SB_PKG_BUF_MAX) {
                            return 2;
                        }
                    }
                    reader->cur_p = reader->buf->len_buf;
                    reader->state = LEN;
                } else {
                    log_warn("invalid reader->state: %d", reader->state);
                    return -1;
                }
            }
        }
    }
}

int sb_net_writer_init(struct sb_net_writer * writer, struct sb_connection * conn) {
    writer->buf = malloc(sizeof(struct sb_net_buf));
    if (!writer->buf) {
        log_error("failed to allocate a sb_net_buf %d %s", errno, strerror(errno));
        return -1;
    }
    writer->cur_p = 0;
    writer->pkg_len = 0;
    writer->cur_pkg = 0;
    writer->conn = conn;

    return 0;
}

void sb_net_writer_del(struct sb_net_writer * writer) {
    free(writer->buf);
    writer->cur_p = 0;
    writer->pkg_len = 0;
    writer->cur_pkg = 0;
    writer->conn = 0;
}

/* Write packages into fd until error or no more data can be written.
 * If sb_package is not fully written, remaining data will be in the writer.
 * return -1 if error, errno is set
 * return 1 if fd is not ready any more
 * return 2 if no more data available
 */
int sb_net_writer_write(struct sb_net_writer * writer, int fd) {
    // prepare the writer
    if (!(writer->cur_pkg)) {
        writer->cur_pkg = TAILQ_FIRST(&(writer->conn->packages_t2n));
        if (!writer->cur_pkg) {
            log_debug("no pkg ready to be sent to net %s", writer->conn);
            return 2;
        }
        (*(unsigned short *)writer->buf->len_buf) = htons(writer->cur_pkg->ipdatalen);
        memcpy(writer->buf->pkg_buf, writer->cur_pkg->ipdata, writer->cur_pkg->ipdatalen);
        writer->cur_p = writer->buf->len_buf;
        writer->pkg_len = writer->cur_pkg->ipdatalen;
    }
    int buflen = writer->pkg_len + sizeof(writer->buf->len_buf) - (writer->cur_p - writer->buf->len_buf);
    log_debug("writing %d bytes to %s", buflen, writer->conn->desc);
    int ret = send(fd, writer->cur_p, buflen, 0);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 1;
        }
        // error
        log_error("failed to send to net %s", writer->conn->desc);
        return -1;
    } else {
        writer->cur_p += ret;
        if (ret == buflen) {
            writer->cur_pkg = 0;
            writer->cur_p = writer->buf->len_buf;
        }
    }
}

void sb_do_net_read(evutil_socket_t fd, short what, void * data) {
    struct sb_connection * conn = data;
    struct sb_app * app = conn->app;

    /* read net fd, until error/EOF/EAGAIN */
    int ret = sb_net_reader_read(&(conn->net_reader), fd);
    if (ret < 0) {
        log_error("failed to read from %s", conn->desc);
    } else if (ret == 0) {
        // EOF
        log_info("net peer closed connection, closing net connection for %s",  conn->desc);
        close(fd);
        sb_connection_del(conn);
    } else if (ret == 2) {
        // packages_n2t full
        event_del(conn->net_readevent);
    } else {
        if (conn->n2t_pkg_count > 0) {
            event_add(app->tun_writeevent, 0);
        }
    }
}

void sb_do_net_write(evutil_socket_t fd, short what, void * data) {
    struct sb_connection * conn = data;

    if (!(what & EV_WRITE)) {
        return;
    }
    int ret = sb_net_writer_write(&(conn->net_writer), fd);
    if (ret < 0) {
        log_error("failed to write to %s", conn->desc);
        // close connection?
    } else if (ret == 1) {
        // no more pkg from tun, just wait
    } else {
        event_del(conn->net_writeevent);
    }
    return;
}

void sb_do_tun_read(evutil_socket_t fd, short what, void * data) {
    struct sb_app * app = (struct sb_app *) data;
    /* read a package from tun */
    int ret;
    int buflen = app->mtu + sizeof(struct sb_tun_pi);
    char buf[buflen];

    log_debug("reading a package from tun");
    ret = read(fd, buf, buflen);
    if (ret < 0) {
        log_error("failed to receive package from tun: %d %s", errno, strerror(errno));
        return;
    }
    log_debug("read %d bytes from tun", ret);

    struct sb_tun_pi * pi = (struct sb_tun_pi *)buf;
    pi->flags = ntohs(pi->flags);
    pi->proto = ntohs(pi->proto);
    log_debug("flags in tun_pi:%04x", pi->flags);
    log_debug("proto in tun_pi:%04x", pi->proto);
    if (pi->proto != PROTO_IPV4) {
        log_debug("unsupported protocol %04x", pi->proto);
        return;
    }
    /* check if the target ip is one of our client, if no, drop it on the floor */
    /* if target ip is one of our client, queue it into that connection's packages_t2n */
    /* if necessary, enable net_writeevent for that connection */
    struct iphdr * iphdr = &(((struct sb_tun_pkg *)buf)->iphdr);
    struct in_addr saddr = *(struct in_addr *)&(iphdr->saddr);
    struct in_addr daddr = *(struct in_addr *)&(iphdr->daddr);
    iphdr->saddr = ntohl(iphdr->saddr);
    iphdr->daddr = ntohl(iphdr->daddr);
    unsigned int ipdatalen = ret - sizeof(struct sb_tun_pi);
    char srcbuf[128];
    char dstbuf[128];
    log_debug("src addr: %s, dest addr: %s, ip pkg len: %d",
            inet_ntop(AF_INET, (const void *)&saddr, srcbuf, sizeof(srcbuf)),
            inet_ntop(AF_INET, (const void *)&daddr, dstbuf, sizeof(dstbuf)),
            ipdatalen);

    struct sb_connection * conn;
    TAILQ_FOREACH(conn, &(app->conns), entries) {
        if (conn->peer_addr.s_addr == daddr.s_addr) {
            if (conn->t2n_pkg_count >= SB_PKG_BUF_MAX) {
                /* should I send a ICMP or something? */
            } else {
                struct sb_package * pkg = sb_package_new((char *)iphdr, ipdatalen);
                TAILQ_INSERT_TAIL(&(conn->packages_t2n), pkg, entries);
                event_add(conn->net_writeevent, 0);
            }
        }
    }
}

void sb_do_tun_write(evutil_socket_t fd, short what, void * data) {
    struct sb_app * app = (struct sb_app *)data;
    /* pick a connection that has package pending in packages_n2t */
    struct sb_connection * conn;
    TAILQ_FOREACH(conn, &(app->conns), entries) {
        if (conn->n2t_pkg_count > 0) {
            struct sb_package * pkg;
            TAILQ_FOREACH(pkg, &(conn->packages_n2t), entries) {
                /* send that package into tun */
                int ret = send(fd, pkg->ipdata, pkg->ipdatalen, 0);
                if (ret < 0) {
                    if (ret == EAGAIN || ret == EWOULDBLOCK) {
                        return;
                    } else {
                        log_error("failed to write to tun device: %d %s", errno, strerror(errno));
                        return;
                    }
                } else {
                    TAILQ_REMOVE(&(conn->packages_n2t), pkg, entries);
                    event_add(conn->net_readevent, 0);
                }
            }
        }
    }
    /* if necessary, disable writeevent for tun */
    bool disable = true;
    TAILQ_FOREACH(conn, &(app->conns), entries) {
        if (conn->n2t_pkg_count > 0) {
            disable = false;
        }
    }
    if (disable) {
        event_del(app->tun_writeevent);
    }
}

struct sb_app * sb_app_new(int tun_fd, struct event_base * eventbase) {
    struct sb_app * app = malloc(sizeof(struct sb_app));
    if (!app) {
        log_error("failed to allocate memory for sb_app: %s", strerror(errno));
        return 0;
    }
    app->tun_fd = tun_fd;
    app->eventbase = eventbase;
    TAILQ_INIT(&(app->conns));

    return app;
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

    int mtu = 1500;
    int tun_fd = setup_tun("192.168.255.1", "255.255.255.0", mtu);
    if (tun_fd < 0) {
        log_fatal("failed to setup tun device");
        return 1;
    }

    struct sb_app * app = sb_app_new(tun_fd, eventbase);
    if (!app) {
        log_fatal("faied to init sb_app");
        return 1;
    }

    app->mtu = mtu;
    struct event * tun_readevent = event_new(eventbase, tun_fd, EV_READ|EV_PERSIST, sb_do_tun_read, app);
    struct event * tun_writeevent = event_new(eventbase, tun_fd, EV_WRITE|EV_PERSIST, sb_do_tun_write, app);
    event_add(tun_readevent, 0);
    event_add(tun_writeevent, 0);

    app->tun_readevent = tun_readevent;
    app->tun_writeevent = tun_writeevent;

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
        accept_ev = event_new(eventbase, listen_fd, EV_READ|EV_PERSIST, sb_do_net_accept, app);
        event_add(accept_ev, 0);
    }

    /* Start the event loop. */
    event_base_dispatch(eventbase);

    return 0;
}

