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
#include <netdb.h>

#include "sb_log.h"
#include "sb_config.h"
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

static int sb_client_socket(struct sockaddr_in * server_addr, socklen_t addr_len) {
    int fd;
    /* Create our listening socket. */
    fd = socket(server_addr->sin_family, SOCK_STREAM, 0);
    if (fd < 0) {
        log_fatal("failed to create client socket: %s", strerror(errno));
        return -1;
    }
    int ret = connect(fd, (struct sockaddr *)server_addr, addr_len);
    if (ret<0) {
        log_fatal("failed to connect to server %d %s", errno, strerror(errno));
        return -1;
    }
    if (evutil_make_socket_closeonexec(fd) < 0) {
        log_fatal("failed to set client socket to closeonexec: %s", strerror(errno));
        return -1;
    }
    /* Set the socket to non-blocking, this is essential in event
     * based programming with libevent. */
    if (evutil_make_socket_nonblocking(fd) < 0) {
        log_fatal("failed to set client socket to nonblock: %s", strerror(errno));
        return -1;
    }

    return fd;
}

static int sb_server_socket(struct sockaddr_in * listen_addr, socklen_t addr_len) {
    int listen_fd;
    /* Create our listening socket. */
    listen_fd = socket(listen_addr->sin_family, SOCK_STREAM, 0);
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
        log_fatal("failed to set server socket to closeonexec: %s", strerror(errno));
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
            char addr[INET_ADDRSTRLEN];
            log_info("accepted connection from %s.", inet_ntop(client_addr.ss_family, (const void*)&(((struct sockaddr_in *)&client_addr)->sin_addr), addr, sizeof(addr)));

            if (evutil_make_socket_nonblocking(client_fd) < 0) {
                log_error("failed to set client socket to nonblock: %s", strerror(errno));
                close(client_fd);
                return;
            }
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
    conn->net_mode = TCP;
    conn->net_state = CONNECTED;

    conn->app = app;
    conn->eventbase = app->eventbase;

    struct event * net_readevent = event_new(conn->eventbase, conn->net_fd, EV_READ | EV_PERSIST, sb_do_net_read, conn);
    conn->net_readevent = net_readevent;
    struct event * net_writeevent = event_new(conn->eventbase, conn->net_fd, EV_WRITE | EV_PERSIST, sb_do_net_write, conn);
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

    snprintf(conn->desc, SB_CONN_DESC_MAX, "[net_fd: %d]", conn->net_fd);

    TAILQ_INSERT_TAIL(&(app->conns), conn, entries);

    return conn;
}

void sb_connection_del(struct sb_connection * conn) {
    struct sb_app * app = conn->app;

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

    event_free(conn->net_writeevent);
    event_free(conn->net_readevent);

    conn->eventbase = 0;
    conn->app = 0;

    memset(&conn->peer_addr, 0, sizeof(conn->peer_addr));

    conn->net_state = TERMINATED;
    conn->net_fd = -1;

    free(conn);
}
void sb_conn_net_received_pkg(struct sb_connection * conn, struct sb_package * pkg) {
    switch(conn->net_state) {
        case CONNECTED:
            // this is the init package, contains client ip
            conn->peer_addr = *((struct in_addr *)pkg->ipdata);
            char buf[INET_ADDRSTRLEN];
            log_info("peer addr is %s", inet_ntop(AF_INET, (const void *)&(conn->peer_addr), buf, sizeof(buf)));
            conn->net_state = ESTABLISHED;
            break;
        case ESTABLISHED:
            log_debug("queue a pkg from net");
            TAILQ_INSERT_TAIL(&(conn->packages_n2t), pkg, entries);
            conn->n2t_pkg_count++;
            log_debug("n2t_pkg_count is %d after inert", conn->n2t_pkg_count);
            break;
        case TERMINATED:
            log_warn("received a pkg in TERMINATED state");
            break;
        default:
            log_warn("invalide state %d", conn->net_state);
            break;
    }
    return;
}

int sb_net_io_buf_init(struct sb_net_io_buf * io_buf, struct sb_connection * conn) {
    io_buf->buf = malloc(sizeof(struct sb_net_buf));
    if (!io_buf->buf) {
        log_error("failed to allocate a sb_net_buf %d %s", errno, strerror(errno));
        return -1;
    }
    io_buf->state = LEN;
    io_buf->cur_pkg = 0;
    io_buf->cur_p = io_buf->buf->len_buf;
    io_buf->pkg_len = 0;
    io_buf->conn = conn;

    return 0;
}

void sb_net_io_buf_del(struct sb_net_io_buf * io_buf) {
    io_buf->conn = 0;
    io_buf->pkg_len = 0;
    io_buf->cur_p = io_buf->buf->len_buf;
    io_buf->cur_pkg = 0;
    io_buf->state = LEN;
    free(io_buf->buf);

    return;
}

int sb_net_io_buf_read(struct sb_net_io_buf * read_buf, int fd) {
    int buflen;
    if (read_buf->state == LEN) {
        buflen = sizeof(read_buf->buf->len_buf) - (read_buf->cur_p - read_buf->buf->len_buf);
    } else if (read_buf->state == PKG) {
        buflen = read_buf->pkg_len - (read_buf->cur_p - read_buf->buf->pkg_buf);
    } else {
        log_warn("invalid read_buf->state: %d", read_buf->state);
        return -1;
    }
    log_debug("trying to read %d bytes from %s", buflen, read_buf->conn->desc);
    int ret = recv(fd, read_buf->cur_p, buflen, 0);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            log_debug("no more data available from %s", read_buf->conn->desc);
            return 0;
        } else {
            // error
            log_error("failed to receive data from connection %s: %d %s", read_buf->conn->desc, ret, strerror(ret));
            return -1;
        }
    } else if (ret == 0) {
        // EOF
        return 2;
    } else {
        log_debug("read %d bytes from %s", ret, read_buf->conn->desc);
        // some bytes were read
        if (ret < buflen) {
            // read less than we want
            read_buf->cur_p += ret;
        } else if (ret > buflen) {
            log_warn("read from %s more bytes than request, impossible", read_buf->conn->desc);
            return -1;
        } else {
            // read equals we want, ipdatalen is fully read or ipdata is fully read
            if (read_buf->state == LEN) {
                read_buf->pkg_len = ntohs(*((uint16_t*)read_buf->buf->len_buf));
                read_buf->cur_p = read_buf->buf->pkg_buf;
                read_buf->state = PKG;
            } else if (read_buf->state == PKG) {
                // full package is read, construct a sb_package, put into conn->packages_n2t
                struct sb_package * pkg = sb_package_new(read_buf->buf->pkg_buf, read_buf->pkg_len);
                if (!pkg) {
                    log_error("failed to create a sb_package for %s", read_buf->conn->desc);
                    return -1;
                } else {
                    read_buf->cur_pkg = pkg;
                }
                read_buf->cur_p = read_buf->buf->len_buf;
                read_buf->state = LEN;
            } else {
                log_warn("invalid read_buf->state: %d", read_buf->state);
                return -1;
            }
        }
        return 1;
    }
}


int sb_net_io_buf_write(struct sb_net_io_buf * write_buf, int fd) {
    int buflen = write_buf->pkg_len + sizeof(write_buf->buf->len_buf) - (write_buf->cur_p - write_buf->buf->len_buf);
    log_debug("writing %d bytes to %s", buflen, write_buf->conn->desc);
    int ret = send(fd, write_buf->cur_p, buflen, 0);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        // error
        log_error("failed to send to net %s", write_buf->conn->desc);
        return -1;
    } else {
        write_buf->cur_p += ret;
        if (ret == buflen) {
            write_buf->cur_pkg = 0;
            write_buf->cur_p = write_buf->buf->len_buf;
        }
        return 1;
    }
}

void sb_do_net_read(evutil_socket_t fd, short what, void * data) {
    struct sb_connection * conn = data;
    struct sb_net_io_buf * read_buf = &conn->net_read_io_buf;
    struct sb_app * app = conn->app;
    bool enable_tun_write = false;
    bool disable_net_read = false;

    /* read net fd, until error/EOF/EAGAIN */
    while (1) {
        int ret = sb_net_io_buf_read(read_buf, fd);
        if (ret < 0) {
            log_error("failed to read from %s", conn->desc);
        } else if (ret == 0) {
            /* fd not readable, wait */
            break;
        } else if (ret == 1) {
            if (read_buf->cur_pkg) {
                sb_conn_net_received_pkg(conn, read_buf->cur_pkg);
                if (conn->n2t_pkg_count >= SB_PKG_BUF_MAX) {
                    // packages_n2t full
                    disable_net_read = true;
                }
                read_buf->cur_pkg = 0;
            }
        } else if (ret == 2) {
            // EOF
            log_info("net peer closed connection, closing net connection for %s",  conn->desc);
            close(fd);
            sb_connection_del(conn);
            break;
        }
    }
    
    if (disable_net_read) {
        log_debug("disabling net read");
        event_del(conn->net_readevent);
    }
    if (conn->n2t_pkg_count > 0) {
        log_debug("enabling tun write");
        enable_tun_write = true;
        event_add(app->tun_writeevent, 0);
    }
}

void sb_do_net_write(evutil_socket_t fd, short what, void * data) {
    struct sb_connection * conn = data;
    struct sb_net_io_buf * write_buf = &conn->net_write_io_buf;
    bool enable_tun_read = false;
    bool disable_net_write = false;

    while (1) {
        if (!(write_buf->cur_pkg)) {
            /* prepare data for write_buf */
            write_buf->cur_pkg = TAILQ_FIRST(&(conn->packages_t2n));
            if (!write_buf->cur_pkg) {
                log_debug("no pkg ready to be sent to net %s", conn);
                disable_net_write = true;
                break;
            }
            (*(unsigned short *)write_buf->buf->len_buf) = htons(write_buf->cur_pkg->ipdatalen);
            memcpy(write_buf->buf->pkg_buf, write_buf->cur_pkg->ipdata, write_buf->cur_pkg->ipdatalen);
            write_buf->cur_p = write_buf->buf->len_buf;
            write_buf->pkg_len = write_buf->cur_pkg->ipdatalen;
        }
        struct sb_package * writing_pkg = write_buf->cur_pkg;
        int ret = sb_net_io_buf_write(&(conn->net_write_io_buf), fd);
        if (ret < 0) {
            log_error("failed to write to %s", conn->desc);
            // close connection?
        } else if (ret == 0) {
            /* fd not writable, wait */
            break;
        } else if (ret == 1) {
            if (!write_buf->cur_pkg) {
                TAILQ_REMOVE(&(conn->packages_t2n), writing_pkg, entries);
                conn->t2n_pkg_count--;
                enable_tun_read = true;
            }
        }
    }

    if (disable_net_write) {
        event_del(conn->net_writeevent);
    }
    if (enable_tun_read) {
        event_add(conn->app->tun_readevent, 0);
    }
    return;
}

void sb_do_tun_read(evutil_socket_t fd, short what, void * data) {
    struct sb_app * app = (struct sb_app *) data;
    /* read a package from tun */
    int tun_frame_size;
    int buflen = app->config->mtu + sizeof(struct sb_tun_pi);
    char buf[buflen];

    log_debug("reading a package from tun");
    tun_frame_size = read(fd, buf, buflen);
    if (tun_frame_size < 0) {
        log_error("failed to receive package from tun: %d %s", errno, strerror(errno));
        return;
    }
    log_debug("read %d bytes from tun", tun_frame_size);

    struct sb_tun_pi pi = *(struct sb_tun_pi *)buf;
    pi.flags = ntohs(pi.flags);
    pi.proto = ntohs(pi.proto);
    log_debug("flags in tun_pi:%04x", pi.flags);
    log_debug("proto in tun_pi:%04x", pi.proto);
    if (pi.proto != PROTO_IPV4) {
        log_debug("unsupported protocol %04x", pi.proto);
        return;
    }
    /* check if the target ip is one of our client, if no, drop it on the floor */
    /* if target ip is one of our client, queue it into that connection's packages_t2n */
    /* if necessary, enable net_writeevent for that connection */
    struct iphdr * iphdr = &(((struct sb_tun_pkg *)buf)->iphdr);
    struct in_addr saddr = *(struct in_addr *)&(iphdr->saddr);
    struct in_addr daddr = *(struct in_addr *)&(iphdr->daddr);
    unsigned int ipdatalen = tun_frame_size - sizeof(struct sb_tun_pi);
    char srcbuf[INET_ADDRSTRLEN];
    char dstbuf[INET_ADDRSTRLEN];
    log_debug("src addr: %s, dest addr: %s, ip pkg len: %d",
            inet_ntop(AF_INET, (const void *)&saddr, srcbuf, sizeof(srcbuf)),
            inet_ntop(AF_INET, (const void *)&daddr, dstbuf, sizeof(dstbuf)),
            ipdatalen);

    struct sb_connection * conn;
    TAILQ_FOREACH(conn, &(app->conns), entries) {
        log_debug("conn addr: %d, pkg addr: %d", conn->peer_addr.s_addr, daddr.s_addr);
        if (app->config->app_mode == CLIENT || conn->peer_addr.s_addr == daddr.s_addr) {
            if (conn->t2n_pkg_count >= SB_PKG_BUF_MAX) {
                /* should I send a ICMP or something? */
            } else {
                struct sb_package * pkg = sb_package_new((char *)buf, tun_frame_size);
                log_debug("queue a pkg from tun for connection %s", conn->desc);
                TAILQ_INSERT_TAIL(&(conn->packages_t2n), pkg, entries);
                conn->t2n_pkg_count++;
                event_add(conn->net_writeevent, 0);
            }
        }
    }
}

void sb_do_tun_write(evutil_socket_t fd, short what, void * data) {
    struct sb_app * app = (struct sb_app *)data;
    bool disable_tun_write = true;
    /* pick a connection that has package pending in packages_n2t */
    struct sb_connection * conn;
    TAILQ_FOREACH(conn, &(app->conns), entries) {
        log_debug("n2t_pkg_count is %d", conn->n2t_pkg_count);
        if (conn->n2t_pkg_count > 0) {
            struct sb_package * pkg;
            TAILQ_FOREACH(pkg, &(conn->packages_n2t), entries) {
                /* send that package into tun */
                log_debug("sending a pkg with length %d to tun", pkg->ipdatalen);
                int ret = write(fd, pkg->ipdata, pkg->ipdatalen);
                if (ret < 0) {
                    if (ret == EAGAIN || ret == EWOULDBLOCK) {
                        return;
                    } else {
                        log_error("failed to write to tun device: %d %s", errno, strerror(errno));
                        return;
                    }
                } else {
                    log_debug("sent a pkg with length %d to tun", ret);
                    TAILQ_REMOVE(&(conn->packages_n2t), pkg, entries);
                    conn->n2t_pkg_count--;
                    log_debug("n2t_pkg_count is %d after remove", conn->n2t_pkg_count);
                    event_add(conn->net_readevent, 0);
                }
            }
        }
    }
    /* if no pkg in queue of any conn, disable writeevent for tun */
    TAILQ_FOREACH(conn, &(app->conns), entries) {
        if (conn->n2t_pkg_count > 0) {
            disable_tun_write = false;
        }
    }
    if (disable_tun_write) {
        event_del(app->tun_writeevent);
    }
}

struct sb_app * sb_app_new(struct event_base * eventbase) {
    struct sb_app * app = malloc(sizeof(struct sb_app));
    if (!app) {
        log_error("failed to allocate memory for sb_app: %s", strerror(errno));
        return 0;
    }
    app->config = 0;
    app->eventbase = eventbase;
    app->tun_readevent = 0;
    app->tun_writeevent = 0;
    TAILQ_INIT(&(app->conns));

    return app;
}
int main(int argc, char ** argv) {
    if (argc != 3 || strlen(argv[1]) != 2 || strncmp(argv[1], "-f", 2) != 0) {
        dprintf(STDERR_FILENO, "Usage: %s -f [config file path]\n", argv[0]);
        return 1;
    }

    sb_logger.lvl = LOG_INFO;

    /* setup libevent */
    struct event_base * eventbase;
    // setup libevent log
    event_set_log_callback(libevent_log);

    eventbase = event_base_new();
    if (!eventbase) {
        log_fatal("failed to init eventbase: %s", strerror(errno));
        return 1;
    }

    struct sb_app * app = sb_app_new(eventbase);
    if (!app) {
        log_fatal("faied to init sb_app");
        return 1;
    }

    char * config_file = argv[2];
    struct sb_config * config = sb_config_read(config_file);
    if(!config) {
        log_fatal("failed to read config file %s", config_file);
        return -1;
    }
    sb_config_apply(app, config);

    int tun_fd = setup_tun(app->config->addr, app->config->paddr, app->config->mask, app->config->mtu);
    if (tun_fd < 0) {
        log_fatal("failed to setup tun device");
        return 1;
    }
    if (evutil_make_socket_nonblocking(tun_fd) < 0) {
        log_fatal("failed to set tun_fd to nonblock: %s", strerror(errno));
        return -1;
    }
    app->tun_fd = tun_fd;

    struct event * tun_readevent = event_new(eventbase, tun_fd, EV_READ|EV_PERSIST, sb_do_tun_read, app);
    struct event * tun_writeevent = event_new(eventbase, tun_fd, EV_WRITE|EV_PERSIST, sb_do_tun_write, app);
    event_add(tun_readevent, 0);
    event_add(tun_writeevent, 0);

    app->tun_readevent = tun_readevent;
    app->tun_writeevent = tun_writeevent;

    if (app->config->app_mode == SERVER) {
        struct sockaddr_in listen_addr;
        int listen_fd;
        struct event *accept_ev;
        memset(&listen_addr, 0, sizeof(listen_addr));
        listen_addr.sin_family = AF_INET;
        int ret = inet_pton(AF_INET, app->config->bind, &listen_addr.sin_addr);
        if (ret < 0) {
            log_error("failed to parse bind address %s. %d %s", app->config->bind, errno, strerror(errno));
            return 1;
        } else if (ret == 0) {
            log_error("invalide bind address %s", app->config->bind);
            return 1;
        }
        listen_addr.sin_port = htons(app->config->port);
        listen_fd = sb_server_socket(&listen_addr, sizeof(listen_addr));
        if (listen_fd < 0) {
            log_fatal("failed to setup server socket for ipv4.");
            return 1;
        } else {
            accept_ev = event_new(eventbase, listen_fd, EV_READ|EV_PERSIST, sb_do_net_accept, app);
            event_add(accept_ev, 0);
        }
    } else {
        int ret;
        int client_fd;
        /* client mode */
        log_info("connecting to %s:%d", app->config->remote, app->config->port);
        struct addrinfo hint, *ai, *ai0;
        memset(&hint, 0, sizeof(hint));
        hint.ai_family = AF_INET;
        hint.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(app->config->remote, 0, &hint, &ai0)) {
            log_error("failed to resolve server address %s", app->config->remote);
            return 1;
        }
        for(ai=ai0;ai;ai = ai->ai_next) {
            if (ai->ai_family == AF_INET) {
                ((struct sockaddr_in *)(ai->ai_addr))->sin_port = htons(app->config->port);
            }
            if ((client_fd = sb_client_socket((struct sockaddr_in *)ai->ai_addr, ai->ai_addrlen)) < 0) {
                log_fatal("failed to setup client socket");
            }
        }
        if (client_fd < 0) {
            return 1;
        }
        log_info("connected to %s:%d", app->config->remote, app->config->port);
        struct sb_connection * conn = sb_connection_new(app, client_fd);
        if (!conn) {
            log_error("failed to init connection for net fd %d", client_fd);
            return 1;
        }
        /* put a initial package into packages_t2n, so that it can be send to server */
        struct sockaddr_in vpn_addr;
        ret = inet_pton(AF_INET, app->config->addr, &vpn_addr.sin_addr);
        if (ret < 0) {
            log_error("failed to parse address %s. %d %s", app->config->addr, errno, strerror(errno));
            return 1;
        } else if (ret == 0) {
            log_error("invalide addr address %s", app->config->addr);
            return 1;
        }
        struct sb_package * init_pkg = sb_package_new((char *)&vpn_addr.sin_addr, sizeof(vpn_addr.sin_addr));
        if (!init_pkg) {
            log_error("failed to create init pkg");
            return 1;
        }
        TAILQ_INSERT_TAIL(&(conn->packages_t2n), init_pkg, entries);
        conn->t2n_pkg_count++;
        conn->net_state = ESTABLISHED;
        event_add(conn->net_readevent, 0);
        event_add(conn->net_writeevent, 0);
    }

    /* Start the event loop. */
    event_base_dispatch(eventbase);

    return 0;
}

