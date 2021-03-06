#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <event2/event.h>

#include "sb_log.h"
#include "sb_util.h"

int sb_util_sockaddr_cmp(struct sockaddr * addr1, struct sockaddr * addr2) {
    if (addr1->sa_family == AF_INET && addr2->sa_family == AF_INET) {
        struct sockaddr_in *a1, *a2;
        a1 = (struct sockaddr_in *)addr1;
        a2 = (struct sockaddr_in *)addr2;
        if (a1->sin_addr.s_addr == a2->sin_addr.s_addr && a1->sin_port == a2->sin_port) {
            return 0;
        }
    } else if (addr1->sa_family == AF_INET6 && addr2->sa_family == AF_INET6) {
        struct sockaddr_in6 *a1, *a2;
        a1 = (struct sockaddr_in6 *)addr1;
        a2 = (struct sockaddr_in6 *)addr2;
        if (memcmp(&a1->sin6_addr, &a2->sin6_addr, sizeof(struct in6_addr)) == 0 && a1->sin6_port == a2->sin6_port) {
            return 0;
        }
    }

    return -1;
}

const char * sb_util_human_addr(int family, void * addr) {
    static char buf[INET6_ADDRSTRLEN];

    inet_ntop(family, addr, buf, sizeof(buf));

    return buf;
}
const char * sb_util_human_endpoint(struct sockaddr * addr) {
    /* 1 for :, 8 for port number */
    static char buf[(INET_ADDRSTRLEN > INET6_ADDRSTRLEN ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN) + 1 + 8];

    void * addrp;
    unsigned short port;
    if (addr->sa_family == AF_INET) {
        addrp = &((struct sockaddr_in *)addr)->sin_addr;
        port = ((struct sockaddr_in *)addr)->sin_port;
    } else {
        addrp = &((struct sockaddr_in6 *)addr)->sin6_addr;
        port = ((struct sockaddr_in6 *)addr)->sin6_port;
    }
    snprintf(buf, sizeof(buf), "%s:%d", sb_util_human_addr(addr->sa_family, addrp), ntohs(port));

    return buf;
}

const char * sb_util_strerror(int errnum) {
    static char buf[256];

    snprintf(buf, sizeof(buf), "%d: %s", errnum, strerror(errnum));

    return buf;
}

int sb_util_random(char * data, unsigned int len) {
    static int urfd = -1;
    int fail = 0;
    
    if (urfd < 0) {
        urfd = open("/dev/urandom", O_RDONLY);
        if (urfd < 0) {
            log_error("failed to open /dev/urandom %s", sb_util_strerror(errno));
            return -1;
        }
    }

    char *p = data;
    int ret;
    while(len > 0) {
        ret = read(urfd, p, len);
        if (ret < 0) {
            log_error("failed to read /dev/urandom %s", sb_util_strerror(errno));
            fail = 1;
            break;
        } else if (ret == 0) {
            log_error("read EOF from /dev/urandom, WTF");
            fail = 1;
            break;
        }
        len -= ret;
        p += ret;
    }
    if (urfd >= 0) {
        close(urfd);
        urfd = -1;
    }

    return fail ? -1 : 0;
}

void sb_util_set_timeout(struct event * ev, unsigned int timeout) {
    if (!ev) {
        log_error("ev is null");
        return;
    }
    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = timeout;
    event_add(ev, &tv);
}

void sb_util_clear_timeout(struct event * ev) {
    event_del(ev);
}
