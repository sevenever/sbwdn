#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#if defined(__linux__)
#include <linux/if_tun.h>
#elif defined(__APPLE__)
#include <net/if.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <arpa/inet.h>

#include "sb_util.h"
#include "sb_log.h"
#include "sb_tun.h"
#include "sbwdn.h"

int sb_setup_tun(struct sb_app * app) {
    int fd;
    struct ifreq ifr;

#ifdef __linux__
    char *clonedev = "/dev/net/tun";
    if( (fd = open(clonedev, O_RDWR)) < 0 ) {
        log_error("failed to open tun clone device %s: %s", clonedev, sb_util_strerror(errno));
        return fd;
    }
    memset(&ifr, 0, sizeof(ifr));

    if (*app->tunname != 0) {
        strncpy(ifr.ifr_name, app->tunname, sizeof(ifr.ifr_name));
    }
    ifr.ifr_flags = IFF_TUN;

    /* try to create the device */
    if( (ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
        log_error("failed to create the tun device: %s.%s", sb_util_strerror(errno), (errno == EPERM ? " Are you root?" : ""));
        close(fd);
        return -1;
    }
    log_info("created tun device %s", ifr.ifr_name);

#elif defined (__APPLE__)
    #define TUN_MAX 16
    char tun_dev[PATH_MAX];
    int tun_id;
    for (tun_id = 0; tun_id < TUN_MAX; tun_id++) {
        snprintf(tun_dev, sizeof(tun_dev), "/dev/tun%d", tun_id);
        log_info("trying to open %s", tun_dev);
        if( (fd = open(tun_dev, O_RDWR)) < 0 ) {
            log_error("failed to open tun clone device %s: %s", tun_dev, sb_util_strerror(errno));
        } else {
            log_info("opened tun device %s", tun_dev);
            break;
        }
    }
    if (fd < 0) {
        return -1;
    }
    /* need to set ifr_name on macos */
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "tun%d", tun_id);
    log_info("openned tun device tun%d", tun_id);
#endif
    strncpy(app->tunname, ifr.ifr_name, sizeof(app->tunname));

    return fd;
}

int sb_config_tun_addr(const char * tunname, const struct in_addr * addr, const struct in_addr * mask, int mtu) {
    char addrstr[INET_ADDRSTRLEN];
    struct ifreq ifr;
    int s, ret, fail = 0;

    do {
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
            log_error("failed to create socket %s", sb_util_strerror(errno));
            fail = 1;
            break;
        }
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, tunname, sizeof(ifr.ifr_name));

        inet_ntop(AF_INET, addr, addrstr, sizeof(addrstr));
        log_info("setting address for tun to %s", addrstr);
        ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr = *addr;
        ret = ioctl(s, SIOCSIFADDR, &ifr);
        if (ret < 0) {
            log_error("failed to set address for tun interface %s: %s", ifr.ifr_name, sb_util_strerror(errno));
            fail = 1;
            break;
        }
        log_info("set address for tun to %s", addrstr);

        inet_ntop(AF_INET, mask, addrstr, sizeof(addrstr));
        log_info("setting mask for tun to %s", addrstr);
        ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr = *mask;
        ret = ioctl(s, SIOCSIFNETMASK, &ifr);
        if (ret < 0) {
            log_error("failed to set net mask for tun interface %s: %s", ifr.ifr_name, sb_util_strerror(errno));
            fail = 1;
            break;
        }
        log_info("set mask for tun to %s", addrstr);

        log_info("bring tun up");
        ret = ioctl(s, SIOCGIFFLAGS, &ifr);
        if (ret < 0) {
            log_error("failed to get flags for tun interface %s: %s", ifr.ifr_name, sb_util_strerror(errno));
            fail = 1;
            break;
        }
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        ret = ioctl(s, SIOCSIFFLAGS, &ifr);
        if (ret < 0) {
            log_error("failed bring up tun interface %s: %s", ifr.ifr_name, sb_util_strerror(errno));
            fail = 1;
            break;
        }
        log_info("brought tun up");

        log_info("setting mtu for tun to %d", mtu);
        ifr.ifr_mtu = mtu;
        ret = ioctl(s, SIOCSIFMTU, &ifr);
        if (ret < 0) {
            log_error("failed set mtu to %d for tun interface %s: %s", mtu, ifr.ifr_name, sb_util_strerror(errno));
            fail = 1;
            break;
        }
        log_info("set mtu for tun to %d", mtu);
    } while(0);

    close(s);

    return fail ? -1 : 0;
}

