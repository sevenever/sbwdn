#include <sys/types.h>
#include <sys/socket.h>

#if defined(__linux__)
#include <linux/if.h>
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

#include "sb_tun.h"
#include "sb_log.h"

int setup_tun(const struct in_addr * addr, const struct in_addr * paddr, const struct in_addr * mask, int mtu) {
    int fd, ret;
    struct ifreq ifr;

#ifdef __linux__
    char *clonedev = "/dev/net/tun";
    if( (fd = open(clonedev, O_RDWR)) < 0 ) {
        log_error("failed to open tun clone device %s: %d %s", clonedev, errno, strerror(errno));
        return fd;
    }
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, TUN_DEV_NAME, sizeof(ifr.ifr_name));
    ifr.ifr_flags = IFF_TUN;

    /* try to create the device */
    if( (ret = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
        log_error("failed to create the tun device: %d %s.%s", errno, strerror(errno), (errno == EPERM ? " Are you root?" : ""));
        close(fd);
        return ret;
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
            log_error("failed to open tun clone device %s: %d %s", tun_dev, errno, strerror(errno));
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
#endif

#ifdef SB_USE_IPROUTE
    /* Using "ip" command to set ip of tun interface, I don't know why SIOCSIFADDR not work...
     * When using SIOCSIFADDR, the package is not routed to the tun interface...
     */
    char cmd[1024];

    log_info("bring up %s", ifr.ifr_name);
    snprintf(cmd, sizeof(cmd), "/sbin/ip link set dev %s up mtu %d", ifr.ifr_name, mtu);
    log_info("invoking %s", cmd);
    ret = system(cmd);
    if (ret != 0) {
        log_error("failed to set address for tun interface %s", ifr.ifr_name);
    }

    log_info("setting address for %s", ifr.ifr_name);
    snprintf(cmd, sizeof(cmd), "/sbin/ip addr add dev %s local %s peer %s", ifr.ifr_name, addr, paddr);
    log_info("invoking %s", cmd);
    ret = system(cmd);
    if (ret != 0) {
        log_error("failed to set address for tun interface %s", ifr.ifr_name);
    }
#else
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    log_info("setting address for tun to %s", addr);
    ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr = *addr;
    ret = ioctl(s, SIOCSIFADDR, &ifr);
    if (ret < 0) {
        log_error("failed to set address for tun interface %s: %d %s", ifr.ifr_name, errno, strerror(errno));
        return -1;
    }
    log_info("set address for tun to %s", addr);

    log_info("setting peer address for tun to %s", paddr);
    ifr.ifr_addr.sa_family = AF_INET;
    ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr = *paddr;
    ret = ioctl(s, SIOCSIFDSTADDR, &ifr);
    if (ret < 0) {
        log_error("failed to set peer address for tun interface %s: %d %s", ifr.ifr_name, errno, strerror(errno));
        return -1;
    }
    log_info("set peer address for tun to %s", paddr);

    log_info("setting mask for tun to %s", mask);
    ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr = *mask;
    ret = ioctl(s, SIOCSIFNETMASK, &ifr);
    if (ret < 0) {
        log_error("failed to set net mask for tun interface %s: %d %s", ifr.ifr_name, errno, strerror(errno));
        return -1;
    }
    log_info("set mask for tun to %s", mask);

    log_info("bring tun up");
    ret = ioctl(s, SIOCGIFFLAGS, &ifr);
    if (ret < 0) {
        log_error("failed to get flags for tun interface %s: %d %s", ifr.ifr_name, errno, strerror(errno));
        return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    ret = ioctl(s, SIOCSIFFLAGS, &ifr);
    if (ret < 0) {
        log_error("failed bring up tun interface %s: %d %s", ifr.ifr_name, errno, strerror(errno));
        return -1;
    }
    log_info("brought tun up");

    log_info("setting mtu for tun to %d", mtu);
    ifr.ifr_mtu = mtu;
    ret = ioctl(s, SIOCSIFMTU, &ifr);
    if (ret < 0) {
        log_error("failed set mtu to %d for tun interface %s: %d %s", mtu, ifr.ifr_name, errno, strerror(errno));
        return -1;
    }
    log_info("set mtu for tun to %d", mtu);
#endif

    return fd;
}

