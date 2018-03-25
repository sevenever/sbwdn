#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
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
#include "log.h"

int setup_tun(const char * addr, const char * mask, int mtu) {
    struct ifreq ifr;
    int fd, ret;
    char *clonedev = "/dev/net/tun";

    if( (fd = open(clonedev, O_RDWR)) < 0 ) {
        log_error("failed to open tun clone device %s: %d %s", clonedev, errno, strerror(errno));
        return fd;
    }
    memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN;
   strncpy(ifr.ifr_name, "sbwdn", IFNAMSIZ);

   /* try to create the device */
   if( (ret = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
       log_error("failed to create the tun device: %d %s.%s", errno, strerror(errno), (errno == EPERM ? " Are you root?" : ""));
        if (errno == EPERM) {
            log_error("Are you root?");
        }
       close(fd);
       return ret;
   }
   log_info("created tun device %s", ifr.ifr_name);

   int s = socket(AF_INET, SOCK_DGRAM, 0);
   ifr.ifr_addr.sa_family = AF_INET;
   inet_pton(AF_INET, addr, &((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
   ret = ioctl(s, SIOCSIFADDR, &ifr);
   if (ret < 0) {
       log_error("failed to set ip address for tun interface %s: %d %s", ifr.ifr_name, errno, strerror(errno));
       return -1;
   }

   inet_pton(AF_INET, mask, &((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
   ret = ioctl(s, SIOCSIFNETMASK, &ifr);
   if (ret < 0) {
       log_error("failed to set net mask for tun interface %s: %d %s", ifr.ifr_name, errno, strerror(errno));
       return -1;
   }
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
   ifr.ifr_mtu = mtu;
   ret = ioctl(s, SIOCSIFMTU, &ifr);
   if (ret < 0) {
       log_error("failed set mtu to %d for tun interface %s: %d %s", mtu, ifr.ifr_name, errno, strerror(errno));
       return -1;
   }

   return fd;
}

