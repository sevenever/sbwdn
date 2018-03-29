#ifndef _SBWDN_TUN_H_
#define _SBWDN_TUN_H_
#include <limits.h>

#define TUN_DEV_NAME "sbwdn"

struct sb_tun_dev {
    char dev_name[PATH_MAX];

    int tun_fd;
};
int setup_tun(const struct in_addr * addr, const struct in_addr * paddr, const struct in_addr * mask, int mtu);
#endif
