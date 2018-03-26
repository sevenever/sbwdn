#ifndef _SBWDN_TUN_H_
#define _SBWDN_TUN_H_
#include <limits.h>


struct sb_tun_dev {
    char dev_name[PATH_MAX];

    int tun_fd;
};
int setup_tun(const char * addr, const char * paddr, const char * mask, int mtu);
#endif
