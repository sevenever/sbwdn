#ifndef _SBWDN_TUN_H_
#define _SBWDN_TUN_H_
#include <limits.h>

#define SB_TUN_DEV_NAME "sbwdn"

struct sb_tun_dev {
    char dev_name[PATH_MAX];

    int tun_fd;
};

/* setup tun device.
 * if tunname is "", will allow system assign a device name
 * otherwise will use this name as device name
 * the device name will be copied into tunname in either case
 */
int sb_setup_tun(char * tunname, unsigned int len);

/* configure address, mask, mtu of device
 * return -1 if error
 * return 0 if no error
 */
int sb_config_tun_addr(const char * tunname, const struct in_addr * addr, const struct in_addr * mask, int mtu);
#endif
