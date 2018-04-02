#ifndef _SB_CONFIG_H_
#define _SB_CONFIG_H_

#include <sys/types.h>
#include <limits.h>

#include "sb_log.h"
#include "sbwdn.h"

#define SB_CONFIG_STR_MAX 256

#define SB_RT_MAX 1024

enum SB_APP_MODE { SB_SERVER, SB_CLIENT };

#define SB_DEFAULT_NET_MODE "udp"
#define SB_DEFAULT_NET_PORT 812
#define SB_DEFAULT_NET_MTU 1400
#define SB_DEFAULT_LOG_LEVEL "info"
#define SB_DEFAULT_LOG_PATH "/var/log/sbwdn.log"

struct sb_rt {
    struct in_addr dst;
    struct in_addr mask;
};

struct sb_config {
    /* client or server */
    enum SB_APP_MODE app_mode;
    char dev[SB_CONFIG_STR_MAX];
    unsigned int net_mode;
    struct in_addr bind;
    char remote[SB_CONFIG_STR_MAX];
    unsigned short port;
    struct in_addr addr;
    struct in_addr paddr;
    struct in_addr mask;
    unsigned int mtu;
    enum sb_log_lvl log;
    char logfile[PATH_MAX];
    char routefile[PATH_MAX];

    unsigned int rt_cnt;
    struct sb_rt rt[SB_RT_MAX];
};

struct sb_app;
struct sb_config * sb_config_read(const char * config_file);
/*
 * apply config
 * return 0 if succeed
 * return -1 otherwise
 */
int sb_config_apply(struct sb_app * app, struct sb_config * config);

int sb_parse_rt_file(struct sb_config * config);
#endif
