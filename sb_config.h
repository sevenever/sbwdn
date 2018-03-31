#ifndef _SB_CONFIG_H_
#define _SB_CONFIG_H_

#include "sb_log.h"
#include "sbwdn.h"

#define SB_CONFIG_STR_MAX 256

enum SB_APP_MODE { SERVER, CLIENT };

#define SB_NET_MODE_TCP 0x01
#define SB_NET_MODE_UDP 0x02

struct sb_config {
    /* client or server */
    enum SB_APP_MODE app_mode;
    unsigned int net_mode;
    struct in_addr bind;
    char remote[SB_CONFIG_STR_MAX];
    unsigned short port;
    struct in_addr addr;
    struct in_addr paddr;
    struct in_addr mask;
    unsigned int mtu;
    enum sb_log_lvl log;
};

struct sb_app;
struct sb_config * sb_config_read(const char * config_file);
void sb_config_apply(struct sb_app * app, struct sb_config * config);
#endif
