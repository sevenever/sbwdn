#ifndef _SB_CONFIG_H_
#define _SB_CONFIG_H_

#include "sb_log.h"
#include "sbwdn.h"

#define SB_CONFIG_STR_MAX 256

enum SB_APP_MODE { SERVER, CLIENT };

struct sb_config {
    /* client or server */
    enum SB_APP_MODE app_mode;
    char bind[SB_CONFIG_STR_MAX];
    char remote[SB_CONFIG_STR_MAX];
    unsigned short port;
    char addr[SB_CONFIG_STR_MAX];
    char paddr[SB_CONFIG_STR_MAX];
    char mask[SB_CONFIG_STR_MAX];
    unsigned int mtu;
    enum sb_log_lvl log;
};

struct sb_app;
struct sb_config * sb_config_read(const char * config_file);
void sb_config_apply(struct sb_app * app, struct sb_config * config);
#endif
