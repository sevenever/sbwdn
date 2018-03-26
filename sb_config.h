#ifndef _SB_CONFIG_H_
#define _SB_CONFIG_H_

#include <confuse.h>

enum SB_APP_MODE { SERVER, CLIENT };

struct sb_config {
    cfg_t *cfg;

    /* client or server */
    enum SB_APP_MODE app_mode;
    char * bind;
    char * remote;
    unsigned short port;
    char * addr;
    char * paddr;
    char * mask;
    unsigned int mtu;
};

struct sb_app;
int sb_config_read(struct sb_app * app, const char * config_file);
#endif
