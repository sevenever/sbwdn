#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#include <confuse.h>

#include "sb_log.h"
#include "sb_util.h"
#include "sb_config.h"

#define SB_DEFAULT_NET_MODE "udp"
#define SB_DEFAULT_NET_PORT 812
#define SB_DEFAULT_NET_MTU  1400
#define SB_DEFAULT_LOG_LEVEL  "info"

struct sb_config * sb_config_read(const char * config_file) {
    int failed = 0;
    struct sb_config * config = 0;
    cfg_t *cfg = 0;

    do {
        config = (struct sb_config *)malloc(sizeof(struct sb_config));
        if (!config) {
            log_error("failed to allocate memory for sb_config: %s", sb_util_strerror(errno));
            failed = 1;
            break;
        }

        memset(config, 0, sizeof(struct sb_config));

        cfg_opt_t opts[] =
        {
            CFG_STR("mode", "", CFGF_NONE),
            CFG_STR("dev", "", CFGF_NONE),
            CFG_STR("net", SB_DEFAULT_NET_MODE, CFGF_NONE),
            CFG_STR("bind", "", CFGF_NONE),
            CFG_STR("remote", "", CFGF_NONE),
            CFG_INT("port", SB_DEFAULT_NET_PORT, CFGF_NONE),
            CFG_STR("addr", "", CFGF_NONE),
            CFG_STR("mask", "", CFGF_NONE),
            CFG_INT("mtu", SB_DEFAULT_NET_MTU, CFGF_NONE),
            CFG_STR("log", SB_DEFAULT_LOG_LEVEL, CFGF_NONE),
            CFG_END()

        };

        cfg = cfg_init(opts, CFGF_NONE);
        int parse_ret = cfg_parse(cfg, config_file);
        if (parse_ret == CFG_FILE_ERROR) {
            log_fatal("warning: configuration file [%s] could not be read: %s\n", config_file, sb_util_strerror(errno));
            failed = 1;
            break;
        } else if (parse_ret == CFG_PARSE_ERROR) {
            failed = 1;
            break;
        }

        const char * app_mode_str = cfg_getstr(cfg, "mode");
        if (strcmp(app_mode_str, "server") == 0) {
            config->app_mode = SERVER;
        } else if (strcmp(app_mode_str, "client") == 0) {
            config->app_mode = CLIENT;
        } else if (strlen(app_mode_str) == 0) {
            log_fatal("mode is required");
            failed = 1;
            break;
        } else {
            log_fatal("invalide app_mode[%s] in config file", app_mode_str);
            failed = 1;
            break;
        }
        log_info("app mode %s mode", app_mode_str);

        strncpy(config->dev, cfg_getstr(cfg, "dev"), sizeof(config->dev));
        log_info("device name in config file: [%s]", config->dev);

        const char * app_net_str = cfg_getstr(cfg, "net");
        if (strcmp(app_net_str, "tcp") == 0) {
            config->net_mode = SB_NET_MODE_TCP;
        } else if (strcmp(app_net_str, "udp") == 0) {
            config->net_mode = SB_NET_MODE_UDP;
        } else if (strcmp(app_net_str, "both") == 0) {
            config->net_mode = SB_NET_MODE_TCP | SB_NET_MODE_UDP;
            if (config->app_mode == CLIENT) {
                log_error("client net mode can only be either tcp or udp, not both");
                failed = 1;
                break;
            }
        } else if (strlen(app_net_str) == 0) {
            log_fatal("net is required");
            failed = 1;
            break;
        } else {
            log_fatal("invalide net [%s] in config file", app_net_str);
            failed = 1;
            break;
        }
        log_info("network mode %s", app_net_str);

        if (config->app_mode == SERVER) {
            const char * bind_str = cfg_getstr(cfg, "bind");
            if (strlen(bind_str) == 0) {
                log_fatal("bind is required if in server mode");
                failed = 1;
                break;
            }
            if (inet_pton(AF_INET, bind_str, &config->bind) <= 0) {
                log_fatal("failed to parse bind address %s", bind_str);
                failed = 1;
                break;
            }
            log_info("bind address is %s", bind_str);

            const char * addr_str = cfg_getstr(cfg, "addr");
            if (strlen(addr_str) == 0) {
                log_fatal("addr is required");
                failed = 1;
                break;
            } else if (inet_pton(AF_INET, addr_str, &config->addr) <= 0) {
                log_fatal("failed to parse addr address %s", addr_str);
                failed = 1;
                break;
            }
            log_info("local address is %s", addr_str);

            const char * mask_str = cfg_getstr(cfg, "mask");
            if (strlen(mask_str) == 0) {
                log_fatal("mask is required");
                failed = 1;
                break;
            } else if (inet_pton(AF_INET, mask_str, &config->mask) <= 0) {
                log_fatal("failed to parse mask %s", mask_str);
                failed = 1;
                break;
            }
            log_info("network mask is %s", mask_str);
        } else {
            strncpy(config->remote, cfg_getstr(cfg, "remote"), sizeof(config->remote));
            if (strlen(config->remote) == 0) {
                log_fatal("remote is required if in client mode");
                failed = 1;
                break;
            }
            log_info("remote address is %s", config->remote);
        }

        config->port = cfg_getint(cfg, "port");
        log_info("net port is %d", config->port);

        config->mtu = cfg_getint(cfg, "mtu");

        char * log_str = cfg_getstr(cfg, "log");
        if (strcmp(log_str, "trace") == 0) {
            config->log = LOG_TRACE;
        } else if (strcmp(log_str, "debug") == 0) {
            config->log = LOG_DEBUG;
        } else if (strcmp(log_str, "info") == 0) {
            config->log = LOG_INFO;
        } else if (strcmp(log_str, "warn") == 0) {
            config->log = LOG_WARN;
        } else if (strcmp(log_str, "error") == 0) {
            config->log = LOG_ERROR;
        } else if (strcmp(log_str, "fatal") == 0) {
            config->log = LOG_FATAL;
        } else if (strcmp(log_str, "all") == 0) {
            config->log = LOG_FATAL;
        } else {
            log_warn("unkown log level %s, will default to info", log_str);
            config->log = LOG_INFO;
        }
    } while(0);

    cfg_free(cfg);

    if (failed) {
        if (config) {
            free(config);
            config = 0;
        }
        return 0;
    } else {
        return config;
    }
}
void sb_config_apply(struct sb_app * app, struct sb_config * config) {
    if (app->config) {
        free(app->config);
    }
    app->config = config;

    log_set_lvl(config->log);
}

