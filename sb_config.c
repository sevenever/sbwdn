#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#include <confuse.h>

#include "sb_log.h"
#include "sb_config.h"

struct sb_config * sb_config_read(const char * config_file) {
    struct sb_config * config = (struct sb_config *)malloc(sizeof(struct sb_config));
    if (!config) {
        log_error("failed to allocate memory for sb_config: %d %s", errno, strerror(errno));
        return 0;
    }

    memset(config, 0, sizeof(struct sb_config));

    cfg_opt_t opts[] =
    {
        CFG_STR("mode", "", CFGF_NONE),
        CFG_STR("net", "udp", CFGF_NONE),
        CFG_STR("bind", "", CFGF_NONE),
        CFG_STR("remote", "", CFGF_NONE),
        CFG_INT("port", 812, CFGF_NONE),
        CFG_STR("addr", "", CFGF_NONE),
        CFG_STR("paddr", "", CFGF_NONE),
        CFG_STR("mask", "", CFGF_NONE),
        CFG_INT("mtu", 1500, CFGF_NONE),
        CFG_STR("log", "info", CFGF_NONE),
        CFG_END()

    };
    cfg_t *cfg;

    cfg = cfg_init(opts, CFGF_NONE);
    switch (cfg_parse(cfg, config_file)) {
        case CFG_FILE_ERROR:
            log_fatal("warning: configuration file [%s] could not be read: %s\n", config_file, strerror(errno));
            return 0;
        case CFG_SUCCESS:
            break;
        case CFG_PARSE_ERROR:
            return 0;

    }

    const char * app_mode_str = cfg_getstr(cfg, "mode");
    if (strcmp(app_mode_str, "server") == 0) {
        config->app_mode = SERVER;
    } else if (strcmp(app_mode_str, "client") == 0) {
        config->app_mode = CLIENT;
    } else if (strlen(app_mode_str) == 0) {
        log_fatal("mode is required");
        return 0;
    } else {
        log_fatal("invalide app_mode[%s] in config file", app_mode_str);
        return 0;
    }
    log_info("app mode %s mode", app_mode_str);

    const char * app_net_str = cfg_getstr(cfg, "net");
    if (strcmp(app_net_str, "tcp") == 0) {
        config->net_mode = SB_NET_MODE_TCP;
    } else if (strcmp(app_net_str, "udp") == 0) {
        config->net_mode = SB_NET_MODE_UDP;
    } else if (strcmp(app_net_str, "both") == 0) {
        config->net_mode = SB_NET_MODE_TCP | SB_NET_MODE_UDP;
        if (config->app_mode == CLIENT) {
            log_error("client net mode can only be either tcp or udp, not both");
            return 0;
        }
    } else if (strlen(app_net_str) == 0) {
        log_fatal("net is required");
        return 0;
    } else {
        log_fatal("invalide net [%s] in config file", app_net_str);
        return 0;
    }
    log_info("network mode %s", app_net_str);

    if (config->app_mode == SERVER) {
        const char * bind_str = cfg_getstr(cfg, "bind");
        if (strlen(bind_str) == 0) {
            log_fatal("bind is required if in server mode");
            return 0;
        }
        if (inet_pton(AF_INET, bind_str, &config->bind) <= 0) {
            log_fatal("failed to parse bind address %s", bind_str);
            return 0;
        }
        log_info("bind address is %s", bind_str);
    } else {
        strncpy(config->remote, cfg_getstr(cfg, "remote"), sizeof(config->remote));
        if (strlen(config->remote) == 0) {
            log_fatal("remote is required if in client mode");
            return 0;
        }
        log_info("remote address is %s", config->remote);
    }

    config->port = cfg_getint(cfg, "port");
    log_info("bind port is %d", config->port);

    const char * addr_str = cfg_getstr(cfg, "addr");
    if (strlen(addr_str) == 0) {
        log_fatal("addr is required");
        return 0;
    } else if (inet_pton(AF_INET, addr_str, &config->addr) <= 0) {
        log_fatal("failed to parse addr address %s", addr_str);
        return 0;
    }
    log_info("local address is %s", addr_str);

    const char * paddr_str = cfg_getstr(cfg, "paddr");
    if (strlen(paddr_str) == 0) {
        log_fatal("paddr is required");
        return 0;
    } else if (inet_pton(AF_INET, paddr_str, &config->paddr) <= 0) {
        log_fatal("failed to parse paddr address %s", paddr_str);
        return 0;
    }
    log_info("peer address is %s", paddr_str);

    const char * mask_str = cfg_getstr(cfg, "mask");
    if (strlen(mask_str) == 0) {
        log_fatal("mask is required");
        return 0;
    } else if (inet_pton(AF_INET, mask_str, &config->mask) <= 0) {
        log_fatal("failed to parse mask %s", mask_str);
        return 0;
    }
    log_info("network mask is %s", mask_str);

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

    cfg_free(cfg);

    return config;
}
void sb_config_apply(struct sb_app * app, struct sb_config * config) {
    if (app->config) {
        free(app->config);
    }
    app->config = config;

    log_set_lvl(config->log);
}

