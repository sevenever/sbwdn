#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "log.h"
#include "sb_config.h"
#include "sbwdn.h"

int sb_config_read(struct sb_app * app, const char * config_file) {
    cfg_opt_t opts[] =
    {
        CFG_STR("mode", "", CFGF_NONE),
        CFG_STR("bind", "", CFGF_NONE),
        CFG_STR("remote", "", CFGF_NONE),
        CFG_INT("port", 812, CFGF_NONE),
        CFG_STR("addr", "", CFGF_NONE),
        CFG_STR("paddr", "", CFGF_NONE),
        CFG_STR("mask", "", CFGF_NONE),
        CFG_INT("mtu", 1500, CFGF_NONE),
        CFG_END()

    };
    cfg_t *cfg;

    cfg = cfg_init(opts, CFGF_NONE);
    switch (cfg_parse(cfg, config_file)) {
        case CFG_FILE_ERROR:
            log_fatal("warning: configuration file [%s] could not be read: %s\n", config_file, strerror(errno));
            return -1;
        case CFG_SUCCESS:
            break;
        case CFG_PARSE_ERROR:
            return -1;

    }

    const char * app_mode_str = cfg_getstr(cfg, "mode");
    if (strcmp(app_mode_str, "server") == 0) {
        app->config.app_mode = SERVER;
    } else if (strcmp(app_mode_str, "client") == 0) {
        app->config.app_mode = CLIENT;
    } else if (strlen(app_mode_str) == 0) {
        log_fatal("mode is required");
        return -1;
    } else {
        log_fatal("invalide app_mode[%s] in config file", app_mode_str);
        return -1;
    }
    log_info("running in %s mode", app_mode_str);

    if (app->config.app_mode == SERVER) {
        app->config.bind = cfg_getstr(cfg, "bind");
        if (strlen(app->config.bind) == 0) {
            log_fatal("bind is required if in server mode");
            return -1;
        }
    } else {
        app->config.remote = cfg_getstr(cfg, "remote");
        if (strlen(app->config.remote) == 0) {
            log_fatal("remote is required if in client mode");
            return -1;
        }
    }

    app->config.port = cfg_getint(cfg, "port");

    app->config.addr = cfg_getstr(cfg, "addr");
    if (strlen(app->config.addr) == 0) {
        log_fatal("addr is required");
        return -1;
    }

    app->config.paddr = cfg_getstr(cfg, "paddr");
    if (strlen(app->config.paddr) == 0) {
        log_fatal("paddr is required");
        return -1;
    }

    app->config.mask = cfg_getstr(cfg, "mask");
    if (strlen(app->config.mask) == 0) {
        log_fatal("mask is required");
        return -1;
    }

    app->config.mtu = cfg_getint(cfg, "mtu");
    if (app->config.cfg) {
        cfg_free(app->config.cfg);
    }
    app->config.cfg = cfg;

    return 0;
}

const char * sb_config_get_str(struct sb_config * config, const char * name) {
    return cfg_getstr(config->cfg, name);
}
int sb_config_get_int(struct sb_config * config, const char * name) {
    return cfg_getint(config->cfg, name);
}
