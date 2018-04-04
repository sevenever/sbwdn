#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <pwd.h>

#include <confuse.h>

#include "sb_log.h"
#include "sb_util.h"
#include "sb_config.h"

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
            CFG_STR("logfile", SB_DEFAULT_LOG_PATH, CFGF_NONE),
            CFG_STR("routefile", "", CFGF_NONE),
            CFG_STR("pidfile", SB_DEFAULT_PID_FILE, CFGF_NONE),
            CFG_END()

        };

        log_debug("reading config file: %s", config_file);
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
            config->app_mode = SB_SERVER;
        } else if (strcmp(app_mode_str, "client") == 0) {
            config->app_mode = SB_CLIENT;
        } else if (strlen(app_mode_str) == 0) {
            log_fatal("mode is required");
            failed = 1;
            break;
        } else {
            log_fatal("invalide app_mode[%s] in config file", app_mode_str);
            failed = 1;
            break;
        }
        log_debug("app mode is set to %s mode", app_mode_str);

        strncpy(config->dev, cfg_getstr(cfg, "dev"), sizeof(config->dev));
        log_debug("device name in config file: [%s]", config->dev);

        const char * app_net_str = cfg_getstr(cfg, "net");
        if (strcmp(app_net_str, "tcp") == 0) {
            config->net_mode = SB_NET_MODE_TCP;
        } else if (strcmp(app_net_str, "udp") == 0) {
            config->net_mode = SB_NET_MODE_UDP;
        } else if (strcmp(app_net_str, "both") == 0) {
            config->net_mode = SB_NET_MODE_TCP | SB_NET_MODE_UDP;
            if (config->app_mode == SB_CLIENT) {
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
        log_debug("network mode is set to %s", app_net_str);

        if (config->app_mode == SB_SERVER) {
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
            log_debug("bind address is set to %s", bind_str);

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
            log_debug("local address is set to %s", addr_str);

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
            log_debug("network mask is set to %s", mask_str);
        } else {
            strncpy(config->remote, cfg_getstr(cfg, "remote"), sizeof(config->remote));
            if (strlen(config->remote) == 0) {
                log_fatal("remote is required if in client mode");
                failed = 1;
                break;
            }
            log_debug("remote address is set to %s", config->remote);
        }

        config->port = cfg_getint(cfg, "port");
        log_debug("net port is set to %d", config->port);

        config->mtu = cfg_getint(cfg, "mtu");
        log_debug("net mtu is set to %d", config->mtu);

        char * log_str = cfg_getstr(cfg, "log");
        if (strcmp(log_str, "trace") == 0) {
            config->log = SB_LOG_TRACE;
        } else if (strcmp(log_str, "debug") == 0) {
            config->log = SB_LOG_DEBUG;
        } else if (strcmp(log_str, "info") == 0) {
            config->log = SB_LOG_INFO;
        } else if (strcmp(log_str, "warn") == 0) {
            config->log = SB_LOG_WARN;
        } else if (strcmp(log_str, "error") == 0) {
            config->log = SB_LOG_ERROR;
        } else if (strcmp(log_str, "fatal") == 0) {
            config->log = SB_LOG_FATAL;
        } else if (strcmp(log_str, "all") == 0) {
            config->log = SB_LOG_FATAL;
        } else {
            log_warn("unkown log level %s, will default to info", log_str);
            config->log = SB_LOG_INFO;
        }
        log_debug("log level is set to %s", config->log == SB_LOG_INFO ? "info" : log_str);

        strncpy(config->logfile, cfg_getstr(cfg, "logfile"), sizeof(config->logfile));
        log_debug("log file is set to [%s]", config->logfile);

        strncpy(config->routefile, cfg_getstr(cfg, "routefile"), sizeof(config->routefile));
        log_debug("route file is set to [%s]", config->routefile);

        /* if any error just ignore */
        if (config->app_mode == SB_SERVER && strlen(config->routefile) != 0) {
            sb_parse_rt_file(config);
        }

        strncpy(config->pidfile, cfg_getstr(cfg, "pidfile"), sizeof(config->pidfile));
        log_debug("pid file is set to [%s]", config->pidfile);

    } while(0);

    if (cfg) {
        cfg_free(cfg);
    }

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

int sb_config_apply(struct sb_app * app, struct sb_config * config) {
    if (app->config) {
        free(app->config);
        app->config = 0;
    }
    app->config = config;

    log_set_lvl(config->log);

    log_debug("openning log file %s", config->logfile);
    FILE * newfp = fopen(config->logfile, "ae");
    if (!newfp) {
        log_fatal("failed to open log file %s", config->logfile);
        return -1;
    }
    if (setvbuf(newfp, 0, _IONBF, 0) != 0) {
        log_error("failed to set log file as unbuffered %s", config->logfile);
        return -1;
    }
    if (sb_logger.fp && fileno(sb_logger.fp) != fileno(newfp)) {
        log_info("log will go to %s, see you there", config->logfile);
        fclose(sb_logger.fp);
        sb_logger.fp = 0;
    }
    sb_logger.fp = newfp;

    return 0;
}

int sb_parse_rt_file(struct sb_config * config) {
    FILE * f = fopen(config->routefile, "r");
    if (!f) {
        log_error("failed to open route file %s", config->routefile, sb_util_strerror(errno));
        return -1;
    }

    int i = 0;
    char * line, * space, * dst, * mask;
    size_t len;
    ssize_t read;
    struct sb_rt rt;
    while ((read = getline(&line, &len, f)) != -1 && i < SB_RT_MAX) {
        if (read <= 1) {
            /* empty line */
            continue;
        }
        line[read-1] = 0;
        space = strstr(line, " ");
        if (!space) {
            log_error("invalid route config %s", line);
            continue;
        }
        dst = line;
        *space = 0;
        mask = space + 1;

        if (inet_pton(AF_INET, dst, &rt.dst) != 1 || inet_pton(AF_INET, mask, &rt.mask) != 1) {
            log_error("invalid route config %s", line);
        } else {
            config->rt[i++] = rt;
        }
    }
    config->rt_cnt = i;
    log_debug("total route count: %d", config->rt_cnt);

    fclose(f);
    if (line) {
        free(line);
        line = 0;
    }

    return 0;
}
