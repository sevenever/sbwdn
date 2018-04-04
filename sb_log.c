#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <syslog.h>

#include "sb_log.h"

struct SB_LOGGER sb_logger;

static const char *lvl[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

void log_init(struct SB_LOGGER * logger) {
    logger->fp = 0;
    logger->lvl = SB_LOG_INFO;
    logger->quiet = 0;
}
void log_set_fp(FILE *fp) {
    sb_logger.fp = fp;
}


void log_set_lvl(int lvl) {
    sb_logger.lvl = lvl;
}

void log_set_quiet(int enable) {
    sb_logger.quiet = enable ? 1 : 0;
}

void log_log(int l, const char *file, int line, const char * func, const char *fmt, ...) {
    /* Log to stderr */
    va_list args;
    if (!sb_logger.quiet) {
        fprintf(stderr, "%-5s %s:%d:%s: ", lvl[l], file, line, func);
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
        fprintf(stderr, "\n");
    }

    /* Log to file */
    if (sb_logger.fp) {
        va_start(args, fmt);
        fprintf(sb_logger.fp, "%-5s %s:%d:%s: ", lvl[l], file, line, func);
        vfprintf(sb_logger.fp, fmt, args);
        fprintf(sb_logger.fp, "\n");
        va_end(args);
    } else {
        int prio;
        switch (l) {
            case SB_LOG_TRACE:
            case SB_LOG_DEBUG:
                prio = LOG_DEBUG;
                break;
            case SB_LOG_INFO:
                prio = LOG_INFO;
                break;
            case SB_LOG_WARN:
                prio = LOG_WARNING;
                break;
            case SB_LOG_ERROR:
                prio = LOG_ERR;
                break;
            case SB_LOG_FATAL:
                prio = LOG_EMERG;
                break;
            default:
                prio = LOG_ERR;
                break;
        }

        va_start(args, fmt);
        static char fmtbuf[SB_SYSLOG_MAX];
        static char logbuf[SB_SYSLOG_MAX];
        snprintf(fmtbuf, sizeof(fmtbuf), "%-5s %s:%d:%s: %s", lvl[l], file, line, func, fmt);
        vsnprintf(logbuf, sizeof(logbuf), fmtbuf, args);
        syslog(prio, "%s", logbuf);
        va_end(args);
    }
}
