/**
 * Copyright (c) 2017 rxi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See `log.c` for details.
 */

#ifndef SB_LOG_H
#define SB_LOG_H

#include <stdio.h>
#include <stdarg.h>

#define SB_SYSLOG_FMT_MAX 512

extern struct SB_LOGGER{
  FILE *fp;
  int lvl;
  int quiet;
} sb_logger;

enum sb_log_lvl { SB_LOG_TRACE, SB_LOG_DEBUG, SB_LOG_INFO, SB_LOG_WARN, SB_LOG_ERROR, SB_LOG_FATAL };

#define log_trace(...) do { \
    if (sb_logger.lvl <= SB_LOG_TRACE) { \
        log_log(SB_LOG_TRACE, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); \
    } \
} while(0);
#define log_debug(...) do { \
    if (sb_logger.lvl <= SB_LOG_DEBUG) { \
        log_log(SB_LOG_DEBUG, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); \
    } \
} while(0);
#define log_info(...) do { \
    if (sb_logger.lvl <= SB_LOG_INFO) { \
        log_log(SB_LOG_INFO, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); \
    } \
} while(0);
#define log_warn(...) do { \
    if (sb_logger.lvl <= SB_LOG_WARN) { \
        log_log(SB_LOG_WARN, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); \
    } \
} while(0);
#define log_error(...) do { \
    if (sb_logger.lvl <= SB_LOG_ERROR) { \
        log_log(SB_LOG_ERROR, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); \
    } \
} while(0);
#define log_fatal(...) do { \
    if (sb_logger.lvl <= SB_LOG_FATAL) { \
        log_log(SB_LOG_FATAL, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); \
    } \
} while(0);

#define log_enter_func(...) log_trace("entering %s", __FUNCTION__)
#define log_exit_func(...) log_trace("exiting %s", __FUNCTION__)

void log_init();
void log_set_fp(FILE *fp);
void log_set_lvl(int lvl);
void log_set_quiet(int enable);

void log_log(int lvl, const char *file, int line, const char * func, const char *fmt, ...);

#endif
