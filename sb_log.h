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

extern struct SB_LOGGER{
  FILE *fp;
  int lvl;
  int quiet;
} sb_logger;

enum sb_log_lvl { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL };

#define log_trace(...) do { \
    if (sb_logger.lvl <= LOG_TRACE) { \
        log_log(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__); \
    } \
} while(0);
#define log_debug(...) do { \
    if (sb_logger.lvl <= LOG_DEBUG) { \
        log_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__); \
    } \
} while(0);
#define log_info(...) do { \
    if (sb_logger.lvl <= LOG_INFO) { \
        log_log(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__); \
    } \
} while(0);
#define log_warn(...) do { \
    if (sb_logger.lvl <= LOG_WARN) { \
        log_log(LOG_WARN, __FILE__, __LINE__, __VA_ARGS__); \
    } \
} while(0);
#define log_error(...) do { \
    if (sb_logger.lvl <= LOG_ERROR) { \
        log_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__); \
    } \
} while(0);
#define log_fatal(...) do { \
    if (sb_logger.lvl <= LOG_FATAL) { \
        log_log(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__); \
    } \
} while(0);

void log_set_fp(FILE *fp);
void log_set_lvl(int lvl);
void log_set_quiet(int enable);

void log_log(int lvl, const char *file, int line, const char *fmt, ...);

#endif
