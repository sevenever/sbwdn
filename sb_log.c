#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "sb_log.h"

struct SB_LOGGER sb_logger;

static const char *lvl[] = {
  "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

void log_set_fp(FILE *fp) {
  sb_logger.fp = fp;
}


void log_set_lvl(int lvl) {
  sb_logger.lvl = lvl;
}

void log_set_quiet(int enable) {
  sb_logger.quiet = enable ? 1 : 0;
}

void log_log(int l, const char *file, int line, const char *fmt, ...) {
  /* Get current time */
  time_t t = time(NULL);
  struct tm *lt = localtime(&t);

  /* Log to stderr */
  if (!sb_logger.quiet) {
    va_list args;
    char buf[16];
    buf[strftime(buf, sizeof(buf), "%H:%M:%S", lt)] = '\0';
    fprintf(stderr, "%s %-5s %s:%d: ", buf, lvl[l], file, line);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
  }

  /* Log to file */
  if (sb_logger.fp) {
    va_list args;
    char buf[32];
    buf[strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", lt)] = '\0';
    fprintf(sb_logger.fp, "%s %-5s %s:%d: ", buf, lvl[l], file, line);
    va_start(args, fmt);
    vfprintf(sb_logger.fp, fmt, args);
    va_end(args);
    fprintf(sb_logger.fp, "\n");
  }
}
