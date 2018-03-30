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

void log_log(int l, const char *file, int line, const char * func, const char *fmt, ...) {
  /* Log to stderr */
  if (!sb_logger.quiet) {
    va_list args;
    fprintf(stderr, "%-5s %s:%d:%s: ", lvl[l], file, line, func);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
  }

  /* Log to file */
  if (sb_logger.fp) {
    va_list args;
    fprintf(sb_logger.fp, "%-5s %s:%d:%s: ", lvl[l], file, line, func);
    va_start(args, fmt);
    vfprintf(sb_logger.fp, fmt, args);
    va_end(args);
    fprintf(sb_logger.fp, "\n");
  }
}
