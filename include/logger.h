#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>

// 输出 INFO 级别日志到 stderr。
void log_info(const char *fmt, ...);

// 输出 WARN 级别日志到 stderr。
void log_warn(const char *fmt, ...);

// 输出 ERROR 级别日志到 stderr。
void log_error(const char *fmt, ...);

#endif
