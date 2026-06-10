#include "logger.h"

#include <stdio.h>

// 统一日志输出格式：[LEVEL] message。
static void log_with_level(const char *level, const char *fmt, va_list args) {
    fprintf(stderr, "[%s] ", level);
    vfprintf(stderr, fmt, args);
    fputc('\n', stderr);
}

// log_info 输出普通运行信息。
void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_with_level("INFO", fmt, args);
    va_end(args);
}

// log_warn 输出可恢复的问题或异常输入。
void log_warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_with_level("WARN", fmt, args);
    va_end(args);
}

// log_error 输出导致当前操作失败的错误。
void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_with_level("ERROR", fmt, args);
    va_end(args);
}
