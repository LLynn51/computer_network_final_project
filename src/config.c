// 根据默认值和命令行参数写入全局配置参数
#include "config.h"

#include "logger.h"
#include "netutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 服务端默认监听 DNS UDP 端口。
#define DEFAULT_DNS_PORT 53

// 默认上游 DNS 服务器，通常是校园网/实验环境内的递归 DNS。
#define DEFAULT_UPSTREAM_DNS "192.168.1.1"

// 默认本地域名-IP 映射表路径。
#define DEFAULT_TABLE_FILE "data/dnsrelay.txt"

// 事件循环 select() 的默认唤醒间隔，单位毫秒。
#define DEFAULT_EVENT_LOOP_TIMEOUT_MS 1000

// 上游 DNS 请求 ID 映射的默认超时时间，单位毫秒。
#define DEFAULT_IDMAP_TIMEOUT_MS 5000

// 全局配置实例，启动时由默认值和命令行参数共同填充。
static Config g_config;

// 安全复制字符串，保证目标缓冲区总是以 '\0' 结尾。
static void copy_string(char *dst, int dst_size, const char *src) {
    if (dst == NULL || dst_size <= 0) {
        return;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    strncpy(dst, src, (size_t)dst_size - 1);
    dst[dst_size - 1] = '\0';
}

// 解析监听端口，端口必须位于 1..65535。
static int parse_port(const char *s, uint16_t *port) {
    long value;
    char *end = NULL;

    if (s == NULL || port == NULL) {
        return -1;
    }

    value = strtol(s, &end, 10);
    if (end == s || *end != '\0' || value <= 0 || value > 65535) {
        return -1;
    }

    *port = (uint16_t)value;
    return 0;
}

// 解析正整数毫秒参数，并限制到合理上界避免异常长等待。
static int parse_positive_int(const char *s, int *value) {
    long parsed;
    char *end = NULL;

    if (s == NULL || value == NULL) {
        return -1;
    }

    parsed = strtol(s, &end, 10);
    if (end == s || *end != '\0' || parsed <= 0 || parsed > 600000) {
        return -1;
    }

    *value = (int)parsed;
    return 0;
}

// 检查命令行字符串能完整放入配置缓冲区，避免被静默截断。
static int string_fits_config_buffer(const char *s, int max_size) {
    if (s == NULL || max_size <= 0) {
        return 0;
    }

    return strlen(s) < (size_t)max_size;
}

// 校验上游 DNS 是否为可用 IPv4/IPv6 字面量。
static int is_valid_ip_literal(const char *s) {
    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (s == NULL || *s == '\0') {
        return 0;
    }

    return inet_pton(AF_INET, s, &ipv4) == 1 ||
           inet_pton(AF_INET6, s, &ipv6) == 1;
}

// 检查本地域名表路径是否非空、未超长，并且当前进程可打开读取。
static int is_readable_table_file(const char *filename) {
    FILE *fp;

    if (filename == NULL || filename[0] == '\0') {
        return 0;
    }
    if (!string_fits_config_buffer(filename, CONFIG_PATH_MAX)) {
        return 0;
    }

    fp = fopen(filename, "r");
    if (fp == NULL) {
        return 0;
    }

    fclose(fp);
    return 1;
}

// config_init_defaults 写入所有默认配置项。
void config_init_defaults(void) {
    g_config.listen_port = DEFAULT_DNS_PORT;
    copy_string(g_config.upstream_dns, sizeof(g_config.upstream_dns), DEFAULT_UPSTREAM_DNS);
    copy_string(g_config.table_file, sizeof(g_config.table_file), DEFAULT_TABLE_FILE);
    g_config.event_loop_timeout_ms = DEFAULT_EVENT_LOOP_TIMEOUT_MS;
    g_config.idmap_timeout_ms = DEFAULT_IDMAP_TIMEOUT_MS;
}

// config_load_args 解析命令行选项；字符串类参数先校验后写入配置，避免错误推迟到后续模块。
int config_load_args(int argc, char **argv) {
    int i;

    config_init_defaults();

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            config_print_usage(argv[0]);
            return 1;
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i + 1 < argc) {
            if (parse_port(argv[++i], &g_config.listen_port) != 0) {
                log_error("invalid listen port: %s", argv[i]);
                return -1;
            }
        } else if ((strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--upstream") == 0) && i + 1 < argc) {
            const char *upstream = argv[++i];
            if (!string_fits_config_buffer(upstream, CONFIG_IP_MAX) || !is_valid_ip_literal(upstream)) {
                log_error("invalid upstream DNS IP: %s", upstream);
                return -1;
            }
            copy_string(g_config.upstream_dns, sizeof(g_config.upstream_dns), upstream);
        } else if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--table") == 0) && i + 1 < argc) {
            const char *table_file = argv[++i];
            if (!is_readable_table_file(table_file)) {
                log_error("invalid or unreadable local table file: %s", table_file);
                return -1;
            }
            copy_string(g_config.table_file, sizeof(g_config.table_file), table_file);
        } else if (strcmp(argv[i], "--event-timeout") == 0 && i + 1 < argc) {
            if (parse_positive_int(argv[++i], &g_config.event_loop_timeout_ms) != 0) {
                log_error("invalid event timeout: %s", argv[i]);
                return -1;
            }
        } else if (strcmp(argv[i], "--id-timeout") == 0 && i + 1 < argc) {
            if (parse_positive_int(argv[++i], &g_config.idmap_timeout_ms) != 0) {
                log_error("invalid id timeout: %s", argv[i]);
                return -1;
            }
        } else {
            log_error("unknown or incomplete option: %s", argv[i]);
            config_print_usage(argv[0]);
            return -1;
        }
    }

    if (!is_readable_table_file(g_config.table_file)) {
        log_error("invalid or unreadable local table file: %s", g_config.table_file);
        return -1;
    }

    return 0;
}

// config_get 返回当前配置的只读访问入口。
const Config *config_get(void) {
    return &g_config;
}

// config_print_usage 打印服务端支持的命令行参数。
void config_print_usage(const char *program_name) {
    fprintf(stderr,
            "Usage: %s [options]\n"
            "Options:\n"
            "  -p, --port <port>           Listen UDP port, default 53\n"
            "  -u, --upstream <ip>         Upstream DNS server IPv4/IPv6 literal\n"
            "  -t, --table <file>          Local table file, default data/dnsrelay.txt\n"
            "      --event-timeout <ms>    select wakeup interval, default 1000\n"
            "      --id-timeout <ms>       upstream response timeout, default 5000\n",
            program_name == NULL ? "Main" : program_name);
}
