#include "config.h"

#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_DNS_PORT 53
#define DEFAULT_UPSTREAM_DNS "8.8.8.8"
#define DEFAULT_TABLE_FILE "data/dnsrelay.txt"
#define DEFAULT_EVENT_LOOP_TIMEOUT_MS 1000
#define DEFAULT_IDMAP_TIMEOUT_MS 5000

static Config g_config;

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

void config_init_defaults(void) {
    g_config.listen_port = DEFAULT_DNS_PORT;
    copy_string(g_config.upstream_dns, sizeof(g_config.upstream_dns), DEFAULT_UPSTREAM_DNS);
    copy_string(g_config.table_file, sizeof(g_config.table_file), DEFAULT_TABLE_FILE);
    g_config.event_loop_timeout_ms = DEFAULT_EVENT_LOOP_TIMEOUT_MS;
    g_config.idmap_timeout_ms = DEFAULT_IDMAP_TIMEOUT_MS;
}

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
            copy_string(g_config.upstream_dns, sizeof(g_config.upstream_dns), argv[++i]);
        } else if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--table") == 0) && i + 1 < argc) {
            copy_string(g_config.table_file, sizeof(g_config.table_file), argv[++i]);
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

    return 0;
}

const Config *config_get(void) {
    return &g_config;
}

void config_print_usage(const char *program_name) {
    fprintf(stderr,
            "Usage: %s [options]\n"
            "Options:\n"
            "  -p, --port <port>           Listen UDP port, default 53\n"
            "  -u, --upstream <ip>         Upstream DNS server, default 8.8.8.8\n"
            "  -t, --table <file>          Local table file, default data/dnsrelay.txt\n"
            "      --event-timeout <ms>    select wakeup interval, default 1000\n"
            "      --id-timeout <ms>       upstream response timeout, default 5000\n",
            program_name == NULL ? "Main" : program_name);
}
