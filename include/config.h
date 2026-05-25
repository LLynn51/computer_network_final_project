#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#define CONFIG_PATH_MAX 260
#define CONFIG_IP_MAX 64

typedef struct {
    uint16_t listen_port;
    char upstream_dns[CONFIG_IP_MAX];
    char table_file[CONFIG_PATH_MAX];
    int event_loop_timeout_ms;
    int idmap_timeout_ms;
} Config;

void config_init_defaults(void);
int config_load_args(int argc, char **argv);
const Config *config_get(void);
void config_print_usage(const char *program_name);

#endif
