#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

// 命令行表文件路径的最大长度，兼容 Windows 常见 MAX_PATH。
#define CONFIG_PATH_MAX 260

// 上游 DNS IPv4 字符串缓冲区长度，预留足够空间用于结束符和错误输入。
#define CONFIG_IP_MAX 64

typedef struct {
    // 本地 DNS Relay 监听的 UDP 端口。
    uint16_t listen_port;
    // 上游 DNS 服务器 IPv4 地址字符串。
    char upstream_dns[CONFIG_IP_MAX];
    // 本地域名表文件路径。
    char table_file[CONFIG_PATH_MAX];
    // select() 事件循环的超时时间，单位毫秒。
    int event_loop_timeout_ms;
    // 转发到上游后等待响应的映射保留时间，单位毫秒。
    int idmap_timeout_ms;
} Config;

// 将全局配置恢复为默认值。
void config_init_defaults(void);

// 解析命令行参数；返回 0 成功，正数表示已处理帮助，负数表示参数错误。
int config_load_args(int argc, char **argv);

// 获取当前全局配置的只读指针。
const Config *config_get(void);

// 打印服务端命令行参数用法。
void config_print_usage(const char *program_name);

#endif
