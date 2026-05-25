#include "dns.h"
#include "logger.h"
#include "netutil.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_DNS_SERVER "127.0.0.1"
#define DEFAULT_DNS_PORT 53
#define CLIENT_TIMEOUT_MS 3000

static void print_usage(const char *program_name) {
    fprintf(stderr,
            "Usage: %s <domain> [dns_server] [dns_port]\n"
            "Examples:\n"
            "  %s www.baidu.com\n"
            "  %s www.baidu.com 127.0.0.1 5353\n",
            program_name,
            program_name,
            program_name);
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

static void print_ipv4(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    printf("%s", inet_ntoa(addr));
}

int main(int argc, char **argv) {
    const char *domain;
    const char *dns_server = DEFAULT_DNS_SERVER;
    uint16_t dns_port = DEFAULT_DNS_PORT;
    socket_t sock;
    struct sockaddr_in server_addr;
    uint8_t query_buf[DNS_MAX_PACKET_SIZE];
    uint8_t response_buf[DNS_MAX_PACKET_SIZE];
    uint16_t query_id;
    int query_len;
    int ready;
    int n;
    DNSResponse response;

    if (argc < 2 || argc > 4) {
        print_usage(argv[0]);
        return 1;
    }

    domain = argv[1];
    if (argc >= 3) {
        dns_server = argv[2];
    }
    if (argc >= 4 && parse_port(argv[3], &dns_port) != 0) {
        fprintf(stderr, "[错误] DNS端口不合法：%s\n", argv[3]);
        return 1;
    }

    srand((unsigned int)time(NULL));

    if (net_init() != 0) {
        return 1;
    }

    query_len = dns_build_query(domain, 1, query_buf, sizeof(query_buf), &query_id);
    if (query_len <= 0) {
        fprintf(stderr, "[错误] 构造DNS查询失败，请检查域名格式\n");
        net_cleanup();
        return 1;
    }

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == SOCKET_INVALID) {
        fprintf(stderr, "[错误] 创建UDP socket失败\n");
        net_cleanup();
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(dns_port);
    server_addr.sin_addr.s_addr = inet_addr(dns_server);
    if (server_addr.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "[错误] DNS服务器地址不合法：%s\n", dns_server);
        socket_close(sock);
        net_cleanup();
        return 1;
    }

    printf("[查询] 域名：%s，DNS服务器：%s:%u\n", domain, dns_server, dns_port);

    n = (int)sendto(sock, (const char *)query_buf, query_len, 0,
                   (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (n != query_len) {
        fprintf(stderr, "[错误] 发送DNS查询失败\n");
        socket_close(sock);
        net_cleanup();
        return 1;
    }

    ready = net_wait_readable(sock, CLIENT_TIMEOUT_MS);
    if (ready == 0) {
        printf("[超时] DNS服务器无响应\n");
        socket_close(sock);
        net_cleanup();
        return 2;
    }
    if (ready < 0) {
        fprintf(stderr, "[错误] 等待DNS响应失败\n");
        socket_close(sock);
        net_cleanup();
        return 1;
    }

    n = (int)recvfrom(sock, (char *)response_buf, sizeof(response_buf), 0, NULL, NULL);
    if (n <= 0) {
        fprintf(stderr, "[错误] 接收DNS响应失败\n");
        socket_close(sock);
        net_cleanup();
        return 1;
    }

    if (dns_parse_response(response_buf, n, &response) != 0) {
        fprintf(stderr, "[错误] DNS响应格式非法\n");
        socket_close(sock);
        net_cleanup();
        return 1;
    }

    if (response.id != query_id) {
        printf("[错误] DNS响应ID不匹配，期望=%u，实际=%u\n", query_id, response.id);
        socket_close(sock);
        net_cleanup();
        return 1;
    }

    if (response.rcode == 3) {
        printf("[失败] 域名不存在，或已被本地DNS Relay拦截\n");
    } else if (response.rcode != 0) {
        printf("[失败] DNS服务器返回错误，RCODE=%u\n", response.rcode);
    } else if (response.has_a_record) {
        if (response.ipv4 == 0) {
            printf("[拦截] %s 此信息不良！将被过滤掉\n返回地址：0.0.0.0\n", domain);
        } else {
            printf("[成功] %s -> ", domain);
            print_ipv4(response.ipv4);
            printf("，TTL=%u秒\n", response.ttl_sec);
        }
    } else if (response.answer_count == 0) {
        printf("[失败] DNS响应没有回答记录\n");
    } else {
        printf("[失败] DNS响应中没有IPv4 A记录\n");
    }

    socket_close(sock);
    net_cleanup();
    return 0;
}
