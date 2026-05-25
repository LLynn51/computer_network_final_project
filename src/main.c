#include "dns.h"
#include "idmap.h"
#include "logger.h"
#include "netutil.h"
#include "relay.h"
#include "table.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// 端口53需要管理员权限
#define DEFAULT_DNS_PORT 53
#define LOCAL_TABLE_FILE "data/dnsrelay.txt"
#define EVENT_LOOP_TIMEOUT_MS 1000 // TODO：EVENT_LOOP是指？
#define IDMAP_TIMEOUT_MS 5000 // DNS 响应超时计时器

static uint16_t parse_port(int argc, char **argv) {
    long port;

    if (argc < 2) {
        return DEFAULT_DNS_PORT;
    }

    port = strtol(argv[1], NULL, 10);
    if (port <= 0 || port > 65535) {
        log_warn("invalid port '%s', use default port %d", argv[1], DEFAULT_DNS_PORT);
        return DEFAULT_DNS_PORT;
    }

    return (uint16_t)port;
}

// 由于UDP协议不可信，因此每次每次调用协议解析器都需要检查边界
int main(int argc, char **argv) {
    uint16_t port = parse_port(argc, argv);
    socket_t sock;
    uint8_t buf[DNS_MAX_PACKET_SIZE];
    uint8_t response[DNS_MAX_PACKET_SIZE];

    // net_init()：Windows系统下WSAStartup()
    // 在netutil.c中实现
    if (net_init() != 0) {
        return 1;
    }

    idmap_init();
    load_table(LOCAL_TABLE_FILE);

    // ubp_bind_socket()：将 socket 绑定到命令行输入指定的端口
    // 在 udp_bind_socket.c中实现
    // 全程（整个项目）只使用一个sock！
    sock = udp_bind_socket(port);
    if (sock == SOCKET_INVALID) {
        net_cleanup();
        return 1;
    }
    // 绑定成功后打印调试信息
    log_info("DNS relay listening on UDP port %u", port);


    for (;;) {
        struct sockaddr_in src_addr;
        socklen_t src_len = sizeof(src_addr);
        int n;
        int ready;
        DNSQuery query;
        char src_ip[64];
        uint32_t local_ip;
        int response_len;


        printf("waiting...\n");

        ready = net_wait_readable(sock, EVENT_LOOP_TIMEOUT_MS);
        if (ready < 0) {
            log_warn("select failed");
            continue;
        }

        if (ready == 0) {
            continue;
        }
        
        // recvfrom 等待，直到有client或上游DNS给主socket发UDP包
        // recvfrom函数把DNS数据写进buf，写入发包方地址(src_addr)，并返回数据长度
        n = (int)recvfrom(sock, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&src_addr, &src_len);
        if (n <= 0) {
            log_warn("recvfrom failed");
        } else {
            printf("received %d bytes\n", n);
            // 现在buf内已是DNS协议二进制数据

            // 处理来自上游DNS服务器的响应
            if (relay_is_from_upstream(&src_addr) && dns_is_response(buf, n)) {
                relay_handle_upstream_response(sock, buf, n);
            } else if (dns_parse_query(buf, n, &query) != 0) {
                // dns_parse_query()：进行DNS协议解析
                // 在dns.c中实现
                // 输入buf[]中的原始二进制协议，输出结构化的结果（含有id、domain和qtype等信息）
                log_warn("invalid dns packet from %s:%u len=%d",
                         sockaddr_to_string(&src_addr, src_ip, sizeof(src_ip)),
                         ntohs(src_addr.sin_port), n);
            } else {
                // 服务器接收到客户端请求时打印调试信息
                log_info("query client=%s:%u id=%u domain=%s qtype=%u qclass=%u",
                         sockaddr_to_string(&src_addr, src_ip, sizeof(src_ip)),
                         ntohs(src_addr.sin_port), query.id, query.domain, query.qtype, query.qclass);

                // 本地表命中时，直接构造固定IP响应
                if (query.qtype == 1 && query.qclass == 1 && table_lookup(query.domain, &local_ip)) {
                    if (local_ip == 0) { // 如果 *ip==0 ，说明是被拦截的域名；
                        response_len = dns_build_nxdomain_response(buf, n, response, sizeof(response));
                        log_info("local block domain=%s", query.domain);
                    } else { // 否则是正常返回的域名
                        response_len = dns_build_a_response(buf, n, local_ip, response, sizeof(response));
                        log_info("local hit domain=%s", query.domain);
                    }

                    // 检查是否正常得到 Question 结束后的第一个字节下标
                    // 如果是，转发给发包方（客户端）
                    if (response_len > 0) {
                        sendto(sock, (const char *)response, response_len, 0,
                               (struct sockaddr *)&src_addr, src_len);
                    } else {
                        log_warn("build local response failed domain=%s", query.domain);
                    }
                } else if (relay_forward_query(sock, buf, n, &src_addr, src_len, query.domain) != 0) {
                    // 本地未命中时，复用主socket转发给上游DNS；响应会在后续recvfrom中收到
                    log_warn("forward failed domain=%s", query.domain);
                }
            }
        }

        idmap_cleanup_timeout(net_now_ms(), IDMAP_TIMEOUT_MS);
    }

    socket_close(sock);
    table_free();
    net_cleanup();
    return 0;
}
