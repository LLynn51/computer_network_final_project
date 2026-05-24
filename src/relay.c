#include "relay.h"

#include "dns.h"
#include "idmap.h"
#include "logger.h"

#include <string.h>

#define UPSTREAM_DNS_IP "8.8.8.8" // 默认上游DNS服务器ip
#define UPSTREAM_DNS_PORT 53

// 没看懂
void relay_get_upstream_addr(struct sockaddr_in *addr) {
    if (addr == NULL) {
        return;
    }
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(UPSTREAM_DNS_PORT);
    addr->sin_addr.s_addr = inet_addr(UPSTREAM_DNS_IP);
}
// 没看懂
int relay_is_from_upstream(const struct sockaddr_in *addr) {
    struct sockaddr_in upstream_addr;
    if (addr == NULL) {
        return 0;
    }
    relay_get_upstream_addr(&upstream_addr);
    return addr->sin_family == AF_INET &&
           addr->sin_port == upstream_addr.sin_port &&
           addr->sin_addr.s_addr == upstream_addr.sin_addr.s_addr;
}

// 复用主socket转发：修改DNS ID，记录映射，然后直接sendto上游DNS。
int relay_forward_query(socket_t sock,
                        uint8_t *query_buf,
                        int query_len,
                        const struct sockaddr_in *client_addr,
                        socklen_t client_len,
                        const char *domain) {
    struct sockaddr_in upstream_addr;
    uint16_t client_id;
    uint16_t upstream_id;
    int n;

    if (sock == SOCKET_INVALID || query_buf == NULL || query_len <= 0 || client_addr == NULL) {
        return -1;
    }

    client_id = dns_get_id(query_buf, query_len);

    // 将客户端相关信息作为新的条目加入ID映射表（upstream_id段暂时留空），并检查
    if (idmap_add(client_id, client_addr, client_len, domain, &upstream_id) != 0) {
        log_warn("add id map failed domain=%s", domain == NULL ? "" : domain);
        return -1;
    }

    dns_set_id(query_buf, query_len, upstream_id);
    relay_get_upstream_addr(&upstream_addr);
    // 将 客户端的查询报 转发给 上游DNS服务器
    n = (int)sendto(sock, (const char *)query_buf, query_len, 0,
                   (struct sockaddr *)&upstream_addr, sizeof(upstream_addr));
    if (n != query_len) {
        idmap_remove(upstream_id);
        log_warn("send query to upstream failed domain=%s", domain == NULL ? "" : domain);
        return -1;
    }

    log_info("forward query domain=%s client_id=%u upstream_id=%u",
             domain == NULL ? "" : domain,
             client_id,
             upstream_id);
    return 0;
}

// relay_handle_upstream_response 上游响应已（在main.c中）由主socket收到；
//                                根据响应ID找到原客户端，改回原ID后发回客户端。
int relay_handle_upstream_response(socket_t sock, uint8_t *response_buf, int response_len) {
    uint16_t upstream_id;
    uint16_t client_id;
    struct sockaddr_in client_addr;
    socklen_t client_len;
    int n;

    if (sock == SOCKET_INVALID || response_buf == NULL || response_len <= 0) {
        return -1;
    }
    // 获取上游 DNS 服务器 id
    upstream_id = dns_get_id(response_buf, response_len);
    if (!idmap_find(upstream_id, &client_id, &client_addr, &client_len)) {
        log_warn("unknown upstream response id=%u", upstream_id);
        return -1;
    }
    // 将上游DNS服务器响应的id设置为客户端请求的旧id
    dns_set_id(response_buf, response_len, client_id);
    // 将修改过id的上游DNS服务器响应 用 原socket 返回给客户端 （flag字段为0表示为查询报）
    n = (int)sendto(sock, (const char *)response_buf, response_len, 0,
                   (struct sockaddr *)&client_addr, client_len);
    // 从ID映射表中去除已经完成返回的条目
    idmap_remove(upstream_id);
    // 检查
    if (n != response_len) {
        log_warn("send upstream response to client failed upstream_id=%u client_id=%u",
                 upstream_id,
                 client_id);
        return -1;
    }
    // 成功后打印调试信息
    log_info("return upstream response upstream_id=%u client_id=%u response_len=%d",
             upstream_id,
             client_id,
             response_len);
    return 0;
}
