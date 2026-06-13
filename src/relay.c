#include "relay.h"

#include "cache.h"
#include "config.h"
#include "dns.h"
#include "idmap.h"
#include "logger.h"

#include <string.h>

// 上游DNS服务器固定使用标准DNS端口。
#define UPSTREAM_DNS_PORT 53

static int is_ipv4_mapped_addr(const struct in6_addr *addr) {
    static const uint8_t prefix[12] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
    };

    return addr != NULL && memcmp(addr->s6_addr, prefix, sizeof(prefix)) == 0;
}

// relay_get_upstream_addr 根据当前配置拼出上游DNS的IPv4/IPv6 UDP地址。
int relay_get_upstream_addr(struct sockaddr_storage *addr, socklen_t *addr_len) {
    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (addr == NULL || addr_len == NULL) {
        return -1;
    }

    memset(addr, 0, sizeof(*addr));

    if (inet_pton(AF_INET6, config_get()->upstream_dns, &ipv6) == 1) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(UPSTREAM_DNS_PORT);
        addr6->sin6_addr = ipv6;
        *addr_len = sizeof(*addr6);
        return 0;
    }

    if (inet_pton(AF_INET, config_get()->upstream_dns, &ipv4) == 1) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(UPSTREAM_DNS_PORT);
        memset(&addr6->sin6_addr, 0, sizeof(addr6->sin6_addr));
        addr6->sin6_addr.s6_addr[10] = 0xff;
        addr6->sin6_addr.s6_addr[11] = 0xff;
        memcpy(&addr6->sin6_addr.s6_addr[12], &ipv4.s_addr, sizeof(ipv4.s_addr));
        *addr_len = sizeof(*addr6);
        return 0;
    }

    return -1;
}

// relay_is_from_upstream 用于区分主socket收到的是客户端查询还是上游响应。
int relay_is_from_upstream(const struct sockaddr *addr) {
    struct sockaddr_storage upstream_addr;
    socklen_t upstream_len;

    if (addr == NULL) {
        return 0;
    }

    if (relay_get_upstream_addr(&upstream_addr, &upstream_len) != 0) {
        return 0;
    }

    if (addr->sa_family == AF_INET &&
        upstream_addr.ss_family == AF_INET6 &&
        is_ipv4_mapped_addr(&((const struct sockaddr_in6 *)&upstream_addr)->sin6_addr)) {
        const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
        const struct sockaddr_in6 *upstream6 = (const struct sockaddr_in6 *)&upstream_addr;

        return addr4->sin_port == upstream6->sin6_port &&
               memcmp(&addr4->sin_addr.s_addr, &upstream6->sin6_addr.s6_addr[12], 4) == 0;
    }

    if (addr->sa_family != upstream_addr.ss_family) {
        return 0;
    }

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
        const struct sockaddr_in *upstream4 = (const struct sockaddr_in *)&upstream_addr;

        return addr4->sin_port == upstream4->sin_port &&
               addr4->sin_addr.s_addr == upstream4->sin_addr.s_addr;
    }

    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
        const struct sockaddr_in6 *upstream6 = (const struct sockaddr_in6 *)&upstream_addr;

        return addr6->sin6_port == upstream6->sin6_port &&
               memcmp(&addr6->sin6_addr, &upstream6->sin6_addr, sizeof(addr6->sin6_addr)) == 0;
    }

    return 0;
}

// 复用主socket转发：修改DNS ID，记录映射，然后直接sendto上游DNS。
int relay_forward_query(socket_t sock,
                        uint8_t *query_buf,
                        int query_len,
                        const struct sockaddr *client_addr,
                        socklen_t client_len,
                        const char *domain,
                        uint16_t qtype,
                        uint16_t qclass) {
    struct sockaddr_storage upstream_addr;
    socklen_t upstream_len;
    uint16_t client_id;
    uint16_t upstream_id;
    int n;

    if (sock == SOCKET_INVALID || query_buf == NULL || query_len <= 0 || client_addr == NULL) {
        return -1;
    }

    client_id = dns_get_id(query_buf, query_len);

    // 将客户端相关信息作为新的条目加入ID映射表（upstream_id段暂时留空），并检查
    if (idmap_add(client_id, client_addr, client_len, query_buf, query_len, domain, qtype, qclass, &upstream_id) != 0) {
        log_warn("add id map failed domain=%s", domain == NULL ? "" : domain);
        return -1;
    }

    dns_set_id(query_buf, query_len, upstream_id);
    if (relay_get_upstream_addr(&upstream_addr, &upstream_len) != 0) {
        idmap_remove(upstream_id);
        log_warn("invalid upstream DNS address: %s", config_get()->upstream_dns);
        return -1;
    }
    // 将 客户端的查询报 转发给 上游DNS服务器
    n = (int)sendto(sock, (const char *)query_buf, query_len, 0,
                   (struct sockaddr *)&upstream_addr, upstream_len);
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
    struct sockaddr_storage client_addr;
    socklen_t client_len;
    char domain[256];
    uint32_t cache_ip;
    uint8_t cache_ipv6[16];
    uint32_t ttl_sec;
    uint16_t qtype;
    uint16_t qclass;
    int n;

    if (sock == SOCKET_INVALID || response_buf == NULL || response_len <= 0) {
        return -1;
    }
    // 获取上游 DNS 服务器 id
    upstream_id = dns_get_id(response_buf, response_len);
    if (!idmap_find(upstream_id, &client_id, &client_addr, &client_len, domain, sizeof(domain), &qtype, &qclass)) {
        log_warn("unknown upstream response id=%u", upstream_id);
        return -1;
    }
    if (!dns_response_matches_question(response_buf, response_len, domain, qtype, qclass)) {
        log_warn("upstream response question mismatch domain=%s upstream_id=%u", domain, upstream_id);
        idmap_remove(upstream_id);
        return -1;
    }
    if (qtype == DNS_TYPE_A && qclass == DNS_CLASS_IN &&
        dns_extract_first_a_record_for_domain(response_buf, response_len, domain, &cache_ip, &ttl_sec)) {
        cache_store(domain, cache_ip, ttl_sec);
    } else if (qtype == DNS_TYPE_AAAA && qclass == DNS_CLASS_IN &&
               dns_extract_first_aaaa_record_for_domain(response_buf, response_len, domain, cache_ipv6, &ttl_sec)) {
        cache_store_aaaa(domain, cache_ipv6, ttl_sec);
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
