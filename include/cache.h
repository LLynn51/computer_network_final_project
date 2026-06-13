#ifndef CACHE_H
#define CACHE_H

#include <stdint.h>

// 初始化内存缓存表，程序启动时调用一次。
void cache_init(void);

// 查询域名缓存；命中且未过期时将主机字节序 IPv4 写入 ip 并返回 1。
int cache_lookup(const char *domain, uint32_t *ip);

// 查询 AAAA 缓存；命中且未过期时写出网络字节序 IPv6 16 字节地址并返回 1。
int cache_lookup_aaaa(const char *domain, uint8_t ipv6[16]);

// 按上游 DNS 返回的 TTL 保存 A 记录缓存；ttl_sec 为 0 时不缓存。
void cache_store(const char *domain, uint32_t ip, uint32_t ttl_sec);

// 按上游 DNS 返回的 TTL 保存 AAAA 记录缓存；ttl_sec 为 0 时不缓存。
void cache_store_aaaa(const char *domain, const uint8_t ipv6[16], uint32_t ttl_sec);

// 清理已经超过过期时间的缓存项，now_ms 使用 net_now_ms() 的毫秒时间。
void cache_cleanup_expired(uint64_t now_ms);

#endif
