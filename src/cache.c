#include "cache.h"

#include "dns.h"
#include "logger.h"
#include "netutil.h"

#include <ctype.h>
#include <string.h>

// 缓存表最大条目数；满表时会覆盖最早过期的条目。
#define CACHE_MAX_ENTRIES 1024

// 缓存键使用的域名缓冲区长度。
#define CACHE_MAX_DOMAIN_LEN 256

typedef struct {
    // 该槽位是否正在保存有效缓存项。
    int used;
    // 小写规范化后的域名。
    char domain[CACHE_MAX_DOMAIN_LEN];
    // DNS记录类型，例如A或AAAA。
    uint16_t qtype;
    // A记录使用前4字节，AAAA记录使用16字节，均为网络字节序。
    uint8_t addr[16];
    // 过期时间点，单位为 net_now_ms() 的毫秒。
    uint64_t expire_at_ms;
} CacheEntry;

// 固定大小的内存 DNS A/AAAA 记录缓存。
static CacheEntry g_cache[CACHE_MAX_ENTRIES];

// 将 ASCII 域名转换为小写，便于做大小写不敏感匹配。
static void to_lower_ascii(char *s) {
    while (s != NULL && *s != '\0') {
        *s = (char)tolower((unsigned char)*s);
        s++;
    }
}

// 根据域名生成缓存键：复制到固定缓冲区并统一转为小写。
static void make_key(const char *domain, char *out, int out_size) {
    if (out == NULL || out_size <= 0) {
        return;
    }

    if (domain == NULL) {
        out[0] = '\0';
        return;
    }

    strncpy(out, domain, (size_t)out_size - 1);
    out[out_size - 1] = '\0';
    to_lower_ascii(out);
}

// cache_init 清空所有缓存槽位。
void cache_init(void) {
    memset(g_cache, 0, sizeof(g_cache));
}

static int cache_lookup_record(const char *domain, uint16_t qtype, uint8_t *addr, int addr_len) {
    char key[CACHE_MAX_DOMAIN_LEN];
    uint64_t now = net_now_ms();
    int i;

    if (domain == NULL || addr == NULL || addr_len <= 0 || addr_len > 16) {
        return 0;
    }

    make_key(domain, key, sizeof(key));
    for (i = 0; i < CACHE_MAX_ENTRIES; i++) {
        if (g_cache[i].used && g_cache[i].qtype == qtype && strcmp(g_cache[i].domain, key) == 0) {
            if (now >= g_cache[i].expire_at_ms) {
                log_info("cache expired domain=%s qtype=%u", g_cache[i].domain, g_cache[i].qtype);
                memset(&g_cache[i], 0, sizeof(g_cache[i]));
                return 0;
            }

            memcpy(addr, g_cache[i].addr, (size_t)addr_len);
            log_info("cache hit domain=%s qtype=%u", domain, qtype);
            return 1;
        }
    }

    return 0;
}

static void cache_store_record(const char *domain, uint16_t qtype, const uint8_t *addr, int addr_len, uint32_t ttl_sec) {
    char key[CACHE_MAX_DOMAIN_LEN];
    uint64_t expire_at_ms;
    int target = -1;
    int i;

    if (domain == NULL || domain[0] == '\0' || addr == NULL || addr_len <= 0 || addr_len > 16 || ttl_sec == 0) {
        return;
    }

    make_key(domain, key, sizeof(key));
    expire_at_ms = net_now_ms() + (uint64_t)ttl_sec * 1000u;

    for (i = 0; i < CACHE_MAX_ENTRIES; i++) {
        if (g_cache[i].used && g_cache[i].qtype == qtype && strcmp(g_cache[i].domain, key) == 0) {
            target = i;
            break;
        }
        if (!g_cache[i].used && target < 0) {
            target = i;
        }
    }

    if (target < 0) {
        target = 0;
        for (i = 1; i < CACHE_MAX_ENTRIES; i++) {
            if (g_cache[i].expire_at_ms < g_cache[target].expire_at_ms) {
                target = i;
            }
        }
    }

    g_cache[target].used = 1;
    strncpy(g_cache[target].domain, key, sizeof(g_cache[target].domain) - 1);
    g_cache[target].domain[sizeof(g_cache[target].domain) - 1] = '\0';
    g_cache[target].qtype = qtype;
    memset(g_cache[target].addr, 0, sizeof(g_cache[target].addr));
    memcpy(g_cache[target].addr, addr, (size_t)addr_len);
    g_cache[target].expire_at_ms = expire_at_ms;
    log_info("cache store domain=%s qtype=%u ttl=%u", domain, qtype, ttl_sec);
}

// cache_lookup 查询未过期的A缓存项；过期项会在命中检查时顺手删除。
int cache_lookup(const char *domain, uint32_t *ip) {
    uint32_t network_ip;

    if (ip == NULL) {
        return 0;
    }

    if (!cache_lookup_record(domain, DNS_TYPE_A, (uint8_t *)&network_ip, sizeof(network_ip))) {
        return 0;
    }

    *ip = ntohl(network_ip);
    return 1;
}

int cache_lookup_aaaa(const char *domain, uint8_t ipv6[16]) {
    return cache_lookup_record(domain, DNS_TYPE_AAAA, ipv6, 16);
}

// cache_store 写入或更新A缓存；如果缓存满，覆盖过期时间最早的条目。
void cache_store(const char *domain, uint32_t ip, uint32_t ttl_sec) {
    uint32_t network_ip = htonl(ip);
    cache_store_record(domain, DNS_TYPE_A, (const uint8_t *)&network_ip, sizeof(network_ip), ttl_sec);
}

void cache_store_aaaa(const char *domain, const uint8_t ipv6[16], uint32_t ttl_sec) {
    cache_store_record(domain, DNS_TYPE_AAAA, ipv6, 16, ttl_sec);
}

// cache_cleanup_expired 周期性清理所有已经过期的缓存项。
void cache_cleanup_expired(uint64_t now_ms) {
    int i;

    for (i = 0; i < CACHE_MAX_ENTRIES; i++) {
        if (g_cache[i].used && now_ms >= g_cache[i].expire_at_ms) {
            log_info("cache expired domain=%s qtype=%u", g_cache[i].domain, g_cache[i].qtype);
            memset(&g_cache[i], 0, sizeof(g_cache[i]));
        }
    }
}
