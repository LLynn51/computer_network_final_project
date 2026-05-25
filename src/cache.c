#include "cache.h"

#include "logger.h"
#include "netutil.h"

#include <ctype.h>
#include <string.h>

#define CACHE_MAX_ENTRIES 1024
#define CACHE_MAX_DOMAIN_LEN 256

typedef struct {
    int used;
    char domain[CACHE_MAX_DOMAIN_LEN];
    uint32_t ip;
    uint64_t expire_at_ms;
} CacheEntry;

static CacheEntry g_cache[CACHE_MAX_ENTRIES];

static void to_lower_ascii(char *s) {
    while (s != NULL && *s != '\0') {
        *s = (char)tolower((unsigned char)*s);
        s++;
    }
}

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

void cache_init(void) {
    memset(g_cache, 0, sizeof(g_cache));
}

int cache_lookup(const char *domain, uint32_t *ip) {
    char key[CACHE_MAX_DOMAIN_LEN];
    uint64_t now = net_now_ms();
    int i;

    if (domain == NULL || ip == NULL) {
        return 0;
    }

    make_key(domain, key, sizeof(key));
    for (i = 0; i < CACHE_MAX_ENTRIES; i++) {
        if (g_cache[i].used && strcmp(g_cache[i].domain, key) == 0) {
            if (now >= g_cache[i].expire_at_ms) {
                log_info("cache expired domain=%s", g_cache[i].domain);
                memset(&g_cache[i], 0, sizeof(g_cache[i]));
                return 0;
            }

            *ip = g_cache[i].ip;
            log_info("cache hit domain=%s", domain);
            return 1;
        }
    }

    return 0;
}

void cache_store(const char *domain, uint32_t ip, uint32_t ttl_sec) {
    char key[CACHE_MAX_DOMAIN_LEN];
    uint64_t expire_at_ms;
    int target = -1;
    int i;

    if (domain == NULL || domain[0] == '\0' || ttl_sec == 0) {
        return;
    }

    make_key(domain, key, sizeof(key));
    expire_at_ms = net_now_ms() + (uint64_t)ttl_sec * 1000u;

    for (i = 0; i < CACHE_MAX_ENTRIES; i++) {
        if (g_cache[i].used && strcmp(g_cache[i].domain, key) == 0) {
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
    g_cache[target].ip = ip;
    g_cache[target].expire_at_ms = expire_at_ms;
    log_info("cache store domain=%s ttl=%u", domain, ttl_sec);
}

void cache_cleanup_expired(uint64_t now_ms) {
    int i;

    for (i = 0; i < CACHE_MAX_ENTRIES; i++) {
        if (g_cache[i].used && now_ms >= g_cache[i].expire_at_ms) {
            log_info("cache expired domain=%s", g_cache[i].domain);
            memset(&g_cache[i], 0, sizeof(g_cache[i]));
        }
    }
}
