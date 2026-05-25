#ifndef CACHE_H
#define CACHE_H

#include <stdint.h>

void cache_init(void);
int cache_lookup(const char *domain, uint32_t *ip);
void cache_store(const char *domain, uint32_t ip, uint32_t ttl_sec);
void cache_cleanup_expired(uint64_t now_ms);

#endif
