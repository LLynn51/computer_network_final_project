#ifndef TABLE_H
#define TABLE_H

#include <stdint.h>

// 从本地域名表文件加载域名到 IPv4/IPv6 的映射，返回成功加载的条目数。
int load_table(const char *filename);

// 查询本地域名表；命中返回 1 并写出主机字节序 IPv4。
int table_lookup_a(const char *domain, uint32_t *ip);

// 查询本地域名表；命中返回 1 并写出网络字节序 IPv6 16 字节地址。
int table_lookup_aaaa(const char *domain, uint8_t ipv6[16]);

// 兼容旧接口：查询 A 记录。
int table_lookup(const char *domain, uint32_t *ip);

// 释放本地域名表链表。
void table_free(void);

#endif
