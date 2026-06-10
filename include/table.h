#ifndef TABLE_H
#define TABLE_H

#include <stdint.h>

// 从本地域名表文件加载域名到 IPv4 的映射，返回成功加载的条目数。
int load_table(const char *filename);

// 查询本地域名表；命中返回 1 并写出主机字节序 IPv4。
int table_lookup(const char *domain, uint32_t *ip);

// 释放本地域名表链表。
void table_free(void);

#endif
