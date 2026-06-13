#ifndef IDMAP_H
#define IDMAP_H

#include "netutil.h"

#include <stdint.h>

// 初始化 DNS ID 映射表。
void idmap_init(void);

// 保存客户端请求信息并分配新的上游 ID；成功返回 0。
int idmap_add(uint16_t client_id,
              const struct sockaddr *client_addr,
              socklen_t client_len,
              const uint8_t *query_buf,
              int query_len,
              const char *domain,
              uint16_t qtype,
              uint16_t qclass,
              uint16_t *upstream_id);

// 根据上游响应 ID 找回客户端地址、原始 ID 和查询信息；命中返回 1。
int idmap_find(uint16_t upstream_id,
               uint16_t *client_id,
               struct sockaddr_storage *client_addr,
               socklen_t *client_len,
               char *domain,
               int domain_size,
               uint16_t *qtype,
               uint16_t *qclass);

// 删除指定上游 ID 对应的映射项。
void idmap_remove(uint16_t upstream_id);

// 清理等待上游响应超时的映射项。
void idmap_cleanup_timeout(socket_t sock, uint64_t now_ms, uint64_t timeout_ms);

#endif
