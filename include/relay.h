#ifndef RELAY_H
#define RELAY_H

#include "netutil.h"

#include <stdint.h>

// 根据当前配置生成上游 DNS 的 IPv4 socket 地址。
void relay_get_upstream_addr(struct sockaddr_in *addr);

// 判断收到的 UDP 包是否来自配置中的上游 DNS。
int relay_is_from_upstream(const struct sockaddr_in *addr);

// 转发客户端查询到上游 DNS，并建立上游 ID 到客户端 ID 的映射。
int relay_forward_query(socket_t sock,
                        uint8_t *query_buf,
                        int query_len,
                        const struct sockaddr_in *client_addr,
                        socklen_t client_len,
                        const char *domain,
                        uint16_t qtype,
                        uint16_t qclass);

// 处理上游 DNS 响应：校验、缓存 A 记录、改回客户端 ID 并回送。
int relay_handle_upstream_response(socket_t sock, uint8_t *response_buf, int response_len);

#endif
