#ifndef RELAY_H
#define RELAY_H

#include "netutil.h"

#include <stdint.h>

void relay_get_upstream_addr(struct sockaddr_in *addr);
int relay_is_from_upstream(const struct sockaddr_in *addr);
int relay_forward_query(socket_t sock,
                        uint8_t *query_buf,
                        int query_len,
                        const struct sockaddr_in *client_addr,
                        socklen_t client_len,
                        const char *domain);
int relay_handle_upstream_response(socket_t sock, uint8_t *response_buf, int response_len);

#endif
