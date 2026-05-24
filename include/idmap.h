#ifndef IDMAP_H
#define IDMAP_H

#include "netutil.h"

#include <stdint.h>

void idmap_init(void);
int idmap_add(uint16_t client_id,
              const struct sockaddr_in *client_addr,
              socklen_t client_len,
              const char *domain,
              uint16_t *upstream_id);
int idmap_find(uint16_t upstream_id,
               uint16_t *client_id,
               struct sockaddr_in *client_addr,
               socklen_t *client_len);
void idmap_remove(uint16_t upstream_id);

#endif
