#ifndef RELAY_H
#define RELAY_H

#include <stdint.h>

int relay_forward_query(const uint8_t *query_buf, int query_len, uint8_t *response_buf, int response_size);

#endif
