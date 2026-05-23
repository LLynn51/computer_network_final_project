#ifndef DNS_H
#define DNS_H

#include <stdint.h>

#define DNS_HEADER_SIZE 12
#define DNS_MAX_PACKET_SIZE 512
#define DNS_MAX_DOMAIN_LEN 256

typedef struct {
    uint16_t id;
    char domain[DNS_MAX_DOMAIN_LEN];
    uint16_t qtype;
    uint16_t qclass;
} DNSQuery;

int dns_parse_query(const uint8_t *buf, int len, DNSQuery *query);

#endif
