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
int dns_build_a_response(const uint8_t *query_buf, int query_len, uint32_t ip, uint8_t *outbuf, int outsize);
int dns_build_nxdomain_response(const uint8_t *query_buf, int query_len, uint8_t *outbuf, int outsize);
uint16_t dns_get_id(const uint8_t *buf, int len);
void dns_set_id(uint8_t *buf, int len, uint16_t id);
int dns_is_response(const uint8_t *buf, int len);

#endif
