#include "dns.h"

#include <stddef.h>
#include <string.h>

static uint16_t read_u16_be(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

int dns_parse_query(const uint8_t *buf, int len, DNSQuery *query) {
    int pos = DNS_HEADER_SIZE;
    int out = 0;
    uint16_t flags;
    uint16_t qdcount;

    if (buf == NULL || query == NULL || len < DNS_HEADER_SIZE) {
        return -1;
    }

    memset(query, 0, sizeof(*query));
    query->id = read_u16_be(buf);
    flags = read_u16_be(buf + 2);
    qdcount = read_u16_be(buf + 4);

    if ((flags & 0x8000u) != 0 || qdcount == 0) {
        return -1;
    }

    while (pos < len) {
        uint8_t label_len = buf[pos++];

        if (label_len == 0) {
            break;
        }

        if ((label_len & 0xC0u) != 0) {
            return -1;
        }

        if (label_len > 63 || pos + label_len > len) {
            return -1;
        }

        if (out != 0) {
            if (out >= DNS_MAX_DOMAIN_LEN - 1) {
                return -1;
            }
            query->domain[out++] = '.';
        }

        if (out + label_len >= DNS_MAX_DOMAIN_LEN) {
            return -1;
        }

        memcpy(query->domain + out, buf + pos, label_len);
        out += label_len;
        pos += label_len;
    }

    if (pos > len || out == 0) {
        return -1;
    }

    if (pos + 4 > len) {
        return -1;
    }

    query->domain[out] = '\0';
    query->qtype = read_u16_be(buf + pos);
    query->qclass = read_u16_be(buf + pos + 2);

    return 0;
}
