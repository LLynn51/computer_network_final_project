#include "dns.h"
#include "logger.h"
#include "netutil.h"

#include <stdint.h>
#include <stdlib.h>

#define DEFAULT_DNS_PORT 5353

static uint16_t parse_port(int argc, char **argv) {
    long port;

    if (argc < 2) {
        return DEFAULT_DNS_PORT;
    }

    port = strtol(argv[1], NULL, 10);
    if (port <= 0 || port > 65535) {
        log_warn("invalid port '%s', use default port %d", argv[1], DEFAULT_DNS_PORT);
        return DEFAULT_DNS_PORT;
    }

    return (uint16_t)port;
}

int main(int argc, char **argv) {
    uint16_t port = parse_port(argc, argv);
    socket_t sock;
    uint8_t buf[DNS_MAX_PACKET_SIZE];

    if (net_init() != 0) {
        return 1;
    }

    sock = udp_bind_socket(port);
    if (sock == SOCKET_INVALID) {
        net_cleanup();
        return 1;
    }

    log_info("DNS relay listening on UDP port %u", port);

    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int n;
        DNSQuery query;
        char client_ip[64];

        n = (int)recvfrom(sock, (char *)buf, sizeof(buf), 0,
                         (struct sockaddr *)&client_addr, &client_len);
        if (n <= 0) {
            log_warn("recvfrom failed");
            continue;
        }

        if (dns_parse_query(buf, n, &query) != 0) {
            log_warn("invalid dns packet from %s:%u len=%d",
                     sockaddr_to_string(&client_addr, client_ip, sizeof(client_ip)),
                     ntohs(client_addr.sin_port),
                     n);
            continue;
        }

        log_info("query client=%s:%u id=%u domain=%s qtype=%u qclass=%u",
                 sockaddr_to_string(&client_addr, client_ip, sizeof(client_ip)),
                 ntohs(client_addr.sin_port),
                 query.id,
                 query.domain,
                 query.qtype,
                 query.qclass);
    }

    socket_close(sock);
    net_cleanup();
    return 0;
}
