#include "netutil.h"

#include "logger.h"

#include <stdio.h>
#include <string.h>

int net_init(void) {
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        log_error("WSAStartup failed");
        return -1;
    }
#endif
    return 0;
}

void net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

socket_t udp_bind_socket(uint16_t port) {
    socket_t sock;
    struct sockaddr_in addr;
    int reuse = 1;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == SOCKET_INVALID) {
        log_error("socket creation failed");
        return SOCKET_INVALID;
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        log_error("bind failed on UDP port %u", port);
        socket_close(sock);
        return SOCKET_INVALID;
    }

    return sock;
}

const char *sockaddr_to_string(const struct sockaddr_in *addr, char *buf, int buflen) {
    const char *ip = NULL;

    if (addr == NULL || buf == NULL || buflen <= 0) {
        return "";
    }

    ip = inet_ntop(AF_INET, &addr->sin_addr, buf, (socklen_t)buflen);
    if (ip == NULL) {
        snprintf(buf, (size_t)buflen, "<invalid>");
    }

    return buf;
}
