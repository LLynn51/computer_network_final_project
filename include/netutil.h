#ifndef NETUTIL_H
#define NETUTIL_H

#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#define SOCKET_INVALID INVALID_SOCKET
#define socket_close closesocket
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int socket_t;
#define SOCKET_INVALID (-1)
#define socket_close close
#endif

int net_init(void);
void net_cleanup(void);
socket_t udp_bind_socket(uint16_t port);
const char *sockaddr_to_string(const struct sockaddr_in *addr, char *buf, int buflen);

#endif
