#ifndef NETUTIL_H
#define NETUTIL_H

#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
// Windows 下 socket 句柄类型。
typedef SOCKET socket_t;
// 跨平台 socket 无效值。
#define SOCKET_INVALID INVALID_SOCKET
// 跨平台 socket 关闭函数。
#define socket_close closesocket
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
// Unix-like 系统下 socket 文件描述符类型。
typedef int socket_t;
// 跨平台 socket 无效值。
#define SOCKET_INVALID (-1)
// 跨平台 socket 关闭函数。
#define socket_close close
#endif

// 初始化平台网络库；Windows 下会调用 WSAStartup。
int net_init(void);

// 清理平台网络库；Windows 下会调用 WSACleanup。
void net_cleanup(void);

// 创建 UDP socket 并绑定到指定本地端口。
socket_t udp_bind_socket(uint16_t port);

// 将 IPv4 socket 地址转换为点分十进制字符串。
const char *sockaddr_to_string(const struct sockaddr_in *addr, char *buf, int buflen);

// 使用 select() 等待 socket 可读；返回 1 可读、0 超时、-1 失败。
int net_wait_readable(socket_t sock, int timeout_ms);

// 返回单调递增毫秒时间，用于超时和 TTL 计算。
uint64_t net_now_ms(void);

#endif
