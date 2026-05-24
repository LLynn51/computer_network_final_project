// netutil.c 负责网络层接口封装（socket创建，bind端口，网络初始化）
#include "netutil.h"

#include "logger.h"

#include <stdio.h>
#include <string.h>

// net_init Windows系统下需要初始化
int net_init(void) {
#ifdef _WIN32
    WSADATA wsa_data;
    // 请求WinSock 2.2版本，WSAStartup初始化Windows网络子系统
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        log_error("WSAStartup failed");
        return -1;
    }
#endif
    return 0;
}

// net_cleanup Windows系统下清理socket环境
void net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

// udp_bind_socket 创建UDP socket并bind指定端口
// 参数 port 要返回的端口
// 返回值 socket_fd：成功 -1：失败
socket_t udp_bind_socket(uint16_t port) {
    socket_t sock;
    struct sockaddr_in addr;
    int reuse = 1;
    // 创建IPv4 UDP UDP协议 socket
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == SOCKET_INVALID) {
        log_error("socket creation failed");
        return SOCKET_INVALID;
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

    // 清空addr结构
    memset(&addr, 0, sizeof(addr));
    // 配置IPv4地址结构
    addr.sin_family = AF_INET; // 地址族为IPv4
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // 监听所有端口
    addr.sin_port = htons(port); // 将主机字节序转化为网络字节序
    // 尝试bind端口。常见失败原因有端口已被占用/权限不足
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        log_error("bind failed on UDP port %u", port);
        #ifdef _WIN32
        closesocket(sock);
        #else
        close(sock);
        #endif
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
