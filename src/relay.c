#include "relay.h"

#include "logger.h"
#include "netutil.h"

#include <string.h>

#define UPSTREAM_DNS_IP "8.8.8.8" // 默认上游DNS服务器ip
#define UPSTREAM_DNS_PORT 53
#define UPSTREAM_TIMEOUT_MS 3000

// relay_forward_query 与上游 DNS 服务器通信。
// TODO：现在每次转发都要新建一个 socket ，与老师“不建议使用两个socket”的要求冲突。后续需要换成 “复用主socket+ID映射”
// 参数 query_buf 客户端发来的原始DNS查询报文 query_len 报文长度
// response_buf 保留上游DNS相应的缓冲区 response_size 缓冲区的最大容量
int relay_forward_query(const uint8_t *query_buf, int query_len, uint8_t *response_buf, int response_size) {
    socket_t upstream_sock;
    struct sockaddr_in upstream_addr;
    socklen_t upstream_len = sizeof(upstream_addr);
    int n;

    if (query_buf == NULL || query_len <= 0 || response_buf == NULL || response_size <= 0) {
        return -1;
    }

    // 创建一个临时UDP socket 与上游DNS服务器通信
    upstream_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (upstream_sock == SOCKET_INVALID) {
        log_warn("create upstream socket failed");
        return -1;
    }

#ifdef _WIN32
    {   // 设置超时时长，避免接收不到包时一直卡在 recvfrom 函数中
        DWORD timeout = UPSTREAM_TIMEOUT_MS;
        setsockopt(upstream_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    }
#else
    {
        struct timeval timeout;
        timeout.tv_sec = UPSTREAM_TIMEOUT_MS / 1000;
        timeout.tv_usec = (UPSTREAM_TIMEOUT_MS % 1000) * 1000;
        setsockopt(upstream_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    }
#endif
    // 填写上游DNS服务器地址，并检查
    memset(&upstream_addr, 0, sizeof(upstream_addr));
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(UPSTREAM_DNS_PORT);
    upstream_addr.sin_addr.s_addr = inet_addr(UPSTREAM_DNS_IP);
    if (upstream_addr.sin_addr.s_addr == INADDR_NONE) {
        socket_close(upstream_sock);
        return -1;
    }

    // 将客户端请求原样发送给上游DNS服务器，并检查
    n = (int)sendto(upstream_sock, (const char *)query_buf, query_len, 0,
                   (struct sockaddr *)&upstream_addr, sizeof(upstream_addr));
    if (n != query_len) {
        log_warn("send query to upstream failed");
        socket_close(upstream_sock);
        return -1;
    }

    // 等待上游DNS返回响应
    n = (int)recvfrom(upstream_sock, (char *)response_buf, response_size, 0,
                     (struct sockaddr *)&upstream_addr, &upstream_len);
    socket_close(upstream_sock);
    if (n <= 0) {
        log_warn("upstream dns timeout or recv failed");
        return -1;
    }
    // 此时 respons_buf 中存储的是上游转发的完整报文，可以直接转发给客户端
    return n;
}
