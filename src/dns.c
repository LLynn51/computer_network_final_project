// dns.c 负责将recvfrom()收到的DNS二进制报文解析成程序内部容易使用的DNSQuery结构体
#include "dns.h"

#include <stddef.h>
#include <string.h>

// uint16_t 从网络（大端序）读取一个16位无符号整数
// 参数p 指向这两个字节的起始地址
static uint16_t read_u16_be(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void write_u16_be(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)(value & 0xffu);
}

static void write_u32_be(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)((value >> 16) & 0xffu);
    p[2] = (uint8_t)((value >> 8) & 0xffu);
    p[3] = (uint8_t)(value & 0xffu);
}
// find_question_end 返回 Question 结束后的第一个字节下标
// 因为构造响应时需要原样复制HEADER和Question，再在结尾追加Answer
static int find_question_end(const uint8_t *buf, int len) {
    int pos = DNS_HEADER_SIZE;

    if (buf == NULL || len < DNS_HEADER_SIZE) {
        return -1;
    }

    while (pos < len) {
        uint8_t label_len = buf[pos++];

        if (label_len == 0) {
            if (pos + 4 <= len) {
                return pos + 4;
            }
            return -1;
        }

        if ((label_len & 0xC0u) != 0 || label_len > 63 || pos + label_len > len) {
            return -1;
        }

        pos += label_len;
    }

    return -1;
}

// dns_parse_query 解析DNS报文
// 参数： buf recv_from()收到的报文原始数据
// len buf总长度，来自recvfrom返回值。因为网络数据不可信，所以需要时时检查以防越界。
// query 输出，解析后的结果
// 返回值： 0 合法 -1 非法
int dns_parse_query(const uint8_t *buf, int len, DNSQuery *query) {
    int pos = DNS_HEADER_SIZE;// pos 当前读到哪里（单位：字节）。由于仅解析域名，所以初始化为HEADER长度。
    int out = 0; // out 当前已经向 query->domain写入字符的数量
    uint16_t flags; // HEADER中的flag字段，包括 QR、OPCODE、AA……
    uint16_t qdcount; // 询问的数量（通常为1）

    // 校验传入为空和len小于HEADER长度（包损坏）的情况
    if (buf == NULL || query == NULL || len < DNS_HEADER_SIZE) {
        return -1;
    }
    // 清空query字段以免干扰写入
    // 依次读入数据
    memset(query, 0, sizeof(*query));
    query->id = read_u16_be(buf);
    flags = read_u16_be(buf + 2);
    qdcount = read_u16_be(buf + 4);
    // 查询QR位是否为0（Query）。由于目前程序只处理Query，因此不是Query视为非法请求。
    // 同时query数量不能为0
    if ((flags & 0x8000u) != 0 || qdcount == 0) {
        return -1;
    }


    // 最关键的QNAME解析主循环
    while (pos < len) { // pos >= len 说明读到包末尾，应该停止。
        // 假设客户端输入的域名为www.baidu.com，那么DNS域名格式实际为3www5baidu3com0
        // 每次首先读入字符长度，再根据长度读入相应数量的字符，从而实现字符串解析
        uint8_t label_len = buf[pos++];

        // return -1 表示包非法，需要立刻停止接收； break 代表当前循环结束但包依然合法。

        if (label_len == 0) { // DNS域名格式以0作为结束符
            break;
        }
        // 起步阶段直接拒绝DNS压缩格式，留到后面实现
        if ((label_len & 0xC0u) != 0) {
            return -1;
        }

        if (label_len > 63 || pos + label_len > len) { // 防止 label 越界 或 label_len 越界（包损坏）
            return -1;
        }

        // 如果不是第一个label，需要在读入label_len后加'.'
        if (out != 0) {
            // 越界检查
            if (out >= DNS_MAX_DOMAIN_LEN - 1) {
                return -1;
            }
            query->domain[out++] = '.';
        }

        // 越界检查
        if (out + label_len >= DNS_MAX_DOMAIN_LEN) {
            return -1;
        }

        // 从报文复制字符串到domain
        memcpy(query->domain + out, buf + pos, label_len);
        // 指针各自移动
        out += label_len;
        pos += label_len;
    }

    // 检查读越界/域名为空
    if (pos > len || out == 0) {
        return -1;
    }

    // 检查QTYPE和QCLASS是否完整
    if (pos + 4 > len) {
        return -1;
    }

    // 在域名结尾添加'\0'结束符使其成为真正的字符串
    query->domain[out] = '\0';
    // 添加QTYPE和QCLASS
    query->qtype = read_u16_be(buf + pos); // 一般 A（1） 表示IPv4地址
    query->qclass = read_u16_be(buf + pos + 2); // 一般 IN （1） 表示 Internet
    // 解析成功，返回0
    return 0;
}
// dns_build_a_response 构建本地合法响应
int dns_build_a_response(const uint8_t *query_buf, int query_len, uint32_t ip, uint8_t *outbuf, int outsize) {
    int question_end = find_question_end(query_buf, query_len);
    int pos;

    if (question_end < 0 || outbuf == NULL || outsize < question_end + 16) {
        return -1;
    }

    memcpy(outbuf, query_buf, (size_t)question_end);

    // flags: QR=1, OPCODE沿用查询，AA=1，RD沿用查询，RA=0，RCODE=0
    outbuf[2] = (uint8_t)((query_buf[2] & 0x78u) | 0x84u | (query_buf[2] & 0x01u));
    outbuf[3] = 0x00;
    write_u16_be(outbuf + 4, 1); // QDCOUNT
    write_u16_be(outbuf + 6, 1); // ANCOUNT
    write_u16_be(outbuf + 8, 0); // NSCOUNT
    write_u16_be(outbuf + 10, 0); // ARCOUNT

    pos = question_end;
    write_u16_be(outbuf + pos, 0xC00C); // NAME 指向请求中的QNAME
    pos += 2;
    write_u16_be(outbuf + pos, 1); // TYPE A
    pos += 2;
    write_u16_be(outbuf + pos, 1); // CLASS IN
    pos += 2;
    write_u32_be(outbuf + pos, 60); // TTL
    pos += 4;
    write_u16_be(outbuf + pos, 4); // RDLENGTH
    pos += 2;
    write_u32_be(outbuf + pos, ip); // RDATA IPv4，ip必须已经是网络字节序
    pos += 4;

    return pos;
}
// dns_build_nxdomain_response 对于本地被拦截的域名构建相应
int dns_build_nxdomain_response(const uint8_t *query_buf, int query_len, uint8_t *outbuf, int outsize) {
    int question_end = find_question_end(query_buf, query_len);

    if (question_end < 0 || outbuf == NULL || outsize < question_end) {
        return -1;
    }

    memcpy(outbuf, query_buf, (size_t)question_end);

    // flags: QR=1, AA=1，RCODE=3(NXDOMAIN)
    outbuf[2] = (uint8_t)((query_buf[2] & 0x78u) | 0x84u | (query_buf[2] & 0x01u));
    outbuf[3] = 0x03;
    write_u16_be(outbuf + 4, 1);
    write_u16_be(outbuf + 6, 0);
    write_u16_be(outbuf + 8, 0);
    write_u16_be(outbuf + 10, 0);

    return question_end;
}
