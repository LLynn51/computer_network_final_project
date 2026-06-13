// dns.c 负责将recvfrom()收到的DNS二进制报文解析成程序内部容易使用的DNSQuery结构体
#include "dns.h"

#include "netutil.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// uint16_t 从网络（大端序）读取一个16位无符号整数
// 参数p 指向这两个字节的起始地址
static uint16_t read_u16_be(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

// write_u16_be 将16位无符号整数按网络字节序写入缓冲区。
static void write_u16_be(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)(value & 0xffu);
}

// write_u32_be 将32位无符号整数按网络字节序写入缓冲区。
static void write_u32_be(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)((value >> 16) & 0xffu);
    p[2] = (uint8_t)((value >> 8) & 0xffu);
    p[3] = (uint8_t)(value & 0xffu);
}

// skip_dns_name 跳过一个DNS NAME字段，支持普通label和压缩指针，返回下一个字段位置。
static int skip_dns_name(const uint8_t *buf, int len, int pos) {
    while (pos < len) {
        uint8_t label_len = buf[pos++];

        if (label_len == 0) {
            return pos;
        }

        if ((label_len & 0xC0u) == 0xC0u) {
            if (pos < len) {
                return pos + 1;
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

// domain_equal_ascii_ci 比较两个域名字符串是否相同，忽略ASCII大小写。
static int domain_equal_ascii_ci(const char *a, const char *b) {
    if (a == NULL || b == NULL) {
        return 0;
    }

    while (*a != '\0' && *b != '\0') {
        char ca = *a;
        char cb = *b;

        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return 0;
        }
        a++;
        b++;
    }

    return *a == '\0' && *b == '\0';
}

// read_dns_name_to_string 将DNS NAME字段解码成点分域名，并处理响应中的压缩指针。
static int read_dns_name_to_string(const uint8_t *buf, int len, int pos, char *out, int outsize, int *next_pos) {
    int cur = pos;
    int outpos = 0;
    int jumped = 0;
    int jump_count = 0;

    if (buf == NULL || out == NULL || outsize <= 0 || next_pos == NULL || pos < 0 || pos >= len) {
        return -1;
    }

    while (cur < len) {
        uint8_t label_len = buf[cur++];

        if (label_len == 0) {
            if (!jumped) {
                *next_pos = cur;
            }
            out[outpos] = '\0';
            return 0;
        }

        if ((label_len & 0xC0u) == 0xC0u) {
            int offset;
            if (cur >= len) {
                return -1;
            }
            offset = (int)(((label_len & 0x3Fu) << 8) | buf[cur++]);
            if (offset < DNS_HEADER_SIZE || offset >= len) {
                return -1;
            }
            if (!jumped) {
                *next_pos = cur;
            }
            cur = offset;
            jumped = 1;
            if (++jump_count > DNS_MAX_DOMAIN_LEN) {
                return -1;
            }
            continue;
        }

        if ((label_len & 0xC0u) != 0 || label_len > 63 || cur + label_len > len) {
            return -1;
        }

        if (outpos != 0) {
            if (outpos >= outsize - 1) {
                return -1;
            }
            out[outpos++] = '.';
        }

        if (outpos + label_len >= outsize) {
            return -1;
        }
        memcpy(out + outpos, buf + cur, label_len);
        outpos += label_len;
        cur += label_len;
    }

    return -1;
}

// write_qname 将点分域名写成DNS QNAME格式，例如 www.example.com -> 3www7example3com0。
static int write_qname(const char *domain, uint8_t *outbuf, int outsize, int pos) {
    const char *label_start = domain;
    const char *p = domain;

    if (domain == NULL || outbuf == NULL || pos < 0) {
        return -1;
    }

    while (1) {
        if (*p == '.' || *p == '\0') {
            int label_len = (int)(p - label_start);

            if (label_len <= 0 || label_len > 63 || pos + 1 + label_len >= outsize) {
                return -1;
            }

            outbuf[pos++] = (uint8_t)label_len;
            memcpy(outbuf + pos, label_start, (size_t)label_len);
            pos += label_len;

            if (*p == '\0') {
                break;
            }

            label_start = p + 1;
        }

        p++;
    }

    if (pos >= outsize) {
        return -1;
    }
    outbuf[pos++] = 0;
    return pos;
}

// copy_question_for_response 将原始查询中的Question规范化写入响应，避免压缩QNAME形成无效指针链。
static int copy_question_for_response(const uint8_t *query_buf, int query_len, uint8_t *outbuf, int outsize) {
    char domain[DNS_MAX_DOMAIN_LEN];
    int pos = DNS_HEADER_SIZE;
    int qtype_pos;

    if (query_buf == NULL || outbuf == NULL || query_len < DNS_HEADER_SIZE || outsize < DNS_HEADER_SIZE) {
        return -1;
    }
    if (read_u16_be(query_buf + 4) != 1) {
        return -1;
    }

    if (read_dns_name_to_string(query_buf, query_len, DNS_HEADER_SIZE, domain, sizeof(domain), &qtype_pos) != 0 ||
        domain[0] == '\0' || qtype_pos + 4 > query_len) {
        return -1;
    }

    memcpy(outbuf, query_buf, DNS_HEADER_SIZE);
    pos = write_qname(domain, outbuf, outsize, pos);
    if (pos < 0 || pos + 4 > outsize) {
        return -1;
    }

    memcpy(outbuf + pos, query_buf + qtype_pos, 4);
    return pos + 4;
}

// dns_parse_query 解析DNS报文
// 参数： buf recv_from()收到的报文原始数据
// len buf总长度，来自recvfrom返回值。因为网络数据不可信，所以需要时时检查以防越界。
// query 输出，解析后的结果
// 返回值： 0 合法 -1 非法
int dns_parse_query(const uint8_t *buf, int len, DNSQuery *query) {
    int pos = DNS_HEADER_SIZE;// pos 当前读到哪里（单位：字节）。由于仅解析域名，所以初始化为HEADER长度。
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
    if ((flags & 0x8000u) != 0 || qdcount != 1) {
        return -1;
    }


    // 解析QNAME，支持普通label和DNS压缩指针。
    if (read_dns_name_to_string(buf, len, pos, query->domain, sizeof(query->domain), &pos) != 0 ||
        query->domain[0] == '\0') {
        return -1;
    }

    // 检查QTYPE和QCLASS是否完整
    if (pos + 4 > len) {
        return -1;
    }

    // 添加QTYPE和QCLASS
    query->qtype = read_u16_be(buf + pos); // A=1 表示IPv4地址，AAAA=28 表示IPv6地址
    query->qclass = read_u16_be(buf + pos + 2); // 一般 IN （1） 表示 Internet
    // 解析成功，返回0
    return 0;
}

// dns_build_query 构建客户端测试程序使用的标准递归查询报文。
int dns_build_query(const char *domain, uint16_t qtype, uint8_t *outbuf, int outsize, uint16_t *out_id) {
    int pos = DNS_HEADER_SIZE;
    uint16_t id;

    if (domain == NULL || domain[0] == '\0' || outbuf == NULL || out_id == NULL || outsize < DNS_HEADER_SIZE + 5) {
        return -1;
    }

    memset(outbuf, 0, (size_t)outsize);
    id = (uint16_t)(net_now_ms() ^ (uint64_t)rand());
    *out_id = id;

    write_u16_be(outbuf, id);
    write_u16_be(outbuf + 2, 0x0100); // RD=1，普通递归查询
    write_u16_be(outbuf + 4, 1); // QDCOUNT
    write_u16_be(outbuf + 6, 0);
    write_u16_be(outbuf + 8, 0);
    write_u16_be(outbuf + 10, 0);

    pos = write_qname(domain, outbuf, outsize, pos);
    if (pos < 0 || pos + 4 > outsize) {
        return -1;
    }

    write_u16_be(outbuf + pos, qtype);
    pos += 2;
    write_u16_be(outbuf + pos, DNS_CLASS_IN); // QCLASS IN
    pos += 2;

    return pos;
}

// dns_build_a_response 构建本地合法响应
// 返回值： response_len
// 返回信息（以指针形式）：*outbuf 构造完成的完整合法响应
int dns_build_a_response(const uint8_t *query_buf, int query_len, uint32_t ip, uint8_t *outbuf, int outsize) {
    int question_end = copy_question_for_response(query_buf, query_len, outbuf, outsize);
    int pos;

    if (question_end < 0 || outbuf == NULL || outsize < question_end + 16) {
        return -1;
    }
    // 构造响应：先写入HEADER和规范化后的QUESTION部分
    // 根据响应性质，覆写flag字段
    // flags: QR=1, OPCODE沿用查询，AA=1，RD沿用查询，RA=0，RCODE=0
    outbuf[2] = (uint8_t)((query_buf[2] & 0x78u) | 0x84u | (query_buf[2] & 0x01u));
    // 分别覆写保留字段Z和各个COUNT字段
    outbuf[3] = 0x00;
    write_u16_be(outbuf + 4, 1); // QDCOUNT
    write_u16_be(outbuf + 6, 1); // ANCOUNT
    write_u16_be(outbuf + 8, 0); // NSCOUNT
    write_u16_be(outbuf + 10, 0); // ARCOUNT
    // 在QUESTION结尾追加ANSWER(指Resource Record Format，其中包含NAME TYPE CLASS TTL RDLENGTH RDATA)
    pos = question_end;
    write_u16_be(outbuf + pos, 0xC00C); // NAME 指向请求中的QNAME
    // 在当前构造方式下可以固定为 0xC00C。因为DNS Header固定12字节，QNAME从偏移量12开始；
    // 0xC00C中第一个C意为NAME字段为DNS压缩指针而非domain字符串；第二个C意思是“NAME字段指向偏移12处的域名”。
    // 可以避免重复写入domain，直接去DNS Header中读取
    pos += 2;
    write_u16_be(outbuf + pos, DNS_TYPE_A); // TYPE A
    pos += 2;
    write_u16_be(outbuf + pos, DNS_CLASS_IN); // CLASS IN
    pos += 2;
    write_u32_be(outbuf + pos, 60); // TTL。客户程序保留该资源记录的秒数。
    // TODO:完善缓存机制
    pos += 4;
    write_u16_be(outbuf + pos, 4); // RDLENGTH。资源数据的字节数，对类型1（TYPE A记录）资源数据是4字节的I P地址
    pos += 2;
    write_u32_be(outbuf + pos, ip); // RDATA IPv4，内部ip使用主机字节序
    pos += 4;

    return pos;
}

// dns_build_aaaa_response 构建本地AAAA响应。
int dns_build_aaaa_response(const uint8_t *query_buf, int query_len, const uint8_t ipv6[16], uint8_t *outbuf, int outsize) {
    int question_end = copy_question_for_response(query_buf, query_len, outbuf, outsize);
    int pos;

    if (question_end < 0 || ipv6 == NULL || outbuf == NULL || outsize < question_end + 28) {
        return -1;
    }

    outbuf[2] = (uint8_t)((query_buf[2] & 0x78u) | 0x84u | (query_buf[2] & 0x01u));
    outbuf[3] = 0x00;
    write_u16_be(outbuf + 4, 1); // QDCOUNT
    write_u16_be(outbuf + 6, 1); // ANCOUNT
    write_u16_be(outbuf + 8, 0); // NSCOUNT
    write_u16_be(outbuf + 10, 0); // ARCOUNT

    pos = question_end;
    write_u16_be(outbuf + pos, 0xC00C); // NAME 指向请求中的QNAME
    pos += 2;
    write_u16_be(outbuf + pos, DNS_TYPE_AAAA); // TYPE AAAA
    pos += 2;
    write_u16_be(outbuf + pos, DNS_CLASS_IN); // CLASS IN
    pos += 2;
    write_u32_be(outbuf + pos, 60); // TTL
    pos += 4;
    write_u16_be(outbuf + pos, 16); // RDLENGTH
    pos += 2;
    memcpy(outbuf + pos, ipv6, 16); // RDATA IPv6，网络字节序16字节
    pos += 16;

    return pos;
}
// dns_build_nxdomain_response 对于本地被拦截的域名构建NXDOMAIN响应
// 大体与上面的合法响应相同。区别是因为没有合法响应，所以不需构造ANSWER部分。
int dns_build_nxdomain_response(const uint8_t *query_buf, int query_len, uint8_t *outbuf, int outsize) {
    int question_end = copy_question_for_response(query_buf, query_len, outbuf, outsize);

    if (question_end < 0 || outbuf == NULL || outsize < question_end) {
        return -1;
    }

    // flags: QR=1, AA=1，RCODE=3(NXDOMAIN)
    outbuf[2] = (uint8_t)((query_buf[2] & 0x78u) | 0x84u | (query_buf[2] & 0x01u));
    outbuf[3] = DNS_RCODE_NXDOMAIN;
    // 更新各个COUNT字段
    write_u16_be(outbuf + 4, 1);
    write_u16_be(outbuf + 6, 0);// 与合法响应不同的是ANCOUNT为0（没有合法回答） 
    write_u16_be(outbuf + 8, 0);
    write_u16_be(outbuf + 10, 0);

    return question_end;
}

// dns_build_error_response 构造无Answer的错误响应，用于上游超时等情况。
int dns_build_error_response(const uint8_t *query_buf, int query_len, uint16_t rcode, uint8_t *outbuf, int outsize) {
    int question_end = copy_question_for_response(query_buf, query_len, outbuf, outsize);

    if (question_end < 0 || outbuf == NULL || outsize < question_end || rcode > 15) {
        return -1;
    }

    // flags: QR=1，保留OPCODE和RD，AA/RA均为0，低4位写入RCODE。
    outbuf[2] = (uint8_t)((query_buf[2] & 0x79u) | 0x80u);
    outbuf[3] = (uint8_t)(rcode & 0x0fu);
    write_u16_be(outbuf + 4, 1);
    write_u16_be(outbuf + 6, 0);
    write_u16_be(outbuf + 8, 0);
    write_u16_be(outbuf + 10, 0);

    return question_end;
}

// dns_build_ptr_response 构造一个本地 PTR 响应，例如 1.0.0.127.in-addr.arpa -> localhost。
int dns_build_ptr_response(const uint8_t *query_buf, int query_len, const char *ptr_domain, uint8_t *outbuf, int outsize) {
    int question_end = copy_question_for_response(query_buf, query_len, outbuf, outsize);
    int pos;
    int rdlength_pos;

    if (question_end < 0 || ptr_domain == NULL || ptr_domain[0] == '\0' || outbuf == NULL || outsize < question_end + 12) {
        return -1;
    }

    // flags: QR=1, AA=1, RD沿用查询, RCODE=0。
    outbuf[2] = (uint8_t)((query_buf[2] & 0x78u) | 0x84u | (query_buf[2] & 0x01u));
    outbuf[3] = 0x00;
    write_u16_be(outbuf + 4, 1);
    write_u16_be(outbuf + 6, 1);
    write_u16_be(outbuf + 8, 0);
    write_u16_be(outbuf + 10, 0);

    pos = question_end;
    if (pos + 12 > outsize) {
        return -1;
    }
    write_u16_be(outbuf + pos, 0xC00C); // Answer NAME 指向原始QNAME。
    pos += 2;
    write_u16_be(outbuf + pos, DNS_TYPE_PTR); // TYPE PTR
    pos += 2;
    write_u16_be(outbuf + pos, DNS_CLASS_IN); // CLASS IN
    pos += 2;
    write_u32_be(outbuf + pos, 60);
    pos += 4;
    rdlength_pos = pos;
    pos += 2;

    pos = write_qname(ptr_domain, outbuf, outsize, pos);
    if (pos < 0) {
        return -1;
    }
    write_u16_be(outbuf + rdlength_pos, (uint16_t)(pos - rdlength_pos - 2));

    return pos;
}
// dns_get_id 从上游响应内容中读取上游id
uint16_t dns_get_id(const uint8_t *buf, int len) {
    if (buf == NULL || len < 2) {
        return 0;
    }
    return read_u16_be(buf);
}
// dns_set_id 实现修改id
void dns_set_id(uint8_t *buf, int len, uint16_t id) {
    if (buf == NULL || len < 2) {
        return;
    }
    write_u16_be(buf, id);
}
// dns_is_response 检查传入内容是response还是query
int dns_is_response(const uint8_t *buf, int len) {
    if (buf == NULL || len < 4) {
        return 0;
    }
    return (read_u16_be(buf + 2) & 0x8000u) != 0;
}

// dns_extract_first_a_record 从任意成功响应中取出第一个IPv4 A记录和TTL。
int dns_extract_first_a_record(const uint8_t *buf, int len, uint32_t *ip, uint32_t *ttl_sec) {
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    int pos;
    int i;

    if (buf == NULL || ip == NULL || ttl_sec == NULL || len < DNS_HEADER_SIZE) {
        return 0;
    }

    flags = read_u16_be(buf + 2);
    qdcount = read_u16_be(buf + 4);
    ancount = read_u16_be(buf + 6);

    if ((flags & 0x8000u) == 0 || (flags & 0x000fu) != 0 || qdcount == 0 || ancount == 0) {
        return 0;
    }

    pos = DNS_HEADER_SIZE;
    for (i = 0; i < qdcount; i++) {
        pos = skip_dns_name(buf, len, pos);
        if (pos < 0 || pos + 4 > len) {
            return 0;
        }
        pos += 4;
    }

    for (i = 0; i < ancount; i++) {
        uint16_t type;
        uint16_t class_value;
        uint16_t rdlength;
        uint32_t ttl;

        pos = skip_dns_name(buf, len, pos);
        if (pos < 0 || pos + 10 > len) {
            return 0;
        }

        type = read_u16_be(buf + pos);
        class_value = read_u16_be(buf + pos + 2);
        ttl = ((uint32_t)buf[pos + 4] << 24) |
              ((uint32_t)buf[pos + 5] << 16) |
              ((uint32_t)buf[pos + 6] << 8) |
              (uint32_t)buf[pos + 7];
        rdlength = read_u16_be(buf + pos + 8);
        pos += 10;

        if (pos + rdlength > len) {
            return 0;
        }

        if (type == DNS_TYPE_A && class_value == DNS_CLASS_IN && rdlength == 4) {
            *ip = ((uint32_t)buf[pos] << 24) |
                  ((uint32_t)buf[pos + 1] << 16) |
                  ((uint32_t)buf[pos + 2] << 8) |
                  (uint32_t)buf[pos + 3];
            *ttl_sec = ttl;
            return 1;
        }

        pos += rdlength;
    }

    return 0;
}

// dns_extract_first_a_record_for_domain 只缓存owner name与原查询域名一致的A记录。
int dns_extract_first_a_record_for_domain(const uint8_t *buf, int len, const char *domain, uint32_t *ip, uint32_t *ttl_sec) {
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    int pos;
    int i;

    if (buf == NULL || domain == NULL || ip == NULL || ttl_sec == NULL || len < DNS_HEADER_SIZE) {
        return 0;
    }

    flags = read_u16_be(buf + 2);
    qdcount = read_u16_be(buf + 4);
    ancount = read_u16_be(buf + 6);

    if ((flags & 0x8000u) == 0 || (flags & 0x000fu) != 0 || qdcount == 0 || ancount == 0) {
        return 0;
    }

    pos = DNS_HEADER_SIZE;
    for (i = 0; i < qdcount; i++) {
        pos = skip_dns_name(buf, len, pos);
        if (pos < 0 || pos + 4 > len) {
            return 0;
        }
        pos += 4;
    }

    for (i = 0; i < ancount; i++) {
        char owner[DNS_MAX_DOMAIN_LEN];
        uint16_t type;
        uint16_t class_value;
        uint16_t rdlength;
        uint32_t ttl;

        if (read_dns_name_to_string(buf, len, pos, owner, sizeof(owner), &pos) != 0) {
            return 0;
        }
        if (pos + 10 > len) {
            return 0;
        }

        type = read_u16_be(buf + pos);
        class_value = read_u16_be(buf + pos + 2);
        ttl = ((uint32_t)buf[pos + 4] << 24) |
              ((uint32_t)buf[pos + 5] << 16) |
              ((uint32_t)buf[pos + 6] << 8) |
              (uint32_t)buf[pos + 7];
        rdlength = read_u16_be(buf + pos + 8);
        pos += 10;

        if (pos + rdlength > len) {
            return 0;
        }

        if (type == DNS_TYPE_A && class_value == DNS_CLASS_IN && rdlength == 4 && domain_equal_ascii_ci(owner, domain)) {
            *ip = ((uint32_t)buf[pos] << 24) |
                  ((uint32_t)buf[pos + 1] << 16) |
                  ((uint32_t)buf[pos + 2] << 8) |
                  (uint32_t)buf[pos + 3];
            *ttl_sec = ttl;
            return 1;
        }

        pos += rdlength;
    }

    return 0;
}

// dns_extract_first_aaaa_record_for_domain 只缓存owner name与原查询域名一致的AAAA记录。
int dns_extract_first_aaaa_record_for_domain(const uint8_t *buf, int len, const char *domain, uint8_t ipv6[16], uint32_t *ttl_sec) {
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    int pos;
    int i;

    if (buf == NULL || domain == NULL || ipv6 == NULL || ttl_sec == NULL || len < DNS_HEADER_SIZE) {
        return 0;
    }

    flags = read_u16_be(buf + 2);
    qdcount = read_u16_be(buf + 4);
    ancount = read_u16_be(buf + 6);

    if ((flags & 0x8000u) == 0 || (flags & 0x000fu) != 0 || qdcount == 0 || ancount == 0) {
        return 0;
    }

    pos = DNS_HEADER_SIZE;
    for (i = 0; i < qdcount; i++) {
        pos = skip_dns_name(buf, len, pos);
        if (pos < 0 || pos + 4 > len) {
            return 0;
        }
        pos += 4;
    }

    for (i = 0; i < ancount; i++) {
        char owner[DNS_MAX_DOMAIN_LEN];
        uint16_t type;
        uint16_t class_value;
        uint16_t rdlength;
        uint32_t ttl;

        if (read_dns_name_to_string(buf, len, pos, owner, sizeof(owner), &pos) != 0) {
            return 0;
        }
        if (pos + 10 > len) {
            return 0;
        }

        type = read_u16_be(buf + pos);
        class_value = read_u16_be(buf + pos + 2);
        ttl = ((uint32_t)buf[pos + 4] << 24) |
              ((uint32_t)buf[pos + 5] << 16) |
              ((uint32_t)buf[pos + 6] << 8) |
              (uint32_t)buf[pos + 7];
        rdlength = read_u16_be(buf + pos + 8);
        pos += 10;

        if (pos + rdlength > len) {
            return 0;
        }

        if (type == DNS_TYPE_AAAA && class_value == DNS_CLASS_IN && rdlength == 16 && domain_equal_ascii_ci(owner, domain)) {
            memcpy(ipv6, buf + pos, 16);
            *ttl_sec = ttl;
            return 1;
        }

        pos += rdlength;
    }

    return 0;
}

// dns_response_matches_question 校验上游响应没有串包或被异常篡改。
int dns_response_matches_question(const uint8_t *buf, int len, const char *domain, uint16_t qtype, uint16_t qclass) {
    uint16_t flags;
    uint16_t qdcount;
    char qname[DNS_MAX_DOMAIN_LEN];
    int pos;

    if (buf == NULL || domain == NULL || len < DNS_HEADER_SIZE) {
        return 0;
    }

    flags = read_u16_be(buf + 2);
    qdcount = read_u16_be(buf + 4);
    if ((flags & 0x8000u) == 0 || qdcount != 1) {
        return 0;
    }

    if (read_dns_name_to_string(buf, len, DNS_HEADER_SIZE, qname, sizeof(qname), &pos) != 0) {
        return 0;
    }
    if (pos + 4 > len) {
        return 0;
    }

    return domain_equal_ascii_ci(qname, domain) &&
           read_u16_be(buf + pos) == qtype &&
           read_u16_be(buf + pos + 2) == qclass;
}

// dns_parse_response 解析客户端关心的响应摘要，用于Client程序展示查询结果。
int dns_parse_response(const uint8_t *buf, int len, DNSResponse *response) {
    uint16_t flags;

    if (buf == NULL || response == NULL || len < DNS_HEADER_SIZE) {
        return -1;
    }

    memset(response, 0, sizeof(*response));
    response->id = read_u16_be(buf);
    flags = read_u16_be(buf + 2);

    if ((flags & 0x8000u) == 0) {
        return -1;
    }

    response->rcode = (uint16_t)(flags & 0x000fu);
    response->answer_count = read_u16_be(buf + 6);
    response->has_a_record = dns_extract_first_a_record(buf, len, &response->ipv4, &response->ttl_sec);
    return 0;
}
