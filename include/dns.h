#ifndef DNS_H
#define DNS_H

#include <stdint.h>

// DNS 固定头部长度，RFC 1035 中为 12 字节。
#define DNS_HEADER_SIZE 12

// UDP DNS 传统报文最大长度；本项目不处理 EDNS 扩展大包。
#define DNS_MAX_PACKET_SIZE 512

// 域名字符串最大长度，包含结尾 '\0' 的缓冲区空间。
#define DNS_MAX_DOMAIN_LEN 256

typedef struct {
    // DNS 报文 ID，用于匹配请求和响应。
    uint16_t id;
    // 点分形式域名，例如 www.example.com。
    char domain[DNS_MAX_DOMAIN_LEN];
    // 查询类型，A 记录为 1。
    uint16_t qtype;
    // 查询类，IN 为 1。
    uint16_t qclass;
} DNSQuery;

typedef struct {
    // DNS 响应 ID。
    uint16_t id;
    // 响应码，0 表示成功，3 表示 NXDOMAIN。
    uint16_t rcode;
    // Answer 区资源记录数量。
    uint16_t answer_count;
    // 是否从响应中解析到了 IPv4 A 记录。
    int has_a_record;
    // 主机字节序 IPv4 地址。
    uint32_t ipv4;
    // A 记录 TTL，单位秒。
    uint32_t ttl_sec;
} DNSResponse;

// 解析客户端 DNS 查询报文，成功返回 0。
int dns_parse_query(const uint8_t *buf, int len, DNSQuery *query);

// 构造一个递归 DNS 查询报文，返回报文长度并输出随机生成的 ID。
int dns_build_query(const char *domain, uint16_t qtype, uint8_t *outbuf, int outsize, uint16_t *out_id);

// 解析 DNS 响应头和第一个 A 记录，成功返回 0。
int dns_parse_response(const uint8_t *buf, int len, DNSResponse *response);

// 基于原始查询报文构造本地 A 记录响应，返回响应长度。
int dns_build_a_response(const uint8_t *query_buf, int query_len, uint32_t ip, uint8_t *outbuf, int outsize);

// 基于原始查询报文构造 NXDOMAIN 响应，通常用于本地拦截。
int dns_build_nxdomain_response(const uint8_t *query_buf, int query_len, uint8_t *outbuf, int outsize);

// 从 DNS 报文头部读取 ID；报文不足 2 字节时返回 0。
uint16_t dns_get_id(const uint8_t *buf, int len);

// 覆写 DNS 报文头部 ID；报文不足 2 字节时不做任何操作。
void dns_set_id(uint8_t *buf, int len, uint16_t id);

// 判断报文 QR 位是否表示响应。
int dns_is_response(const uint8_t *buf, int len);

// 从响应 Answer 区提取第一个 A 记录，不校验记录所属域名。
int dns_extract_first_a_record(const uint8_t *buf, int len, uint32_t *ip, uint32_t *ttl_sec);

// 从响应 Answer 区提取指定域名对应的第一个 A 记录。
int dns_extract_first_a_record_for_domain(const uint8_t *buf, int len, const char *domain, uint32_t *ip, uint32_t *ttl_sec);

// 校验上游响应中的 Question 是否与转发前记录的域名、类型和类别一致。
int dns_response_matches_question(const uint8_t *buf, int len, const char *domain, uint16_t qtype, uint16_t qclass);

#endif
