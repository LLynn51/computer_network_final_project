// table 在本地表(dnsrelay.txt)中查找域名
#include "table.h"

#include "dns.h"
#include "logger.h"
#include "netutil.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 本地域名表单行最大长度。
#define TABLE_LINE_LEN 512

// TableNode 以链表形式存储域名和对应ip
typedef struct TableNode {
    // 小写规范化后的域名。
    char domain[256];
    // 记录类型，支持 A 和 AAAA。
    uint16_t qtype;
    // 主机字节序IPv4地址；A记录中0表示拦截域名。
    uint32_t ip;
    // 网络字节序IPv6地址；AAAA记录中全0表示拦截域名。
    uint8_t ipv6[16];
    // 指向下一个表项。
    struct TableNode *next;
} TableNode;
// g_table 本地 DNS 表的链表头指针
static TableNode *g_table = NULL;

// trim_newline 辅助函数，去除行末换行符
static void trim_newline(char *s) {
    size_t len;
    if (s == NULL) {
        return;
    }
    len = strlen(s);
    // 换行符上兼容不同操作系统
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[--len] = '\0';
    }
}

// to_lower_ascii 辅助函数，将大写字母统一转换为小写字母
static void to_lower_ascii(char *s) {
    while (s != NULL && *s != '\0') {
        *s = (char)tolower((unsigned char)*s);
        s++;
    }
}

// parse_ip_literal 将 IPv4/IPv6 字面量解析为内部地址格式，成功返回1。
static int parse_ip_literal(const char *s, uint16_t *qtype, uint32_t *ip, uint8_t ipv6[16]) {
    struct in_addr addr4;
    struct in6_addr addr6;

    if (s == NULL || qtype == NULL || ip == NULL || ipv6 == NULL) {
        return 0;
    }

    if (inet_pton(AF_INET, s, &addr4) == 1) {
        *qtype = DNS_TYPE_A;
        *ip = ntohl(addr4.s_addr);
        memset(ipv6, 0, 16);
        return 1;
    }

    if (inet_pton(AF_INET6, s, &addr6) == 1) {
        *qtype = DNS_TYPE_AAAA;
        *ip = 0;
        memcpy(ipv6, &addr6, 16);
        return 1;
    }

    return 0;
}

// add_entry 将从本地表（磁盘）中读出的域名和ip信息填入 TableNode 链表（内存），便于处理
static int add_entry(const char *domain, uint16_t qtype, uint32_t ip, const uint8_t ipv6[16]) {
    // 创建新节点
    TableNode *node;
    // 检查传入信息（空域名）
    if (domain == NULL || domain[0] == '\0' || (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA)) {
        return -1;
    }
    // 分配空间并检查
    node = (TableNode *)malloc(sizeof(*node));
    if (node == NULL) {
        return -1;
    }
    // 将本地表中信息复制到TableNode节点中
    strncpy(node->domain, domain, sizeof(node->domain) - 1); // 复制域名
    node->domain[sizeof(node->domain) - 1] = '\0'; // 添结束符
    to_lower_ascii(node->domain); // 大小写转换 到此域名复制工作完成
    node->qtype = qtype;
    node->ip = ip; // 复制ip
    memset(node->ipv6, 0, sizeof(node->ipv6));
    if (qtype == DNS_TYPE_AAAA && ipv6 != NULL) {
        memcpy(node->ipv6, ipv6, sizeof(node->ipv6));
    }
    node->next = g_table; 
    g_table = node; // 头插法创建新节点
    // 成功读入内存则返回0
    return 0;
}

// table_free 操作完成后释放 TableNode 链表。
void table_free(void) {
    TableNode *node = g_table;
    while (node != NULL) {
        TableNode *next = node->next;
        free(node);
        node = next;
    }
    g_table = NULL;
}

// load_table 传入本地表路径，将其中内容读入内存处理
// 参数 filename 文件名
// 返回 count 成功读入的文件条数
int load_table(const char *filename) {
    FILE *fp;
    char line[TABLE_LINE_LEN];
    int count = 0;
    // 清空旧数据
    table_free();
    // 打开本地表并检查
    fp = fopen(filename, "r");
    if (fp == NULL) {
        log_warn("cannot open local table: %s", filename);
        return -1;
    }
    // 读取并解析每一行的数据，并存入内存
    while (fgets(line, sizeof(line), fp) != NULL) {
        char first[256];
        char second[256];// 本项目中，本地表支持"域名 ip"和"ip 域名"两种格式
        uint32_t ip;
        uint16_t qtype;
        uint8_t ipv6[16];
        const char *domain = NULL; // 临时存放数据
        // 去除换行符
        trim_newline(line);
        // 跳过空行和预处理指令
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        // 跳过缺项行
        if (sscanf(line, "%255s %255s", first, second) != 2) { // %255s 最多读入255个字符，预留一个字符给结束符 
            continue;
        }
        // 分别尝试在两种格式下解析域名，并检查
        if (parse_ip_literal(first, &qtype, &ip, ipv6)) {
            domain = second;
        } else if (parse_ip_literal(second, &qtype, &ip, ipv6)) {
            domain = first;
        } else {
            log_warn("skip invalid table line: %s", line);
            continue;
        }
        // 如果成功读入内存，增加计数器
        if (add_entry(domain, qtype, ip, ipv6) == 0) {
            count++;
        }
    }
    // 好习惯，关闭文件
    fclose(fp);
    // 打印调试信息
    log_info("loaded %d local DNS table entries", count);
    // 返回读入数据条数
    return count;
}
static int make_lookup_key(const char *domain, char *key, int key_size) {
    if (domain == NULL || key == NULL || key_size <= 0) {
        return -1;
    }

    strncpy(key, domain, (size_t)key_size - 1);
    key[key_size - 1] = '\0';
    to_lower_ascii(key);
    return 0;
}

// table_lookup_a 在本地表中查询domain对应IPv4地址。
int table_lookup_a(const char *domain, uint32_t *ip) {
    char key[256];
    TableNode *node;
    // 查询的信息本身为空，返回不存在
    if (domain == NULL || ip == NULL) {
        return 0;
    }
    if (make_lookup_key(domain, key, sizeof(key)) != 0) {
        return 0;
    }
    // 从本地表头指针开始在本地表中查询，命中则返回1。
    // 是否拦截由返回值和*ip共同判断：返回0表示未找到；返回1且*ip为0表示命中拦截规则。
    for (node = g_table; node != NULL; node = node->next) {
        if (node->qtype == DNS_TYPE_A && strcmp(node->domain, key) == 0) {
            *ip = node->ip; // 如果 *ip==0 ，说明是被拦截的域名；否则是正常返回的域名
            return 1;
        }
    }

    return 0;
}

// table_lookup_aaaa 在本地表中查询domain对应IPv6地址。
int table_lookup_aaaa(const char *domain, uint8_t ipv6[16]) {
    char key[256];
    TableNode *node;

    if (domain == NULL || ipv6 == NULL) {
        return 0;
    }
    if (make_lookup_key(domain, key, sizeof(key)) != 0) {
        return 0;
    }

    for (node = g_table; node != NULL; node = node->next) {
        if (node->qtype == DNS_TYPE_AAAA && strcmp(node->domain, key) == 0) {
            memcpy(ipv6, node->ipv6, 16);
            return 1;
        }
    }

    return 0;
}

// table_lookup 兼容旧接口：查询 A 记录。
int table_lookup(const char *domain, uint32_t *ip) {
    return table_lookup_a(domain, ip);
}
