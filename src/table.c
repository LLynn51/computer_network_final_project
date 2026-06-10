// table 在本地表(dnsrelay.txt)中查找域名
#include "table.h"

#include "logger.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

// 本地域名表单行最大长度。
#define TABLE_LINE_LEN 512

// TableNode 以链表形式存储域名和对应ip
typedef struct TableNode {
    // 小写规范化后的域名。
    char domain[256];
    // 主机字节序IPv4地址；0表示拦截域名。
    uint32_t ip;
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

// parse_ip 将IPv4字面量解析成主机字节序整数，成功返回1。
static int parse_ip(const char *s, uint32_t *ip) {
    unsigned long addr;
    if (s == NULL || ip == NULL) {
        return 0;
    }
    // 使用 inet_addr 读取 IPv4 地址。若读入的字符串是域名而不是 IPv4 地址，返回0。
    addr = inet_addr(s);
    if (addr == INADDR_NONE && strcmp(s, "255.255.255.255") != 0) {
        return 0; // INADDR_NONE 非法地址格式 并且 排除稀有的全 1 域名
    }
    *ip = ntohl((uint32_t)addr);
    return 1;
}

// add_entry 将从本地表（磁盘）中读出的域名和ip信息填入 TableNode 链表（内存），便于处理
static int add_entry(const char *domain, uint32_t ip) {
    // 创建新节点
    TableNode *node;
    // 检查传入信息（空域名）
    if (domain == NULL || domain[0] == '\0') {
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
    node->ip = ip; // 复制ip
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
        if (parse_ip(first, &ip)) {
            domain = second;
        } else if (parse_ip(second, &ip)) {
            domain = first;
        } else {
            log_warn("skip invalid table line: %s", line);
            continue;
        }
        // 如果成功读入内存，增加计数器
        if (add_entry(domain, ip) == 0) {
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
// table_lookup 在本地表中查询domain对应ip
// 参数 domain 要查询的（客户端提供）域名 ip 一般为本机ip
int table_lookup(const char *domain, uint32_t *ip) {
    char key[256];
    TableNode *node;
    // 查询的信息本身为空，返回不存在
    if (domain == NULL || ip == NULL) {
        return 0;
    }
    // 在 key 数组中存储规范化后的 domain
    strncpy(key, domain, sizeof(key) - 1);
    key[sizeof(key) - 1] = '\0';
    to_lower_ascii(key);
    // 从本地表头指针开始在本地表中查询，命中则返回1。
    // 是否拦截由返回值和*ip共同判断：返回0表示未找到；返回1且*ip为0表示命中拦截规则。
    for (node = g_table; node != NULL; node = node->next) {
        if (strcmp(node->domain, key) == 0) {
            *ip = node->ip; // 如果 *ip==0 ，说明是被拦截的域名；否则是正常返回的域名
            return 1;
        }
    }

    return 0;
}
