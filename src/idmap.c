#include "idmap.h"

#include "logger.h"

#include <string.h>

#define IDMAP_MAX_ENTRIES 1024

typedef struct {
    int used; // 标记 ID映射表中的当前条目是否可以被覆盖（因为g_entries容量有限，需要覆盖原有条目来存储新条目）
    // 1 表示该槽位已被占用，保存着一个尚未完成的转发请求；
    // 0 表示该槽位空闲，可以写入新的映射。
    uint16_t upstream_id;
    uint16_t client_id;
    struct sockaddr_in client_addr;
    socklen_t client_len;
    char domain[256];
    uint64_t created_at_ms; // 创建时间戳
} IDMapEntry; // 单条映射条目
static IDMapEntry g_entries[IDMAP_MAX_ENTRIES]; // g_entries 存储所有ID映射
static uint16_t g_next_id = 1; // g_next_id 新分配id的计数器

// idmap_init 清空映射表
void idmap_init(void) {
    memset(g_entries, 0, sizeof(g_entries));
    g_next_id = 1;
}

// id_in_use 判断当前id是否在ID映射表中被使用
static int id_in_use(uint16_t id) {
    int i;
    for (i = 0; i < IDMAP_MAX_ENTRIES; i++) {
        if (g_entries[i].used && g_entries[i].upstream_id == id) {
            return 1;
        }
    }
    return 0;
}

// allocate_upstream_id 为上游DNS响应分配ID。这样即使多个客户端使用了相同的原始ID，上游DNS返回时也能通过这个新ID找到对应客户端。
static int allocate_upstream_id(uint16_t *upstream_id) {
    int tries;
    // 尝试遍历ID映射表判断candidate id是否能够使用，如果能九江candidate id作为上游DNS响应的id返回。
    // 尝试太多次判断为超时错误。
    for (tries = 0; tries < 65535; tries++) {
        uint16_t candidate = g_next_id++;
        // g_next_id是uint16_t，65535自增后会溢出为0。这里跳过0，避免把0作为新分配的upstream_id使用。
        if (g_next_id == 0) {
            g_next_id = 1; // 初始化。
        }
        if (!id_in_use(candidate)) { // 如果candidate id没有被ID映射表中有效条目使用，那么就可以被使用
            *upstream_id = candidate;
            return 0;
        }
    }
    // 超时失败
    return -1;
}

// idmap_add 在ID映射表中添加新条目
int idmap_add(uint16_t client_id,const struct sockaddr_in *client_addr,
              socklen_t client_len,const char *domain,uint16_t *upstream_id) {
    int i;
    uint16_t new_id;
    // 检查传入信息是否正常
    if (client_addr == NULL || upstream_id == NULL) {
        return -1;
    }
    // 检查是否成功为上游DNS响应成功分配id
    if (allocate_upstream_id(&new_id) != 0) {
        return -1;
    }
    // 遍历ID映射表寻找可覆盖的条目/可以存储新条目的下标
    for (i = 0; i < IDMAP_MAX_ENTRIES; i++) {
        if (!g_entries[i].used) {
            g_entries[i].used = 1; // 修改used标记为1，占有该条目并填入相关信息
            // 把客户端原ID保存起来，并为转发给上游DNS的请求分配新ID；上游响应会携带这个新ID，后续靠它查回原客户端和原ID。
            g_entries[i].upstream_id = new_id; 
            g_entries[i].client_id = client_id;
            g_entries[i].client_addr = *client_addr;
            g_entries[i].client_len = client_len;
            g_entries[i].created_at_ms = net_now_ms();
            // 填入domain字段时注意结束符和为空处理
            if (domain != NULL) {
                strncpy(g_entries[i].domain, domain, sizeof(g_entries[i].domain) - 1);
                g_entries[i].domain[sizeof(g_entries[i].domain) - 1] = '\0';
            } else {
                g_entries[i].domain[0] = '\0';
            }
            // 覆盖upstream_id
            *upstream_id = new_id;
            return 0;
        }
    }
    // ID映射表已满，返回失败并打印报错
    log_warn("id map is full");
    return -1;
}
// idmap_find 寻找和上游DNS响应id对应的客户端请求id
int idmap_find(uint16_t upstream_id,
               uint16_t *client_id,
               struct sockaddr_in *client_addr,
               socklen_t *client_len,
               char *domain,
               int domain_size) {
    int i;
    // 遍历 idmap 中所有条目，寻找对应 id。 如果成功找到，就返回条目中存储的信息。
    for (i = 0; i < IDMAP_MAX_ENTRIES; i++) {
        if (g_entries[i].used && g_entries[i].upstream_id == upstream_id) {
            if (client_id != NULL) {
                *client_id = g_entries[i].client_id;
            }
            if (client_addr != NULL) {
                *client_addr = g_entries[i].client_addr;
            }
            if (client_len != NULL) {
                *client_len = g_entries[i].client_len;
            }
            if (domain != NULL && domain_size > 0) {
                strncpy(domain, g_entries[i].domain, (size_t)domain_size - 1);
                domain[domain_size - 1] = '\0';
            }
            return 1;
        }
    }

    return 0;
}

// idmap_remove 清除ID映射表中特定的条目（转发失败和已经完成的包）
void idmap_remove(uint16_t upstream_id) {
    int i;
    for (i = 0; i < IDMAP_MAX_ENTRIES; i++) {
        if (g_entries[i].used && g_entries[i].upstream_id == upstream_id) {
            // 清除方式：直接设为0
            memset(&g_entries[i], 0, sizeof(g_entries[i]));
            return;
        }
    }
}

// idmap_cleanup_timeout 清理超过timeout_ms仍未收到上游DNS响应的映射项
// 参数 timeout_ms 一般直接传入默认值
// 每次报错和转发时调用
void idmap_cleanup_timeout(uint64_t now_ms, uint64_t timeout_ms) {
    int i;
    // 遍历ID映射表，对于正在使用且超时的条目进行清理
    for (i = 0; i < IDMAP_MAX_ENTRIES; i++) {
        if (g_entries[i].used && now_ms - g_entries[i].created_at_ms >= timeout_ms) {
            log_warn("upstream timeout domain=%s client_id=%u upstream_id=%u age=%llu ms",
                     g_entries[i].domain,
                     g_entries[i].client_id,
                     g_entries[i].upstream_id,
                     (unsigned long long)(now_ms - g_entries[i].created_at_ms));
            memset(&g_entries[i], 0, sizeof(g_entries[i]));
        }
    }
}
