/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024
 */

#ifndef FLOW_MANAGER_H
#define FLOW_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "fdir_core.h"
#include "fdir_config.h"

/* Flow类型枚举 */
enum fdir_flow_type {
    FDIR_FLOW_TYPE_IPV4 = 0,
    FDIR_FLOW_TYPE_IPV6,
    FDIR_FLOW_TYPE_TCP,
    FDIR_FLOW_TYPE_UDP,
    FDIR_FLOW_TYPE_VLAN,
    FDIR_FLOW_TYPE_HTTP,
    FDIR_FLOW_TYPE_TLS,
    FDIR_FLOW_TYPE_ICMP,
    FDIR_FLOW_TYPE_CUSTOM,
    FDIR_FLOW_TYPE_MAX
};

/* Flow动作类型 */
enum fdir_flow_action {
    FDIR_FLOW_ACTION_QUEUE = 0,
    FDIR_FLOW_ACTION_DROP,
    FDIR_FLOW_ACTION_MARK,
    FDIR_FLOW_ACTION_COUNT,
    FDIR_FLOW_ACTION_RSS,
    FDIR_FLOW_ACTION_PASSTHRU,
    FDIR_FLOW_ACTION_MAX
};

/* Flow匹配模式 */
enum fdir_flow_match_mode {
    FDIR_FLOW_MATCH_EXACT = 0,      /* 精确匹配 */
    FDIR_FLOW_MATCH_PREFIX,         /* 前缀匹配 */
    FDIR_FLOW_MATCH_RANGE,          /* 范围匹配 */
    FDIR_FLOW_MATCH_WILDCARD,       /* 通配符匹配 */
    FDIR_FLOW_MATCH_MASK,           /* 掩码匹配 */
    FDIR_FLOW_MATCH_MAX
};

/* Flow规则配置 */
struct fdir_flow_config {
    uint32_t rule_id;               /* 规则ID */
    char name[FDIR_MAX_NAME_LEN];   /* 规则名称 */
    char description[FDIR_MAX_DESC_LEN]; /* 规则描述 */
    enum fdir_flow_type type;       /* 流量类型 */
    uint32_t priority;              /* 优先级 */
    uint16_t port_id;               /* 端口ID */
    bool active;                    /* 是否激活 */
    bool ingress;                   /* 入口方向 */
    bool egress;                    /* 出口方向 */
    enum fdir_flow_action action_type;   /* 动作类型 */

    /* 匹配配置 */
    struct {
        /* 通用匹配 */
        enum fdir_flow_match_mode mode;  /* 匹配模式 */
        bool negate;                     /* 取反匹配 */

        /* L2层匹配 */
        struct {
            struct rte_ether_addr addr;  /* MAC地址 */
            struct rte_ether_addr mask;  /* MAC掩码 */
            bool enabled;
        } src_mac, dst_mac;

        /* VLAN匹配 */
        struct {
            uint16_t tci;               /* VLAN TCI */
            uint16_t mask;              /* VLAN掩码 */
            bool present;               /* 是否必须存在 */
            bool enabled;
        } vlan;

        /* IPv4匹配 */
        struct {
            uint32_t addr;              /* IPv4地址 */
            uint32_t mask;              /* IPv4掩码 */
            bool enabled;
        } src_ipv4, dst_ipv4;

        /* IPv6匹配 */
        struct {
            uint8_t addr[16];           /* IPv6地址 */
            uint8_t mask[16];           /* IPv6掩码 */
            bool enabled;
        } src_ipv6, dst_ipv6;

        /* 端口匹配 */
        struct {
            uint16_t port;              /* 端口号 */
            uint16_t mask;              /* 端口掩码 */
            bool enabled;
        } src_port, dst_port;

        /* 协议匹配 */
        struct {
            uint8_t protocol;           /* 协议号 */
            uint8_t mask;               /* 协议掩码 */
            bool enabled;
        } protocol;

        /* TCP标志匹配 */
        struct {
            uint8_t flags;              /* TCP标志 */
            uint8_t mask;               /* TCP标志掩码 */
            bool enabled;
        } tcp_flags;

        /* 应用层匹配 */
        struct {
            char pattern[256];          /* 模式串 */
            size_t pattern_len;         /* 模式长度 */
            size_t offset;              /* 偏移量 */
            bool case_sensitive;        /* 大小写敏感 */
            bool enabled;
        } app_match;
    } match;

    /* 动作配置 */
    struct {
        uint16_t queue;                 /* 队列索引 */
        uint32_t mark;                  /* 标记值 */
        uint64_t counter_id;            /* 计数器ID */
        struct {
            uint16_t *queues;           /* 队列数组 */
            uint16_t queue_num;         /* 队列数量 */
            uint64_t types;             /* RSS类型 */
            uint8_t *key;               /* RSS密钥 */
            uint8_t key_len;            /* RSS密钥长度 */
        } rss;
    } action;
};

/* Flow管理器 */
struct fdir_flow_manager {
    struct fdir_flow_config *rules;     /* 规则数组 */
    uint32_t rule_count;                /* 规则数量 */
    uint32_t max_rules;                 /* 最大规则数 */
    struct rte_flow **rte_flows;        /* rte_flow对象数组 */
    uint32_t *rule_id_map;              /* 规则ID映射表 */
    pthread_rwlock_t lock;              /* 读写锁 */
    bool initialized;                   /* 是否已初始化 */
    uint16_t port_id;                   /* 关联的端口ID */
};

/* 规则操作结果 */
struct fdir_flow_op_result {
    bool success;                       /* 操作是否成功 */
    int error_code;                     /* 错误码 */
    char error_msg[256];                /* 错误消息 */
    uint32_t rule_id;                   /* 规则ID */
    uint16_t flow_handle;               /* Flow句柄 */
};

/* 批量操作结构 */
struct fdir_flow_bulk_op {
    struct fdir_flow_config *rules;     /* 规则数组 */
    uint32_t rule_count;                /* 规则数量 */
    struct fdir_flow_op_result *results; /* 结果数组 */
    bool atomic;                        /* 是否原子操作 */
};

/* 函数声明 */

/* 初始化和清理 */
int fdir_flow_manager_init(struct fdir_flow_manager *mgr, uint16_t port_id,
                           uint32_t max_rules);
int fdir_flow_manager_cleanup(struct fdir_flow_manager *mgr);

/* 规则管理 */
int fdir_flow_manager_add_rule(struct fdir_flow_manager *mgr,
                              const struct fdir_flow_config *rule);
int fdir_flow_manager_del_rule(struct fdir_flow_manager *mgr, uint32_t rule_id);
int fdir_flow_manager_update_rule(struct fdir_flow_manager *mgr,
                                 const struct fdir_flow_config *rule);
int fdir_flow_manager_get_rule(struct fdir_flow_manager *mgr, uint32_t rule_id,
                               struct fdir_flow_config *rule);
int fdir_flow_manager_list_rules(struct fdir_flow_manager *mgr,
                                struct fdir_flow_config *rules,
                                uint32_t *count);

/* 规则激活/停用 */
int fdir_flow_manager_enable_rule(struct fdir_flow_manager *mgr, uint32_t rule_id);
int fdir_flow_manager_disable_rule(struct fdir_flow_manager *mgr, uint32_t rule_id);

/* 批量操作 */
int fdir_flow_manager_bulk_add(struct fdir_flow_manager *mgr,
                               const struct fdir_flow_bulk_op *bulk_op);
int fdir_flow_manager_bulk_delete(struct fdir_flow_manager *mgr,
                                  const uint32_t *rule_ids, uint32_t count);
int fdir_flow_manager_bulk_update(struct fdir_flow_manager *mgr,
                                  const struct fdir_flow_bulk_op *bulk_op);

/* 规则配置加载 */
int fdir_flow_manager_load_config(struct fdir_flow_manager *mgr,
                                 const char *config_file);
int fdir_flow_manager_save_config(struct fdir_flow_manager *mgr,
                                 const char *config_file);

/* 规则优先级管理 */
int fdir_flow_manager_set_priority(struct fdir_flow_manager *mgr,
                                   uint32_t rule_id, uint32_t priority);
int fdir_flow_manager_get_priority(struct fdir_flow_manager *mgr,
                                   uint32_t rule_id, uint32_t *priority);

/* 规则统计 */
int fdir_flow_manager_get_stats(struct fdir_flow_manager *mgr,
                                uint32_t rule_id, struct rte_flow_query_count *stats);
int fdir_flow_manager_reset_stats(struct fdir_flow_manager *mgr,
                                  uint32_t rule_id);

/* 规则验证 */
int fdir_flow_manager_validate_rule(struct fdir_flow_manager *mgr,
                                    const struct fdir_flow_config *rule,
                                    struct rte_flow_error *error);
int fdir_flow_manager_validate_all(struct fdir_flow_manager *mgr);

/* 规则查找 */
int fdir_flow_manager_find_by_name(struct fdir_flow_manager *mgr,
                                   const char *name, uint32_t *rule_id);
int fdir_flow_manager_find_by_type(struct fdir_flow_manager *mgr,
                                   enum fdir_flow_type type,
                                   uint32_t *rule_ids, uint32_t *count);

/* 工具函数 */
const char *fdir_flow_type_to_string(enum fdir_flow_type type);
const char *fdir_flow_action_to_string(enum fdir_flow_action action);
const char *fdir_flow_match_mode_to_string(enum fdir_flow_match_mode mode);
enum fdir_flow_type fdir_flow_string_to_type(const char *str);
enum fdir_flow_action fdir_flow_string_to_action(const char *str);

/* 配置解析 */
int fdir_flow_parse_config_line(const char *line, struct fdir_flow_config *rule);
int fdir_flow_rule_to_string(const struct fdir_flow_config *rule,
                            char *buf, size_t buf_len);

/* 调试函数 */
#if FDIR_DEBUG
void fdir_flow_manager_print_rules(struct fdir_flow_manager *mgr);
void fdir_flow_print_config(const struct fdir_flow_config *rule);
#endif

#endif /* FLOW_MANAGER_H */