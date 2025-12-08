/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024
 */

#ifndef FDIR_CORE_H
#define FDIR_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mbuf.h>
#include "fdir_config.h"

/* FDIR端口配置 */
struct fdir_port_config {
    uint16_t port_id;                   /* 端口ID */
    uint16_t nb_rx_queues;              /* 接收队列数量 */
    uint16_t nb_tx_queues;              /* 发送队列数量 */
    uint16_t nb_rx_desc;                /* 接收描述符数量 */
    uint16_t nb_tx_desc;                /* 发送描述符数量 */
    struct rte_mempool *mbuf_pool;      /* mbuf内存池 */
    bool promiscuous;                   /* 混杂模式 */
    bool rss_enable;                    /* RSS启用 */
    uint64_t rss_hf;                    /* RSS哈希函数 */
    uint8_t rss_key[40];                /* RSS密钥 */
    uint16_t rss_reta_size;             /* RSS重定向表大小 */
    uint16_t rss_reta[FDIR_MAX_QUEUES]; /* RSS重定向表 */
};

/* FDIR统计信息 */
struct fdir_port_stats {
    uint64_t rx_packets;                /* 接收包总数 */
    uint64_t tx_packets;                /* 发送包总数 */
    uint64_t rx_bytes;                  /* 接收字节数 */
    uint64_t tx_bytes;                  /* 发送字节数 */
    uint64_t rx_errors;                 /* 接收错误数 */
    uint64_t tx_errors;                 /* 发送错误数 */
    uint64_t rx_missed;                 /* 丢失包数 */
    uint64_t rx_nombuf;                 /* 无缓冲区次数 */
    uint64_t flow_matches;              /* flow匹配次数 */
    uint64_t flow_misses;               /* flow未匹配次数 */
    uint64_t queue_stats[FDIR_MAX_QUEUES]; /* 队列统计 */
    struct rte_eth_stats eth_stats;     /* 网卡统计 */
};

/* FDIR核心上下文 */
struct fdir_context {
    uint16_t nb_ports;                  /* 端口数量 */
    uint16_t enabled_port_mask;         /* 启用的端口掩码 */
    struct fdir_port_config ports[FDIR_MAX_PORTS]; /* 端口配置 */
    struct fdir_port_stats port_stats[FDIR_MAX_PORTS]; /* 端口统计 */
    pthread_mutex_t stats_lock;         /* 统计锁 */
    bool initialized;                   /* 是否已初始化 */
    bool running;                       /* 是否运行中 */
};

/* Flow规则结构 */
struct fdir_flow_rule {
    uint32_t id;                        /* 规则ID */
    char name[FDIR_MAX_NAME_LEN];       /* 规则名称 */
    char description[FDIR_MAX_DESC_LEN];/* 规则描述 */
    uint32_t priority;                  /* 优先级 */
    uint16_t port_id;                   /* 端口ID */
    uint16_t queue_id;                  /* 目标队列 */
    bool active;                        /* 是否激活 */
    bool ingress;                       /* 入口方向 */
    bool egress;                        /* 出口方向 */

    /* 匹配条件 */
    struct {
        /* L2层 */
        struct rte_ether_addr src_mac;  /* 源MAC地址 */
        struct rte_ether_addr dst_mac;  /* 目的MAC地址 */
        bool src_mac_mask;              /* 源MAC掩码 */
        bool dst_mac_mask;              /* 目的MAC掩码 */
        uint16_t ether_type;            /* 以太网类型 */

        /* VLAN */
        uint16_t vlan_tci;              /* VLAN TCI */
        uint16_t vlan_tci_mask;         /* VLAN TCI掩码 */
        bool vlan_present;              /* 是否有VLAN */

        /* L3层 */
        uint32_t src_ip;                /* 源IPv4地址 */
        uint32_t dst_ip;                /* 目的IPv4地址 */
        uint32_t src_ip_mask;           /* 源IPv4掩码 */
        uint32_t dst_ip_mask;           /* 目的IPv4掩码 */
        uint8_t src_ip6[16];            /* 源IPv6地址 */
        uint8_t dst_ip6[16];            /* 目的IPv6地址 */
        uint8_t src_ip6_mask[16];       /* 源IPv6掩码 */
        uint8_t dst_ip6_mask[16];       /* 目的IPv6掩码 */
        uint8_t ip_proto;               /* IP协议 */
        uint8_t ip_proto_mask;          /* IP协议掩码 */

        /* L4层 */
        uint16_t src_port;              /* 源端口 */
        uint16_t dst_port;              /* 目的端口 */
        uint16_t src_port_mask;         /* 源端口掩码 */
        uint16_t dst_port_mask;         /* 目的端口掩码 */
        uint8_t tcp_flags;              /* TCP标志 */
        uint8_t tcp_flags_mask;         /* TCP标志掩码 */

        /* 应用层 */
        bool http_enable;               /* HTTP识别 */
        bool tls_enable;                /* TLS识别 */
        char http_method[HTTP_METHOD_MAX_LEN]; /* HTTP方法 */
        char http_host[HTTP_HOST_MAX_LEN];     /* HTTP主机 */
        char http_uri[HTTP_URI_MAX_LEN];       /* HTTP URI */
        char tls_sni[TLS_SNI_MAX_LEN];         /* TLS SNI */
    } match;

    /* 动作 */
    struct {
        uint16_t queue;                 /* 队列索引 */
        bool drop;                      /* 丢弃包 */
        uint32_t mark;                  /* 标记值 */
        bool count;                     /* 计数 */
    } action;

    /* rte_flow对象 */
    struct rte_flow *rte_flow;          /* rte_flow对象 */
};

/* 函数声明 */

/* 初始化和清理 */
int fdir_init(struct fdir_context *ctx, uint16_t port_mask);
int fdir_cleanup(struct fdir_context *ctx);

/* 端口管理 */
int fdir_port_init(struct fdir_context *ctx, uint16_t port_id,
                   struct fdir_port_config *port_cfg);
int fdir_port_start(struct fdir_context *ctx, uint16_t port_id);
int fdir_port_stop(struct fdir_context *ctx, uint16_t port_id);
int fdir_port_stats_get(struct fdir_context *ctx, uint16_t port_id,
                       struct fdir_port_stats *stats);
int fdir_port_stats_reset(struct fdir_context *ctx, uint16_t port_id);

/* Flow规则管理 */
int fdir_flow_create(struct fdir_context *ctx, struct fdir_flow_rule *rule);
int fdir_flow_destroy(struct fdir_context *ctx, struct fdir_flow_rule *rule);
int fdir_flow_validate(struct fdir_context *ctx, struct fdir_flow_rule *rule,
                      struct rte_flow_error *error);

/* 辅助函数 */
int fdir_mbuf_pool_create(struct fdir_context *ctx, uint16_t port_id,
                          uint32_t nb_mbufs, uint16_t mbuf_cache_size);
int fdir_rss_configure(struct fdir_context *ctx, uint16_t port_id);
int fdir_port_mac_addr_get(uint16_t port_id, struct rte_ether_addr *mac_addr);

/* 统计和监控 */
int fdir_stats_update(struct fdir_context *ctx, uint16_t port_id,
                      uint16_t queue_id, uint32_t packet_count);
void fdir_stats_print(struct fdir_context *ctx);
int fdir_stats_reset_all(struct fdir_context *ctx);

/* 工具函数 */
int fdir_parse_ipv4(const char *ip_str, uint32_t *ip_addr);
int fdir_parse_ipv6(const char *ip_str, uint8_t *ip_addr);
int fdir_parse_mac(const char *mac_str, struct rte_ether_addr *mac_addr);
const char *fdir_format_ipv4(uint32_t ip_addr, char *buf, size_t buf_len);
const char *fdir_format_ipv6(const uint8_t *ip_addr, char *buf, size_t buf_len);
const char *fdir_format_mac(const struct rte_ether_addr *mac_addr,
                           char *buf, size_t buf_len);

/* 调试函数 */
#if FDIR_DEBUG
void fdir_debug_print_flow_rule(struct fdir_flow_rule *rule);
void fdir_debug_print_port_config(struct fdir_port_config *port_cfg);
void fdir_debug_print_mbuf(struct rte_mbuf *mbuf);
#endif

#endif /* FDIR_CORE_H */