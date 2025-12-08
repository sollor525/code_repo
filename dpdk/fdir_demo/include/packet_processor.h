/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024
 */

#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include "fdir_config.h"

/* 数据包处理模式 */
enum fdir_process_mode {
    FDIR_PROCESS_MODE_POLL = 0,       /* 轮询模式 */
    FDIR_PROCESS_MODE_INTERRUPT,      /* 中断模式 */
    FDIR_PROCESS_MODE_EVENT,          /* 事件模式 */
    FDIR_PROCESS_MODE_MAX
};

/* 数据包类型 */
enum fdir_packet_type {
    FDIR_PACKET_TYPE_UNKNOWN = 0,     /* 未知类型 */
    FDIR_PACKET_TYPE_IPV4,            /* IPv4包 */
    FDIR_PACKET_TYPE_IPV6,            /* IPv6包 */
    FDIR_PACKET_TYPE_TCP,             /* TCP包 */
    FDIR_PACKET_TYPE_UDP,             /* UDP包 */
    FDIR_PACKET_TYPE_ICMP,            /* ICMP包 */
    FDIR_PACKET_TYPE_VLAN,            /* VLAN包 */
    FDIR_PACKET_TYPE_HTTP,            /* HTTP包 */
    FDIR_PACKET_TYPE_TLS,             /* TLS包 */
    FDIR_PACKET_TYPE_MAX
};

/* 数据包解析上下文 */
struct fdir_packet_ctx {
    struct rte_mbuf *mbuf;            /* DPDK mbuf */
    uint16_t port_id;                 /* 接收端口ID */
    uint16_t queue_id;                /* 接收队列ID */
    uint64_t timestamp;               /* 时间戳 */
    enum fdir_packet_type type;       /* 包类型 */
    uint32_t flow_id;                 /* 匹配的flow ID */
    uint16_t pkt_len;                 /* 包长度 */
    uint16_t data_len;                /* 数据长度 */

    /* L2层 */
    struct rte_ether_hdr *eth_hdr;    /* 以太网头 */
    struct rte_vlan_hdr *vlan_hdr;    /* VLAN头 */

    /* L3层 */
    struct rte_ipv4_hdr *ipv4_hdr;    /* IPv4头 */
    struct rte_ipv6_hdr *ipv6_hdr;    /* IPv6头 */
    uint8_t l3_proto;                 /* L3协议 */

    /* L4层 */
    struct rte_tcp_hdr *tcp_hdr;      /* TCP头 */
    struct rte_udp_hdr *udp_hdr;      /* UDP头 */
    void *l4_hdr;                     /* L4头指针 */
    uint16_t l4_hdr_len;              /* L4头长度 */

    /* 应用层 */
    uint8_t *app_data;                /* 应用层数据 */
    uint16_t app_data_len;            /* 应用层数据长度 */

    /* 解析标志 */
    bool has_vlan;                    /* 是否有VLAN */
    bool has_ipv4;                    /* 是否有IPv4 */
    bool has_ipv6;                    /* 是否有IPv6 */
    bool has_tcp;                     /* 是否有TCP */
    bool has_udp;                     /* 是否有UDP */
    bool has_http;                    /* 是否有HTTP */
    bool has_tls;                     /* 是否有TLS */
};

/* 数据包处理配置 */
struct fdir_process_config {
    uint16_t port_id;                 /* 端口ID */
    uint16_t queue_id;                /* 队列ID */
    uint16_t burst_size;              /* 批处理大小 */
    uint16_t max_burst_size;          /* 最大批处理大小 */
    enum fdir_process_mode mode;      /* 处理模式 */
    bool enable_stats;                /* 启用统计 */
    bool enable_monitor;              /* 启用监控 */
    uint32_t stats_interval;          /* 统计间隔（秒） */
    uint32_t timeout_ms;              /* 超时时间（毫秒） */
    uint32_t cpu_affinity;            /* CPU亲和性 */
    uint16_t prefetch_offset;         /* 预取偏移 */
    bool enable_dpi;                  /* 启用深度包检测 */
};

/* 数据包处理统计 */
struct fdir_process_stats {
    uint64_t rx_packets;              /* 接收包数 */
    uint64_t tx_packets;              /* 发送包数 */
    uint64_t drop_packets;            /* 丢弃包数 */
    uint64_t process_packets;         /* 处理包数 */
    uint64_t bytes_received;          /* 接收字节数 */
    uint64_t bytes_sent;              /* 发送字节数 */
    uint64_t bytes_processed;         /* 处理字节数 */
    uint64_t parse_errors;            /* 解析错误数 */
    uint64_t flow_matches;            /* 流匹配数 */
    uint64_t flow_misses;             /* 流未匹配数 */
    uint64_t queue_full;              /* 队列满次数 */
    uint64_t alloc_fail;              /* 分配失败次数 */
    uint64_t timeout_cnt;             /* 超时次数 */
    double avg_latency;               /* 平均延迟（微秒） */
    double max_latency;               /* 最大延迟（微秒） */
    double min_latency;               /* 最小延迟（微秒） */

    /* 按类型统计 */
    uint64_t type_stats[FDIR_PACKET_TYPE_MAX];

    /* 时间窗口统计 */
    uint64_t window_packets;          /* 时间窗口包数 */
    uint64_t window_bytes;            /* 时间窗口字节数 */
    double window_throughput;         /* 时间窗口吞吐量 */
};

/* 数据包处理器 */
struct fdir_packet_processor {
    uint16_t port_id;                 /* 端口ID */
    uint16_t queue_id;                /* 队列ID */
    struct fdir_process_config config;/* 配置 */
    struct fdir_process_stats stats;  /* 统计 */
    pthread_t thread;                 /* 处理线程 */
    volatile bool running;            /* 运行标志 */
    pthread_mutex_t lock;             /* 锁 */
    void *user_data;                  /* 用户数据 */

    /* 回调函数 */
    int (*on_packet)(struct fdir_packet_processor *proc,
                    struct fdir_packet_ctx *ctx);
    int (*on_error)(struct fdir_packet_processor *proc,
                   int error_code, const char *error_msg);
    int (*on_stats)(struct fdir_packet_processor *proc,
                   const struct fdir_process_stats *stats);
};

/* 批处理结构 */
struct fdir_packet_batch {
    struct rte_mbuf **mbufs;          /* mbuf数组 */
    uint16_t count;                   /* 包数量 */
    uint16_t max_count;               /* 最大包数 */
    uint64_t timestamp;               /* 时间戳 */
    struct fdir_packet_ctx *ctxs;     /* 上下文数组 */
};

/* 函数声明 */

/* 初始化和清理 */
int fdir_packet_processor_init(struct fdir_packet_processor *proc,
                               const struct fdir_process_config *config);
int fdir_packet_processor_cleanup(struct fdir_packet_processor *proc);

/* 启动和停止 */
int fdir_packet_processor_start(struct fdir_packet_processor *proc);
int fdir_packet_processor_stop(struct fdir_packet_processor *proc);

/* 数据包处理 */
int fdir_packet_process(struct fdir_packet_processor *proc);
int fdir_packet_process_batch(struct fdir_packet_processor *proc,
                             struct fdir_packet_batch *batch);
int fdir_packet_forward(struct fdir_packet_processor *proc,
                       struct fdir_packet_ctx *ctx, uint16_t dst_queue);
int fdir_packet_drop(struct fdir_packet_processor *proc,
                    struct fdir_packet_ctx *ctx);

/* 数据包解析 */
int fdir_packet_parse(struct fdir_packet_ctx *ctx);
int fdir_packet_parse_l2(struct fdir_packet_ctx *ctx);
int fdir_packet_parse_l3(struct fdir_packet_ctx *ctx);
int fdir_packet_parse_l4(struct fdir_packet_ctx *ctx);
int fdir_packet_parse_app(struct fdir_packet_ctx *ctx);

/* 数据包验证 */
int fdir_packet_validate(struct fdir_packet_ctx *ctx);
bool fdir_packet_is_valid(const struct fdir_packet_ctx *ctx);
bool fdir_packet_is_ipv4(const struct fdir_packet_ctx *ctx);
bool fdir_packet_is_ipv6(const struct fdir_packet_ctx *ctx);
bool fdir_packet_is_tcp(const struct fdir_packet_ctx *ctx);
bool fdir_packet_is_udp(const struct fdir_packet_ctx *ctx);

/* 数据包特征提取 */
uint32_t fdir_packet_get_hash(const struct fdir_packet_ctx *ctx);
uint32_t fdir_packet_get_5tuple_hash(const struct fdir_packet_ctx *ctx);
uint16_t fdir_packet_get_payload_offset(const struct fdir_packet_ctx *ctx);
uint16_t fdir_packet_get_payload_len(const struct fdir_packet_ctx *ctx);

/* 批处理管理 */
int fdir_packet_batch_create(struct fdir_packet_batch *batch,
                            uint16_t max_count);
int fdir_packet_batch_destroy(struct fdir_packet_batch *batch);
int fdir_packet_batch_add(struct fdir_packet_batch *batch,
                         struct rte_mbuf *mbuf);
int fdir_packet_batch_clear(struct fdir_packet_batch *batch);

/* 统计管理 */
int fdir_packet_stats_get(struct fdir_packet_processor *proc,
                         struct fdir_process_stats *stats);
int fdir_packet_stats_reset(struct fdir_packet_processor *proc);
int fdir_packet_stats_update(struct fdir_packet_processor *proc,
                            uint32_t packet_count, uint64_t byte_count);
void fdir_packet_stats_print(const struct fdir_process_stats *stats);

/* 监控和调试 */
int fdir_packet_monitor_start(struct fdir_packet_processor *proc);
int fdir_packet_monitor_stop(struct fdir_packet_processor *proc);

/* 回调函数设置 */
int fdir_packet_set_callback(struct fdir_packet_processor *proc,
                            void (*on_packet)(struct fdir_packet_processor *,
                                             struct fdir_packet_ctx *));
int fdir_packet_set_error_callback(struct fdir_packet_processor *proc,
                                  int (*on_error)(struct fdir_packet_processor *,
                                                 int, const char *));
int fdir_packet_set_stats_callback(struct fdir_packet_processor *proc,
                                  int (*on_stats)(struct fdir_packet_processor *,
                                                 const struct fdir_process_stats *));

/* 工具函数 */
const char *fdir_packet_type_to_string(enum fdir_packet_type type);
const char *fdir_process_mode_to_string(enum fdir_process_mode mode);
uint64_t fdir_packet_get_timestamp(void);
double fdir_packet_calc_latency(uint64_t start_time, uint64_t end_time);

/* 调试函数 */
#if FDIR_DEBUG
void fdir_packet_print_ctx(const struct fdir_packet_ctx *ctx);
void fdir_packet_print_hex(const uint8_t *data, uint16_t len);
void fdir_packet_print_headers(const struct fdir_packet_ctx *ctx);
#endif

#endif /* PACKET_PROCESSOR_H */