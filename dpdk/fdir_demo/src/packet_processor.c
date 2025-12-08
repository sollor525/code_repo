/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include "packet_processor.h"
#include "dpdk_utils.h"
#include "pattern_matcher.h"

static void *fdir_packet_processor_thread(void *arg);
static inline void fdir_packet_prefetch(struct rte_mbuf *mbuf);

/**
 * 初始化数据包处理器
 */
int fdir_packet_processor_init(struct fdir_packet_processor *proc,
                               const struct fdir_process_config *config)
{
    if (!proc || !config) {
        printf("Error: Invalid parameters for packet processor init\n");
        return FDIR_INVALID_PARAM;
    }

    memset(proc, 0, sizeof(*proc));
    proc->config = *config;
    proc->port_id = config->port_id;
    proc->queue_id = config->queue_id;

    /* 初始化锁 */
    if (pthread_mutex_init(&proc->lock, NULL) != 0) {
        printf("Error: Failed to initialize processor lock\n");
        return FDIR_ERROR;
    }

    /* 初始化统计信息 */
    memset(&proc->stats, 0, sizeof(proc->stats));
    proc->stats.min_latency = 0xFFFFFFFFFFFFFFFFULL;
    proc->stats.max_latency = 0;

    /* 设置默认回调函数 */
    proc->on_packet = NULL;
    proc->on_error = NULL;
    proc->on_stats = NULL;

    printf("Packet processor initialized: port=%u, queue=%u\n",
           proc->port_id, proc->queue_id);

    return FDIR_SUCCESS;
}

/**
 * 清理数据包处理器
 */
int fdir_packet_processor_cleanup(struct fdir_packet_processor *proc)
{
    if (!proc) {
        return FDIR_INVALID_PARAM;
    }

    /* 停止处理器 */
    if (proc->running) {
        fdir_packet_processor_stop(proc);
    }

    /* 销毁锁 */
    pthread_mutex_destroy(&proc->lock);

    memset(proc, 0, sizeof(*proc));

    printf("Packet processor cleanup completed\n");
    return FDIR_SUCCESS;
}

/**
 * 启动数据包处理器
 */
int fdir_packet_processor_start(struct fdir_packet_processor *proc)
{
    if (!proc) {
        return FDIR_INVALID_PARAM;
    }

    if (proc->running) {
        printf("Warning: Processor already running\n");
        return FDIR_SUCCESS;
    }

    /* 创建处理线程 */
    if (pthread_create(&proc->thread, NULL, fdir_packet_processor_thread, proc) != 0) {
        printf("Error: Failed to create processor thread\n");
        return FDIR_ERROR;
    }

    /* 设置线程亲和性 */
    if (proc->config.cpu_affinity != 0xFFFFFFFF) {
        fdir_set_thread_affinity(proc->thread, proc->config.cpu_affinity);
    }

    proc->running = true;

    printf("Packet processor started: port=%u, queue=%u\n",
           proc->port_id, proc->queue_id);

    return FDIR_SUCCESS;
}

/**
 * 停止数据包处理器
 */
int fdir_packet_processor_stop(struct fdir_packet_processor *proc)
{
    if (!proc) {
        return FDIR_INVALID_PARAM;
    }

    if (!proc->running) {
        return FDIR_SUCCESS;
    }

    proc->running = false;

    /* 等待线程结束 */
    pthread_join(proc->thread, NULL);

    printf("Packet processor stopped\n");
    return FDIR_SUCCESS;
}

/**
 * 处理数据包（批处理）
 */
int fdir_packet_process(struct fdir_packet_processor *proc)
{
    struct rte_mbuf *mbufs[FDIR_BATCH_SIZE];
    struct fdir_packet_ctx ctxs[FDIR_BATCH_SIZE];
    uint16_t nb_rx;
    uint64_t start_time, end_time;
    int ret;

    if (!proc) {
        return FDIR_INVALID_PARAM;
    }

    /* 接收数据包 */
    start_time = fdir_get_tsc_cycles();
    nb_rx = rte_eth_rx_burst(proc->port_id, proc->queue_id,
                            mbufs, proc->config.burst_size);
    end_time = fdir_get_tsc_cycles();

    if (nb_rx == 0) {
        proc->stats.timeout_cnt++;
        return 0;
    }

    /* 更新统计 */
    pthread_mutex_lock(&proc->lock);
    proc->stats.rx_packets += nb_rx;

    /* 计算延迟 */
    double latency = fdir_cycles_to_usec(end_time - start_time);
    if (latency < proc->stats.min_latency) {
        proc->stats.min_latency = latency;
    }
    if (latency > proc->stats.max_latency) {
        proc->stats.max_latency = latency;
    }
    /* 简单平均延迟计算 */
    proc->stats.avg_latency = (proc->stats.avg_latency + latency) / 2;
    pthread_mutex_unlock(&proc->lock);

    /* 处理每个数据包 */
    for (uint16_t i = 0; i < nb_rx; i++) {
        /* 预取下一个包 */
        if (i + 1 < nb_rx) {
            fdir_packet_prefetch(mbufs[i + 1]);
        }

        /* 初始化上下文 */
        memset(&ctxs[i], 0, sizeof(ctxs[i]));
        ctxs[i].mbuf = mbufs[i];
        ctxs[i].port_id = proc->port_id;
        ctxs[i].queue_id = proc->queue_id;
        ctxs[i].timestamp = fdir_get_tsc_cycles();
        ctxs[i].pkt_len = mbufs[i]->pkt_len;
        ctxs[i].data_len = mbufs[i]->data_len;

        /* 解析数据包 */
        ret = fdir_packet_parse(&ctxs[i]);
        if (ret != FDIR_SUCCESS) {
            pthread_mutex_lock(&proc->lock);
            proc->stats.parse_errors++;
            pthread_mutex_unlock(&proc->lock);

            if (proc->on_error) {
                proc->on_error(proc, ret, "Packet parse error");
            }
            continue;
        }

        /* 更新统计 */
        pthread_mutex_lock(&proc->lock);
        proc->stats.process_packets++;
        proc->stats.bytes_processed += mbufs[i]->pkt_len;
        if (ctxs[i].type < FDIR_PACKET_TYPE_MAX) {
            proc->stats.type_stats[ctxs[i].type]++;
        }
        pthread_mutex_unlock(&proc->lock);

        /* 调用回调函数 */
        if (proc->on_packet) {
            proc->on_packet(proc, &ctxs[i]);
        }
    }

    /* 释放mbuf */
    for (uint16_t i = 0; i < nb_rx; i++) {
        rte_pktmbuf_free(mbufs[i]);
    }

    /* 更新统计 */
    pthread_mutex_lock(&proc->lock);
    proc->stats.window_packets += nb_rx;
    proc->stats.window_bytes += (end_time - start_time);
    pthread_mutex_unlock(&proc->lock);

    return nb_rx;
}

/**
 * 解析数据包
 */
int fdir_packet_parse(struct fdir_packet_ctx *ctx)
{
    if (!ctx || !ctx->mbuf) {
        return FDIR_INVALID_PARAM;
    }

    /* 解析L2层 */
    int ret = fdir_packet_parse_l2(ctx);
    if (ret != FDIR_SUCCESS) {
        return ret;
    }

    /* 解析L3层 */
    ret = fdir_packet_parse_l3(ctx);
    if (ret != FDIR_SUCCESS) {
        return ret;
    }

    /* 解析L4层 */
    ret = fdir_packet_parse_l4(ctx);
    if (ret != FDIR_SUCCESS) {
        return ret;
    }

    /* 解析应用层 */
    ret = fdir_packet_parse_app(ctx);
    if (ret != FDIR_SUCCESS) {
        return ret;
    }

    /* 确定包类型 */
    if (ctx->has_ipv4) {
        ctx->type = FDIR_PACKET_TYPE_IPV4;
    } else if (ctx->has_ipv6) {
        ctx->type = FDIR_PACKET_TYPE_IPV6;
    }

    if (ctx->has_tcp) {
        ctx->type = FDIR_PACKET_TYPE_TCP;
    } else if (ctx->has_udp) {
        ctx->type = FDIR_PACKET_TYPE_UDP;
    }

    if (ctx->has_vlan) {
        ctx->type = FDIR_PACKET_TYPE_VLAN;
    }

    if (ctx->has_http) {
        ctx->type = FDIR_PACKET_TYPE_HTTP;
    } else if (ctx->has_tls) {
        ctx->type = FDIR_PACKET_TYPE_TLS;
    }

    return FDIR_SUCCESS;
}

/**
 * 解析L2层
 */
int fdir_packet_parse_l2(struct fdir_packet_ctx *ctx)
{
    struct rte_ether_hdr *eth_hdr;
    uint16_t ether_type;

    if (!ctx || !ctx->mbuf) {
        return FDIR_INVALID_PARAM;
    }

    /* 获取以太网头 */
    eth_hdr = rte_pktmbuf_mtod(ctx->mbuf, struct rte_ether_hdr *);
    ctx->eth_hdr = eth_hdr;

    /* 检查VLAN */
    ether_type = ntohs(eth_hdr->ether_type);
    if (ether_type == RTE_ETHER_TYPE_VLAN) {
        ctx->vlan_hdr = (struct rte_vlan_hdr *)(eth_hdr + 1);
        ctx->has_vlan = true;
        ether_type = ntohs(ctx->vlan_hdr->eth_proto);
    }

    /* 保存以太网类型 */
    ctx->pkt_len = ctx->mbuf->pkt_len;

    return FDIR_SUCCESS;
}

/**
 * 解析L3层
 */
int fdir_packet_parse_l3(struct fdir_packet_ctx *ctx)
{
    void *l3_hdr;
    uint16_t ether_type;

    if (!ctx || !ctx->eth_hdr) {
        return FDIR_INVALID_PARAM;
    }

    /* 确定L3头位置 */
    if (ctx->has_vlan) {
        l3_hdr = ctx->vlan_hdr + 1;
        ether_type = ntohs(ctx->vlan_hdr->eth_proto);
    } else {
        l3_hdr = ctx->eth_hdr + 1;
        ether_type = ntohs(ctx->eth_hdr->ether_type);
    }

    /* 解析IPv4 */
    if (ether_type == RTE_ETHER_TYPE_IPV4) {
        ctx->ipv4_hdr = (struct rte_ipv4_hdr *)l3_hdr;
        ctx->has_ipv4 = true;
        ctx->l3_proto = ctx->ipv4_hdr->next_proto_id;
    }
    /* 解析IPv6 */
    else if (ether_type == RTE_ETHER_TYPE_IPV6) {
        ctx->ipv6_hdr = (struct rte_ipv6_hdr *)l3_hdr;
        ctx->has_ipv6 = true;
        ctx->l3_proto = ctx->ipv6_hdr->proto;
    } else {
        /* 不支持的L3协议 */
        ctx->l3_proto = 0;
    }

    return FDIR_SUCCESS;
}

/**
 * 解析L4层
 */
int fdir_packet_parse_l4(struct fdir_packet_ctx *ctx)
{
    void *l4_hdr = NULL;
    uint8_t l3_proto;

    if (!ctx) {
        return FDIR_INVALID_PARAM;
    }

    l3_proto = ctx->l3_proto;

    /* 确定L4头位置 */
    if (ctx->has_ipv4) {
        uint8_t ihl = ctx->ipv4_hdr->version_ihl & 0x0f;
        l4_hdr = (uint8_t *)ctx->ipv4_hdr + ihl * 4;
    } else if (ctx->has_ipv6) {
        l4_hdr = ctx->ipv6_hdr + 1;
    } else {
        return FDIR_SUCCESS; /* 没有L3层，跳过L4层 */
    }

    /* 解析TCP */
    if (l3_proto == IPPROTO_TCP) {
        ctx->tcp_hdr = (struct rte_tcp_hdr *)l4_hdr;
        ctx->has_tcp = true;
        ctx->l4_hdr = l4_hdr;
        ctx->l4_hdr_len = (ctx->tcp_hdr->data_off >> 4) * 4;
    }
    /* 解析UDP */
    else if (l3_proto == IPPROTO_UDP) {
        ctx->udp_hdr = (struct rte_udp_hdr *)l4_hdr;
        ctx->has_udp = true;
        ctx->l4_hdr = l4_hdr;
        ctx->l4_hdr_len = sizeof(struct rte_udp_hdr);
    }
    /* 解析ICMP */
    else if (l3_proto == IPPROTO_ICMP) {
        ctx->l4_hdr = l4_hdr;
        ctx->l4_hdr_len = sizeof(struct rte_icmp_hdr);
    } else {
        /* 不支持的L4协议 */
        ctx->l4_hdr = l4_hdr;
        ctx->l4_hdr_len = 0;
    }

    return FDIR_SUCCESS;
}

/**
 * 解析应用层
 */
int fdir_packet_parse_app(struct fdir_packet_ctx *ctx)
{
    if (!ctx || !ctx->l4_hdr) {
        return FDIR_SUCCESS; /* 没有L4层，跳过应用层 */
    }

    /* 确定应用层数据位置 */
    if (ctx->has_tcp || ctx->has_udp) {
        uint8_t *app_data = (uint8_t *)ctx->l4_hdr + ctx->l4_hdr_len;
        uint16_t remaining_len = ctx->mbuf->pkt_len -
                               (app_data - rte_pktmbuf_mtod(ctx->mbuf, uint8_t *));

        if (remaining_len > 0) {
            ctx->app_data = app_data;
            ctx->app_data_len = remaining_len;

            /* 简单的HTTP检测 */
            if (ctx->app_data_len >= 4) {
                /* 检查HTTP方法 */
                if (strncmp((char *)ctx->app_data, "GET ", 4) == 0 ||
                    strncmp((char *)ctx->app_data, "POST", 4) == 0 ||
                    strncmp((char *)ctx->app_data, "PUT ", 4) == 0 ||
                    strncmp((char *)ctx->app_data, "HEAD", 4) == 0) {
                    ctx->has_http = true;
                }
            }

            /* 简单的TLS检测 */
            if (ctx->app_data_len >= 3) {
                /* TLS记录层：0x16 + 版本号 */
                if (ctx->app_data[0] == 0x16 && ctx->app_data[1] == 0x03) {
                    ctx->has_tls = true;
                }
            }
        }
    }

    return FDIR_SUCCESS;
}

/**
 * 转发数据包
 */
int fdir_packet_forward(struct fdir_packet_processor *proc,
                       struct fdir_packet_ctx *ctx, uint16_t dst_queue)
{
    uint16_t nb_tx;

    if (!proc || !ctx) {
        return FDIR_INVALID_PARAM;
    }

    /* 发送数据包 */
    nb_tx = rte_eth_tx_burst(proc->port_id, dst_queue, &ctx->mbuf, 1);

    if (nb_tx < 1) {
        pthread_mutex_lock(&proc->lock);
        proc->stats.queue_full++;
        pthread_mutex_unlock(&proc->lock);
        return FDIR_NO_BUFFER;
    }

    /* 更新统计 */
    pthread_mutex_lock(&proc->lock);
    proc->stats.tx_packets++;
    proc->stats.bytes_sent += ctx->mbuf->pkt_len;
    pthread_mutex_unlock(&proc->lock);

    return FDIR_SUCCESS;
}

/**
 * 丢弃数据包
 */
int fdir_packet_drop(struct fdir_packet_processor *proc,
                    struct fdir_packet_ctx *ctx)
{
    if (!proc || !ctx) {
        return FDIR_INVALID_PARAM;
    }

    /* 释放mbuf */
    rte_pktmbuf_free(ctx->mbuf);

    /* 更新统计 */
    pthread_mutex_lock(&proc->lock);
    proc->stats.drop_packets++;
    pthread_mutex_unlock(&proc->lock);

    return FDIR_SUCCESS;
}

/**
 * 验证数据包
 */
int fdir_packet_validate(struct fdir_packet_ctx *ctx)
{
    if (!ctx || !ctx->mbuf) {
        return FDIR_INVALID_PARAM;
    }

    /* 检查mbuf有效性 */
    if (ctx->mbuf->pkt_len == 0) {
        return FDIR_ERROR;
    }

    /* 检查L2层 */
    if (!ctx->eth_hdr) {
        return FDIR_ERROR;
    }

    /* 检查IP层 */
    if (ctx->has_ipv4) {
        if (!ctx->ipv4_hdr) {
            return FDIR_ERROR;
        }
        /* 检查IP版本 */
        if ((ctx->ipv4_hdr->version_ihl >> 4) != 4) {
            return FDIR_ERROR;
        }
    } else if (ctx->has_ipv6) {
        if (!ctx->ipv6_hdr) {
            return FDIR_ERROR;
        }
        /* 检查IP版本 */
        if ((ctx->ipv6_hdr->vtc_flow >> 28) != 6) {
            return FDIR_ERROR;
        }
    }

    /* 检查L4层 */
    if (ctx->has_tcp) {
        if (!ctx->tcp_hdr) {
            return FDIR_ERROR;
        }
    } else if (ctx->has_udp) {
        if (!ctx->udp_hdr) {
            return FDIR_ERROR;
        }
    }

    return FDIR_SUCCESS;
}

/**
 * 检查数据包是否有效
 */
bool fdir_packet_is_valid(const struct fdir_packet_ctx *ctx)
{
    if (!ctx || !ctx->mbuf) {
        return false;
    }

    return ctx->mbuf->pkt_len > 0 && ctx->eth_hdr != NULL;
}

/**
 * 检查是否为IPv4包
 */
bool fdir_packet_is_ipv4(const struct fdir_packet_ctx *ctx)
{
    return ctx && ctx->has_ipv4;
}

/**
 * 检查是否为IPv6包
 */
bool fdir_packet_is_ipv6(const struct fdir_packet_ctx *ctx)
{
    return ctx && ctx->has_ipv6;
}

/**
 * 检查是否为TCP包
 */
bool fdir_packet_is_tcp(const struct fdir_packet_ctx *ctx)
{
    return ctx && ctx->has_tcp;
}

/**
 * 检查是否为UDP包
 */
bool fdir_packet_is_udp(const struct fdir_packet_ctx *ctx)
{
    return ctx && ctx->has_udp;
}

/**
 * 获取数据包哈希值
 */
uint32_t fdir_packet_get_hash(const struct fdir_packet_ctx *ctx)
{
    if (!ctx || !ctx->mbuf) {
        return 0;
    }

    /* 使用DPDK mbuf的哈希值 */
    return ctx->mbuf->hash.rss;
}

/**
 * 获取5元组哈希值
 */
uint32_t fdir_packet_get_5tuple_hash(const struct fdir_packet_ctx *ctx)
{
    uint8_t key[36];
    uint32_t key_len = 0;

    if (!ctx) {
        return 0;
    }

    /* IPv4 */
    if (ctx->has_ipv4 && ctx->ipv4_hdr) {
        memcpy(key + key_len, &ctx->ipv4_hdr->src_addr, 4);
        key_len += 4;
        memcpy(key + key_len, &ctx->ipv4_hdr->dst_addr, 4);
        key_len += 4;
    }
    /* IPv6 */
    else if (ctx->has_ipv6 && ctx->ipv6_hdr) {
        memcpy(key + key_len, ctx->ipv6_hdr->src_addr, 16);
        key_len += 16;
        memcpy(key + key_len, ctx->ipv6_hdr->dst_addr, 16);
        key_len += 16;
    } else {
        return 0;
    }

    /* 端口 */
    if (ctx->has_tcp && ctx->tcp_hdr) {
        memcpy(key + key_len, &ctx->tcp_hdr->src_port, 2);
        key_len += 2;
        memcpy(key + key_len, &ctx->tcp_hdr->dst_port, 2);
        key_len += 2;
    } else if (ctx->has_udp && ctx->udp_hdr) {
        memcpy(key + key_len, &ctx->udp_hdr->src_port, 2);
        key_len += 2;
        memcpy(key + key_len, &ctx->udp_hdr->dst_port, 2);
        key_len += 2;
    }

    /* 协议 */
    if (key_len > 0) {
        key[key_len] = ctx->l3_proto;
        key_len++;
    }

    return fdir_hash_jhash(key, key_len, 0);
}

/**
 * 获取载荷偏移
 */
uint16_t fdir_packet_get_payload_offset(const struct fdir_packet_ctx *ctx)
{
    if (!ctx || !ctx->app_data) {
        return 0;
    }

    return ctx->app_data - rte_pktmbuf_mtod(ctx->mbuf, uint8_t *);
}

/**
 * 获取载荷长度
 */
uint16_t fdir_packet_get_payload_len(const struct fdir_packet_ctx *ctx)
{
    if (!ctx) {
        return 0;
    }

    return ctx->app_data_len;
}

/**
 * 创建批处理
 */
int fdir_packet_batch_create(struct fdir_packet_batch *batch,
                            uint16_t max_count)
{
    if (!batch || max_count == 0) {
        return FDIR_INVALID_PARAM;
    }

    memset(batch, 0, sizeof(*batch));

    batch->mbufs = (struct rte_mbuf **)rte_zmalloc(
        "batch_mbufs", max_count * sizeof(struct rte_mbuf *), 0);
    if (!batch->mbufs) {
        return FDIR_NO_MEMORY;
    }

    batch->ctxs = (struct fdir_packet_ctx *)rte_zmalloc(
        "batch_ctxs", max_count * sizeof(struct fdir_packet_ctx), 0);
    if (!batch->ctxs) {
        rte_free(batch->mbufs);
        return FDIR_NO_MEMORY;
    }

    batch->max_count = max_count;
    batch->count = 0;

    return FDIR_SUCCESS;
}

/**
 * 销毁批处理
 */
int fdir_packet_batch_destroy(struct fdir_packet_batch *batch)
{
    if (!batch) {
        return FDIR_INVALID_PARAM;
    }

    if (batch->mbufs) {
        rte_free(batch->mbufs);
    }

    if (batch->ctxs) {
        rte_free(batch->ctxs);
    }

    memset(batch, 0, sizeof(*batch));

    return FDIR_SUCCESS;
}

/**
 * 添加mbuf到批处理
 */
int fdir_packet_batch_add(struct fdir_packet_batch *batch,
                         struct rte_mbuf *mbuf)
{
    if (!batch || !mbuf) {
        return FDIR_INVALID_PARAM;
    }

    if (batch->count >= batch->max_count) {
        return FDIR_NO_BUFFER;
    }

    batch->mbufs[batch->count] = mbuf;
    batch->count++;

    return FDIR_SUCCESS;
}

/**
 * 清空批处理
 */
int fdir_packet_batch_clear(struct fdir_packet_batch *batch)
{
    if (!batch) {
        return FDIR_INVALID_PARAM;
    }

    batch->count = 0;
    batch->timestamp = 0;

    return FDIR_SUCCESS;
}

/**
 * 获取统计信息
 */
int fdir_packet_stats_get(struct fdir_packet_processor *proc,
                         struct fdir_process_stats *stats)
{
    if (!proc || !stats) {
        return FDIR_INVALID_PARAM;
    }

    pthread_mutex_lock(&proc->lock);
    *stats = proc->stats;
    pthread_mutex_unlock(&proc->lock);

    return FDIR_SUCCESS;
}

/**
 * 重置统计信息
 */
int fdir_packet_stats_reset(struct fdir_packet_processor *proc)
{
    if (!proc) {
        return FDIR_INVALID_PARAM;
    }

    pthread_mutex_lock(&proc->lock);
    memset(&proc->stats, 0, sizeof(proc->stats));
    proc->stats.min_latency = 0xFFFFFFFFFFFFFFFFULL;
    pthread_mutex_unlock(&proc->lock);

    return FDIR_SUCCESS;
}

/**
 * 打印统计信息
 */
void fdir_packet_stats_print(const struct fdir_process_stats *stats)
{
    if (!stats) {
        return;
    }

    printf("\n=== Packet Processor Stats ===\n");
    printf("Rx Packets: %lu\n", stats->rx_packets);
    printf("Tx Packets: %lu\n", stats->tx_packets);
    printf("Drop Packets: %lu\n", stats->drop_packets);
    printf("Process Packets: %lu\n", stats->process_packets);
    printf("Bytes Received: %lu\n", stats->bytes_received);
    printf("Bytes Sent: %lu\n", stats->bytes_sent);
    printf("Bytes Processed: %lu\n", stats->bytes_processed);
    printf("Parse Errors: %lu\n", stats->parse_errors);
    printf("Flow Matches: %lu\n", stats->flow_matches);
    printf("Flow Misses: %lu\n", stats->flow_misses);
    printf("Queue Full: %lu\n", stats->queue_full);
    printf("Alloc Fail: %lu\n", stats->alloc_fail);
    printf("Timeout Count: %lu\n", stats->timeout_cnt);
    printf("Min Latency: %.2f us\n", stats->min_latency);
    printf("Max Latency: %.2f us\n", stats->max_latency);
    printf("Avg Latency: %.2f us\n", stats->avg_latency);

    printf("\nPacket Type Stats:\n");
    printf("  IPv4: %lu\n", stats->type_stats[FDIR_PACKET_TYPE_IPV4]);
    printf("  IPv6: %lu\n", stats->type_stats[FDIR_PACKET_TYPE_IPV6]);
    printf("  TCP: %lu\n", stats->type_stats[FDIR_PACKET_TYPE_TCP]);
    printf("  UDP: %lu\n", stats->type_stats[FDIR_PACKET_TYPE_UDP]);
    printf("  VLAN: %lu\n", stats->type_stats[FDIR_PACKET_TYPE_VLAN]);
    printf("  HTTP: %lu\n", stats->type_stats[FDIR_PACKET_TYPE_HTTP]);
    printf("  TLS: %lu\n", stats->type_stats[FDIR_PACKET_TYPE_TLS]);
    printf("===============================\n\n");
}

/**
 * 设置回调函数
 */
int fdir_packet_set_callback(struct fdir_packet_processor *proc,
                            void (*on_packet)(struct fdir_packet_processor *,
                                             struct fdir_packet_ctx *))
{
    if (!proc) {
        return FDIR_INVALID_PARAM;
    }

    proc->on_packet = on_packet;
    return FDIR_SUCCESS;
}

/**
 * 设置错误回调函数
 */
int fdir_packet_set_error_callback(struct fdir_packet_processor *proc,
                                  int (*on_error)(struct fdir_packet_processor *,
                                                 int, const char *))
{
    if (!proc) {
        return FDIR_INVALID_PARAM;
    }

    proc->on_error = on_error;
    return FDIR_SUCCESS;
}

/**
 * 设置统计回调函数
 */
int fdir_packet_set_stats_callback(struct fdir_packet_processor *proc,
                                  int (*on_stats)(struct fdir_packet_processor *,
                                                 const struct fdir_process_stats *))
{
    if (!proc) {
        return FDIR_INVALID_PARAM;
    }

    proc->on_stats = on_stats;
    return FDIR_SUCCESS;
}

/* 工具函数 */

/**
 * 包类型转字符串
 */
const char *fdir_packet_type_to_string(enum fdir_packet_type type)
{
    switch (type) {
    case FDIR_PACKET_TYPE_UNKNOWN:
        return "Unknown";
    case FDIR_PACKET_TYPE_IPV4:
        return "IPv4";
    case FDIR_PACKET_TYPE_IPV6:
        return "IPv6";
    case FDIR_PACKET_TYPE_TCP:
        return "TCP";
    case FDIR_PACKET_TYPE_UDP:
        return "UDP";
    case FDIR_PACKET_TYPE_ICMP:
        return "ICMP";
    case FDIR_PACKET_TYPE_VLAN:
        return "VLAN";
    case FDIR_PACKET_TYPE_HTTP:
        return "HTTP";
    case FDIR_PACKET_TYPE_TLS:
        return "TLS";
    default:
        return "Invalid";
    }
}

/**
 * 处理模式转字符串
 */
const char *fdir_process_mode_to_string(enum fdir_process_mode mode)
{
    switch (mode) {
    case FDIR_PROCESS_MODE_POLL:
        return "Poll";
    case FDIR_PROCESS_MODE_INTERRUPT:
        return "Interrupt";
    case FDIR_PROCESS_MODE_EVENT:
        return "Event";
    default:
        return "Unknown";
    }
}

/**
 * 获取时间戳
 */
uint64_t fdir_packet_get_timestamp(void)
{
    return fdir_get_tsc_cycles();
}

/**
 * 计算延迟
 */
double fdir_packet_calc_latency(uint64_t start_time, uint64_t end_time)
{
    if (end_time <= start_time) {
        return 0.0;
    }

    return fdir_cycles_to_usec(end_time - start_time);
}

/* 内部函数实现 */

/**
 * 预取mbuf数据
 */
static inline void fdir_packet_prefetch(struct rte_mbuf *mbuf)
{
    if (!mbuf) {
        return;
    }

    /* 预取mbuf结构 */
    rte_prefetch0(mbuf);

    /* 预取包数据 */
    if (mbuf->buf_addr) {
        rte_prefetch0(mbuf->buf_addr);
    }
}

/**
 * 数据包处理线程
 */
static void *fdir_packet_processor_thread(void *arg)
{
    struct fdir_packet_processor *proc = (struct fdir_packet_processor *)arg;
    uint64_t last_stats_time = 0;
    uint64_t current_time;

    printf("Packet processor thread started: port=%u, queue=%u\n",
           proc->port_id, proc->queue_id);

    while (proc->running) {
        /* 处理数据包 */
        int nb_rx = fdir_packet_process(proc);
        if (nb_rx < 0) {
            if (proc->on_error) {
                proc->on_error(proc, nb_rx, "Packet process error");
            }
            continue;
        }

        /* 定期输出统计信息 */
        current_time = fdir_get_tsc_cycles();
        if (proc->config.enable_stats &&
            (current_time - last_stats_time) > proc->config.stats_interval * fdir_get_timer_hz()) {
            if (proc->on_stats) {
                proc->on_stats(proc, &proc->stats);
            }
            last_stats_time = current_time;
        }

        /* 如果没有数据包，短暂休眠 */
        if (nb_rx == 0) {
            usleep(100);
        }
    }

    printf("Packet processor thread stopped\n");
    return NULL;
}

#if FDIR_DEBUG
/**
 * 调试：打印数据包上下文
 */
void fdir_packet_print_ctx(const struct fdir_packet_ctx *ctx)
{
    if (!ctx) {
        printf("Packet context is NULL\n");
        return;
    }

    printf("\n=== Packet Context ===\n");
    printf("Port: %u\n", ctx->port_id);
    printf("Queue: %u\n", ctx->queue_id);
    printf("Timestamp: %lu\n", ctx->timestamp);
    printf("Type: %s\n", fdir_packet_type_to_string(ctx->type));
    printf("Flow ID: %u\n", ctx->flow_id);
    printf("Pkt Len: %u\n", ctx->pkt_len);
    printf("Data Len: %u\n", ctx->data_len);
    printf("Has VLAN: %s\n", ctx->has_vlan ? "Yes" : "No");
    printf("Has IPv4: %s\n", ctx->has_ipv4 ? "Yes" : "No");
    printf("Has IPv6: %s\n", ctx->has_ipv6 ? "Yes" : "No");
    printf("Has TCP: %s\n", ctx->has_tcp ? "Yes" : "No");
    printf("Has UDP: %s\n", ctx->has_udp ? "Yes" : "No");
    printf("Has HTTP: %s\n", ctx->has_http ? "Yes" : "No");
    printf("Has TLS: %s\n", ctx->has_tls ? "Yes" : "No");
    printf("App Data Len: %u\n", ctx->app_data_len);
    printf("======================\n\n");
}

/**
 * 调试：打印十六进制数据
 */
void fdir_packet_print_hex(const uint8_t *data, uint16_t len)
{
    uint16_t i;

    if (!data || len == 0) {
        return;
    }

    for (i = 0; i < len; i++) {
        if (i % 16 == 0) {
            printf("%04x: ", i);
        }
        printf("%02x ", data[i]);
        if (i % 16 == 15) {
            printf("\n");
        }
    }
    if (len % 16 != 0) {
        printf("\n");
    }
}

/**
 * 调试：打印数据包头部
 */
void fdir_packet_print_headers(const struct fdir_packet_ctx *ctx)
{
    if (!ctx) {
        return;
    }

    /* 打印以太网头 */
    if (ctx->eth_hdr) {
        fdir_print_eth_hdr(ctx->eth_hdr);
    }

    /* 打印VLAN头 */
    if (ctx->vlan_hdr) {
        fdir_print_vlan_hdr(ctx->vlan_hdr);
    }

    /* 打印IPv4头 */
    if (ctx->ipv4_hdr) {
        fdir_print_ipv4_hdr(ctx->ipv4_hdr);
    }

    /* 打印IPv6头 */
    if (ctx->ipv6_hdr) {
        fdir_print_ipv6_hdr(ctx->ipv6_hdr);
    }

    /* 打印TCP头 */
    if (ctx->tcp_hdr) {
        fdir_print_tcp_hdr(ctx->tcp_hdr);
    }

    /* 打印UDP头 */
    if (ctx->udp_hdr) {
        fdir_print_udp_hdr(ctx->udp_hdr);
    }
}
#endif /* FDIR_DEBUG */