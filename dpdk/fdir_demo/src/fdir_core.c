/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_lcore.h>
#include <rte_jhash.h>
#include <rte_hash_crc.h>
#include "fdir_core.h"
#include "dpdk_utils.h"

/* 内部函数声明 */
static int fdir_configure_port(struct fdir_context *ctx, uint16_t port_id);
static int fdir_setup_queues(struct fdir_context *ctx, uint16_t port_id);
static int fdir_validate_flow_rule(struct fdir_flow_rule *rule,
                                  struct rte_flow_error *error);

/**
 * 初始化FDIR上下文
 */
int fdir_init(struct fdir_context *ctx, uint16_t port_mask)
{
    uint16_t port_id;
    int ret;

    if (!ctx) {
        printf("Error: Invalid FDIR context\n");
        return FDIR_INVALID_PARAM;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->enabled_port_mask = port_mask;

    /* 初始化统计锁 */
    if (pthread_mutex_init(&ctx->stats_lock, NULL) != 0) {
        printf("Error: Failed to initialize stats lock\n");
        return FDIR_ERROR;
    }

    /* 获取网卡数量 */
    ctx->nb_ports = rte_eth_dev_count_avail();
    if (ctx->nb_ports == 0) {
        printf("Error: No Ethernet ports available\n");
        return FDIR_NOT_FOUND;
    }

    printf("Found %u ports\n", ctx->nb_ports);

    /* 初始化每个启用的端口 */
    RTE_ETH_FOREACH_DEV(port_id) {
        if (!(port_mask & (1u << port_id)))
            continue;

        printf("Initializing port %u...\n", port_id);

        /* 设置默认端口配置 */
        struct fdir_port_config *port_cfg = &ctx->ports[port_id];
        port_cfg->port_id = port_id;
        port_cfg->nb_rx_queues = FDIR_DEFAULT_RX_QUEUES;
        port_cfg->nb_tx_queues = FDIR_DEFAULT_TX_QUEUES;
        port_cfg->nb_rx_desc = 1024;
        port_cfg->nb_tx_desc = 1024;
        port_cfg->promiscuous = true;
        port_cfg->rss_enable = true;
        port_cfg->rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP;

        /* 生成RSS密钥 */
        for (int i = 0; i < 40; i++) {
            port_cfg->rss_key[i] = rte_rand();
        }

        /* 配置端口 */
        ret = fdir_configure_port(ctx, port_id);
        if (ret != FDIR_SUCCESS) {
            printf("Error: Failed to configure port %u: %d\n", port_id, ret);
            continue;
        }

        /* 启动端口 */
        ret = rte_eth_dev_start(port_id);
        if (ret < 0) {
            printf("Error: Failed to start port %u: %s\n",
                   port_id, rte_strerror(-ret));
            continue;
        }

        printf("Port %u started successfully\n", port_id);

        /* 获取端口MAC地址 */
        struct rte_ether_addr mac_addr;
        rte_eth_macaddr_get(port_id, &mac_addr);
        printf("Port %u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               port_id,
               mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
               mac_addr.addr_bytes[2], mac_addr.addr_bytes[3],
               mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
    }

    ctx->initialized = true;
    ctx->running = false;

    printf("FDIR initialized successfully\n");
    return FDIR_SUCCESS;
}

/**
 * 清理FDIR上下文
 */
int fdir_cleanup(struct fdir_context *ctx)
{
    uint16_t port_id;

    if (!ctx || !ctx->initialized) {
        return FDIR_INVALID_PARAM;
    }

    /* 停止所有端口 */
    RTE_ETH_FOREACH_DEV(port_id) {
        if (!(ctx->enabled_port_mask & (1u << port_id)))
            continue;

        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
    }

    /* 销毁统计锁 */
    pthread_mutex_destroy(&ctx->stats_lock);

    memset(ctx, 0, sizeof(*ctx));

    printf("FDIR cleanup completed\n");
    return FDIR_SUCCESS;
}

/**
 * 配置端口
 */
static int fdir_configure_port(struct fdir_context *ctx, uint16_t port_id)
{
    struct fdir_port_config *port_cfg = &ctx->ports[port_id];
    struct rte_eth_conf port_conf;
    struct rte_eth_rxconf rx_conf;
    struct rte_eth_txconf tx_conf;
    int ret;

    /* 重置配置 */
    memset(&port_conf, 0, sizeof(port_conf));
    memset(&rx_conf, 0, sizeof(rx_conf));
    memset(&tx_conf, 0, sizeof(tx_conf));

    /* 配置端口基本参数 */
    port_conf.rxmode.max_rx_pkt_len = RTE_ETHER_MAX_LEN;
    port_conf.rxmode.offloads = DEV_RX_OFFLOAD_CHECKSUM |
                                 DEV_RX_OFFLOAD_VLAN_STRIP |
                                 DEV_RX_OFFLOAD_JUMBO_FRAME;

    /* 配置RSS */
    if (port_cfg->rss_enable) {
        port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
        port_conf.rx_adv_conf.rss_conf.rss_key = port_cfg->rss_key;
        port_conf.rx_adv_conf.rss_conf.rss_key_len = 40;
        port_conf.rx_adv_conf.rss_conf.rss_hf = port_cfg->rss_hf;
    }

    /* 配置队列 */
    ret = rte_eth_dev_configure(port_id, port_cfg->nb_rx_queues,
                               port_cfg->nb_tx_queues, &port_conf);
    if (ret < 0) {
        printf("Error: Failed to configure port %u: %s\n",
               port_id, rte_strerror(-ret));
        return FDIR_ERROR;
    }

    /* 创建内存池 */
    ret = fdir_mbuf_pool_create(ctx, port_id, 8192, FDIR_DEFAULT_MBUF_CACHE);
    if (ret != FDIR_SUCCESS) {
        printf("Error: Failed to create mbuf pool for port %u\n", port_id);
        return FDIR_ERROR;
    }

    /* 设置接收队列配置 */
    rx_conf.rx_free_thresh = 32;
    rx_conf.rx_drop_en = 1;
    rx_conf.offloads = port_conf.rxmode.offloads;

    /* 设置发送队列配置 */
    tx_conf.tx_free_thresh = 32;
    tx_conf.offloads = DEV_TX_OFFLOAD_VLAN_INSERT |
                       DEV_TX_OFFLOAD_IPV4_CKSUM |
                       DEV_TX_OFFLOAD_UDP_CKSUM |
                       DEV_TX_OFFLOAD_TCP_CKSUM;

    /* 设置队列 */
    ret = fdir_setup_queues(ctx, port_id);
    if (ret != FDIR_SUCCESS) {
        printf("Error: Failed to setup queues for port %u\n", port_id);
        return ret;
    }

    /* 配置RSS重定向表 */
    if (port_cfg->rss_enable) {
        ret = fdir_rss_configure(ctx, port_id);
        if (ret != FDIR_SUCCESS) {
            printf("Warning: Failed to configure RSS for port %u\n", port_id);
            /* RSS失败不是致命错误，继续执行 */
        }
    }

    return FDIR_SUCCESS;
}

/**
 * 设置队列
 */
static int fdir_setup_queues(struct fdir_context *ctx, uint16_t port_id)
{
    struct fdir_port_config *port_cfg = &ctx->ports[port_id];
    int ret;

    /* 设置接收队列 */
    for (uint16_t q = 0; q < port_cfg->nb_rx_queues; q++) {
        ret = rte_eth_rx_queue_setup(port_id, q, port_cfg->nb_rx_desc,
                                    rte_eth_dev_socket_id(port_id),
                                    NULL, port_cfg->mbuf_pool);
        if (ret < 0) {
            printf("Error: Failed to setup Rx queue %u on port %u: %s\n",
                   q, port_id, rte_strerror(-ret));
            return FDIR_ERROR;
        }
    }

    /* 设置发送队列 */
    for (uint16_t q = 0; q < port_cfg->nb_tx_queues; q++) {
        ret = rte_eth_tx_queue_setup(port_id, q, port_cfg->nb_tx_desc,
                                    rte_eth_dev_socket_id(port_id),
                                    NULL);
        if (ret < 0) {
            printf("Error: Failed to setup Tx queue %u on port %u: %s\n",
                   q, port_id, rte_strerror(-ret));
            return FDIR_ERROR;
        }
    }

    return FDIR_SUCCESS;
}

/**
 * 创建mbuf内存池
 */
int fdir_mbuf_pool_create(struct fdir_context *ctx, uint16_t port_id,
                         uint32_t nb_mbufs, uint16_t mbuf_cache_size)
{
    struct fdir_port_config *port_cfg = &ctx->ports[port_id];
    char pool_name[RTE_MEMPOOL_NAMESIZE];
    struct rte_mempool *mp;
    uint32_t socket_id;

    /* 检查是否已经创建 */
    if (port_cfg->mbuf_pool) {
        return FDIR_SUCCESS;
    }

    /* 生成内存池名称 */
    snprintf(pool_name, sizeof(pool_name), "mbuf_pool_%u", port_id);
    socket_id = rte_eth_dev_socket_id(port_id);

    /* 创建内存池 */
    mp = rte_pktmbuf_pool_create(pool_name, nb_mbufs, mbuf_cache_size,
                                 0, FDIR_DEFAULT_MBUF_SIZE, socket_id);
    if (!mp) {
        printf("Error: Failed to create mbuf pool %s\n", pool_name);
        return FDIR_NO_MEMORY;
    }

    port_cfg->mbuf_pool = mp;
    printf("Created mbuf pool %s with %u mbufs\n", pool_name, nb_mbufs);

    return FDIR_SUCCESS;
}

/**
 * 配置RSS
 */
int fdir_rss_configure(struct fdir_context *ctx, uint16_t port_id)
{
    struct fdir_port_config *port_cfg = &ctx->ports[port_id];

    /* RSS已在端口配置中启用，这里不需要额外配置 */
    printf("RSS enabled for port %u with %u queues\n",
           port_id, port_cfg->nb_rx_queues);

    return FDIR_SUCCESS;
}

/**
 * 启动端口
 */
int fdir_port_start(struct fdir_context *ctx, uint16_t port_id)
{
    int ret;

    if (!ctx || !ctx->initialized) {
        return FDIR_INVALID_PARAM;
    }

    if (!fdir_port_is_valid(port_id)) {
        return FDIR_INVALID_PARAM;
    }

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        printf("Error: Failed to start port %u: %s\n",
               port_id, rte_strerror(-ret));
        return FDIR_ERROR;
    }

    /* 设置混杂模式 */
    if (ctx->ports[port_id].promiscuous) {
        rte_eth_promiscuous_enable(port_id);
    }

    printf("Port %u started\n", port_id);
    return FDIR_SUCCESS;
}

/**
 * 停止端口
 */
int fdir_port_stop(struct fdir_context *ctx, uint16_t port_id)
{
    if (!ctx || !ctx->initialized) {
        return FDIR_INVALID_PARAM;
    }

    if (!fdir_port_is_valid(port_id)) {
        return FDIR_INVALID_PARAM;
    }

    rte_eth_dev_stop(port_id);
    printf("Port %u stopped\n", port_id);
    return FDIR_SUCCESS;
}

/**
 * 获取端口统计信息
 */
int fdir_port_stats_get(struct fdir_context *ctx, uint16_t port_id,
                       struct fdir_port_stats *stats)
{
    int ret;

    if (!ctx || !stats || !ctx->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_mutex_lock(&ctx->stats_lock);

    /* 获取网卡统计 */
    ret = rte_eth_stats_get(port_id, &stats->eth_stats);
    if (ret < 0) {
        printf("Error: Failed to get stats for port %u\n", port_id);
        pthread_mutex_unlock(&ctx->stats_lock);
        return FDIR_ERROR;
    }

    /* 复制自定义统计 */
    *stats = ctx->port_stats[port_id];

    pthread_mutex_unlock(&ctx->stats_lock);

    return FDIR_SUCCESS;
}

/**
 * 重置端口统计信息
 */
int fdir_port_stats_reset(struct fdir_context *ctx, uint16_t port_id)
{
    if (!ctx || !ctx->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_mutex_lock(&ctx->stats_lock);

    /* 重置网卡统计 */
    rte_eth_stats_reset(port_id);

    /* 重置自定义统计 */
    memset(&ctx->port_stats[port_id], 0, sizeof(ctx->port_stats[port_id]));

    pthread_mutex_unlock(&ctx->stats_lock);

    return FDIR_SUCCESS;
}

/**
 * 创建flow规则
 */
int fdir_flow_create(struct fdir_context *ctx, struct fdir_flow_rule *rule)
{
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[16];
    struct rte_flow_action actions[8];
    struct rte_flow_error error;
    struct rte_flow *flow;
    int ret, idx = 0;

    if (!ctx || !rule || !ctx->initialized) {
        return FDIR_INVALID_PARAM;
    }

    /* 验证规则 */
    ret = fdir_validate_flow_rule(rule, &error);
    if (ret != FDIR_SUCCESS) {
        printf("Error: Invalid flow rule: %s\n", error.message);
        return ret;
    }

    /* 初始化属性 */
    memset(&attr, 0, sizeof(attr));
    attr.ingress = rule->ingress;
    attr.egress = rule->egress;
    attr.priority = rule->priority;

    /* 初始化模式和动作数组 */
    memset(pattern, 0, sizeof(pattern));
    memset(actions, 0, sizeof(actions));

    /* 构建模式 */

    /* Ethernet层 */
    struct rte_flow_item_eth eth_spec = {0};
    struct rte_flow_item_eth eth_mask = {0};
    bool eth_enabled = false;

    if (rule->match.src_mac_mask || rule->match.dst_mac_mask) {
        if (rule->match.src_mac_mask) {
            rte_memcpy(&eth_spec.src.addr_bytes, &rule->match.src_mac.addr_bytes,
                      RTE_ETHER_ADDR_LEN);
            memset(&eth_mask.src.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);
        }
        if (rule->match.dst_mac_mask) {
            rte_memcpy(&eth_spec.dst.addr_bytes, &rule->match.dst_mac.addr_bytes,
                      RTE_ETHER_ADDR_LEN);
            memset(&eth_mask.dst.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);
        }
        eth_enabled = true;
    }

    if (rule->match.ether_type != 0) {
        eth_spec.type = htons(rule->match.ether_type);
        eth_mask.type = 0xFFFF;
        eth_enabled = true;
    }

    if (eth_enabled) {
        pattern[idx].type = RTE_FLOW_ITEM_TYPE_ETH;
        pattern[idx].spec = &eth_spec;
        pattern[idx].mask = &eth_mask;
        idx++;
    }

    /* VLAN层 */
    if (rule->match.vlan_present) {
        struct rte_flow_item_vlan vlan_spec = {0};
        struct rte_flow_item_vlan vlan_mask = {0};

        vlan_spec.tci = htons(rule->match.vlan_tci);
        vlan_mask.tci = htons(rule->match.vlan_tci_mask);

        pattern[idx].type = RTE_FLOW_ITEM_TYPE_VLAN;
        pattern[idx].spec = &vlan_spec;
        pattern[idx].mask = &vlan_mask;
        idx++;
    }

    /* IPv4层 */
    if (rule->match.src_ip_mask || rule->match.dst_ip_mask ||
        rule->match.ip_proto_mask) {
        struct rte_flow_item_ipv4 ipv4_spec = {0};
        struct rte_flow_item_ipv4 ipv4_mask = {0};

        if (rule->match.src_ip_mask) {
            ipv4_spec.hdr.src_addr = htonl(rule->match.src_ip);
            ipv4_mask.hdr.src_addr = rule->match.src_ip_mask;
        }
        if (rule->match.dst_ip_mask) {
            ipv4_spec.hdr.dst_addr = htonl(rule->match.dst_ip);
            ipv4_mask.hdr.dst_addr = rule->match.dst_ip_mask;
        }
        if (rule->match.ip_proto_mask) {
            ipv4_spec.hdr.next_proto_id = rule->match.ip_proto;
            ipv4_mask.hdr.next_proto_id = rule->match.ip_proto_mask;
        }

        pattern[idx].type = RTE_FLOW_ITEM_TYPE_IPV4;
        pattern[idx].spec = &ipv4_spec;
        pattern[idx].mask = &ipv4_mask;
        idx++;
    }

    /* IPv6层 */
    if (rule->match.src_ip6[0] || rule->match.dst_ip6[0]) {
        struct rte_flow_item_ipv6 ipv6_spec = {0};
        struct rte_flow_item_ipv6 ipv6_mask = {0};

        if (rule->match.src_ip6[0]) {
            rte_memcpy(ipv6_spec.hdr.src_addr, rule->match.src_ip6, 16);
            memcpy(ipv6_mask.hdr.src_addr, rule->match.src_ip6_mask, 16);
        }
        if (rule->match.dst_ip6[0]) {
            rte_memcpy(ipv6_spec.hdr.dst_addr, rule->match.dst_ip6, 16);
            memcpy(ipv6_mask.hdr.dst_addr, rule->match.dst_ip6_mask, 16);
        }
        if (rule->match.ip_proto_mask) {
            ipv6_spec.hdr.proto = rule->match.ip_proto;
            ipv6_mask.hdr.proto = rule->match.ip_proto_mask;
        }

        pattern[idx].type = RTE_FLOW_ITEM_TYPE_IPV6;
        pattern[idx].spec = &ipv6_spec;
        pattern[idx].mask = &ipv6_mask;
        idx++;
    }

    /* TCP层 */
    if (rule->match.src_port_mask || rule->match.dst_port_mask ||
        rule->match.tcp_flags_mask) {
        struct rte_flow_item_tcp tcp_spec = {0};
        struct rte_flow_item_tcp tcp_mask = {0};

        if (rule->match.src_port_mask) {
            tcp_spec.hdr.src_port = htons(rule->match.src_port);
            tcp_mask.hdr.src_port = htons(rule->match.src_port_mask);
        }
        if (rule->match.dst_port_mask) {
            tcp_spec.hdr.dst_port = htons(rule->match.dst_port);
            tcp_mask.hdr.dst_port = htons(rule->match.dst_port_mask);
        }
        if (rule->match.tcp_flags_mask) {
            tcp_spec.hdr.tcp_flags = rule->match.tcp_flags;
            tcp_mask.hdr.tcp_flags = rule->match.tcp_flags_mask;
        }

        pattern[idx].type = RTE_FLOW_ITEM_TYPE_TCP;
        pattern[idx].spec = &tcp_spec;
        pattern[idx].mask = &tcp_mask;
        idx++;
    }

    /* UDP层 */
    if (rule->match.src_port_mask || rule->match.dst_port_mask) {
        struct rte_flow_item_udp udp_spec = {0};
        struct rte_flow_item_udp udp_mask = {0};

        if (rule->match.src_port_mask) {
            udp_spec.hdr.src_port = htons(rule->match.src_port);
            udp_mask.hdr.src_port = htons(rule->match.src_port_mask);
        }
        if (rule->match.dst_port_mask) {
            udp_spec.hdr.dst_port = htons(rule->match.dst_port);
            udp_mask.hdr.dst_port = htons(rule->match.dst_port_mask);
        }

        pattern[idx].type = RTE_FLOW_ITEM_TYPE_UDP;
        pattern[idx].spec = &udp_spec;
        pattern[idx].mask = &udp_mask;
        idx++;
    }

    /* 结束模式 */
    pattern[idx].type = RTE_FLOW_ITEM_TYPE_END;

    /* 构建动作 */
    idx = 0;

    /* 队列动作 */
    if (rule->action.queue != 0xFFFF) {
        struct rte_flow_action_queue queue = { .index = rule->action.queue };
        actions[idx].type = RTE_FLOW_ACTION_TYPE_QUEUE;
        actions[idx].conf = &queue;
        idx++;
    }

    /* 标记动作 */
    if (rule->action.mark != 0) {
        struct rte_flow_action_mark mark = { .id = rule->action.mark };
        actions[idx].type = RTE_FLOW_ACTION_TYPE_MARK;
        actions[idx].conf = &mark;
        idx++;
    }

    /* 计数动作 */
    if (rule->action.count) {
        actions[idx].type = RTE_FLOW_ACTION_TYPE_COUNT;
        idx++;
    }

    /* 结束动作 */
    actions[idx].type = RTE_FLOW_ACTION_TYPE_END;

    /* 创建flow */
    flow = rte_flow_create(rule->port_id, &attr, pattern, actions, &error);
    if (!flow) {
        printf("Error: Failed to create flow: %s\n", error.message);
        return FDIR_ERROR;
    }

    rule->rte_flow = flow;

    printf("Flow rule created successfully on port %u, queue %u\n",
           rule->port_id, rule->action.queue);

    return FDIR_SUCCESS;
}

/**
 * 销毁flow规则
 */
int fdir_flow_destroy(struct fdir_context *ctx, struct fdir_flow_rule *rule)
{
    struct rte_flow_error error;

    if (!ctx || !rule || !ctx->initialized) {
        return FDIR_INVALID_PARAM;
    }

    if (!rule->rte_flow) {
        return FDIR_SUCCESS; /* 已经销毁 */
    }

    if (rte_flow_destroy(rule->port_id, rule->rte_flow, &error) < 0) {
        printf("Error: Failed to destroy flow: %s\n", error.message);
        return FDIR_ERROR;
    }

    rule->rte_flow = NULL;
    printf("Flow rule destroyed\n");

    return FDIR_SUCCESS;
}

/**
 * 验证flow规则
 */
static int fdir_validate_flow_rule(struct fdir_flow_rule *rule,
                                  struct rte_flow_error *error)
{
    /* 检查基本参数 */
    if (!rule || !error) {
        return FDIR_INVALID_PARAM;
    }

    /* 检查端口ID */
    if (!fdir_port_is_valid(rule->port_id)) {
        error->message = "Invalid port ID";
        return FDIR_INVALID_PARAM;
    }

    /* 检查优先级 */
    if (rule->priority > 0xFFFF) {
        error->message = "Priority too high";
        return FDIR_INVALID_PARAM;
    }

    /* 检查队列索引 */
    if (rule->action.queue != 0xFFFF && rule->action.queue >= FDIR_MAX_QUEUES) {
        error->message = "Invalid queue index";
        return FDIR_INVALID_PARAM;
    }

    /* 检查IP地址 */
    if (rule->match.src_ip && !rule->match.src_ip_mask) {
        error->message = "Source IP mask required";
        return FDIR_INVALID_PARAM;
    }
    if (rule->match.dst_ip && !rule->match.dst_ip_mask) {
        error->message = "Destination IP mask required";
        return FDIR_INVALID_PARAM;
    }

    /* 检查端口 */
    if (rule->match.src_port && !rule->match.src_port_mask) {
        error->message = "Source port mask required";
        return FDIR_INVALID_PARAM;
    }
    if (rule->match.dst_port && !rule->match.dst_port_mask) {
        error->message = "Destination port mask required";
        return FDIR_INVALID_PARAM;
    }

    return FDIR_SUCCESS;
}

/**
 * 获取端口MAC地址
 */
int fdir_port_mac_addr_get(uint16_t port_id, struct rte_ether_addr *mac_addr)
{
    if (!mac_addr) {
        return FDIR_INVALID_PARAM;
    }

    if (!fdir_port_is_valid(port_id)) {
        return FDIR_INVALID_PARAM;
    }

    rte_eth_macaddr_get(port_id, mac_addr);
    return FDIR_SUCCESS;
}

/**
 * 更新统计信息
 */
int fdir_stats_update(struct fdir_context *ctx, uint16_t port_id,
                     uint16_t queue_id, uint32_t packet_count)
{
    if (!ctx || !ctx->initialized) {
        return FDIR_INVALID_PARAM;
    }

    if (!fdir_port_is_valid(port_id)) {
        return FDIR_INVALID_PARAM;
    }

    if (queue_id >= FDIR_MAX_QUEUES) {
        return FDIR_INVALID_PARAM;
    }

    pthread_mutex_lock(&ctx->stats_lock);

    ctx->port_stats[port_id].queue_stats[queue_id] += packet_count;
    ctx->port_stats[port_id].flow_matches += packet_count;

    pthread_mutex_unlock(&ctx->stats_lock);

    return FDIR_SUCCESS;
}

/**
 * 打印统计信息
 */
void fdir_stats_print(struct fdir_context *ctx)
{
    uint16_t port_id;

    if (!ctx || !ctx->initialized) {
        return;
    }

    printf("\n=== FDIR Statistics ===\n");

    RTE_ETH_FOREACH_DEV(port_id) {
        if (!(ctx->enabled_port_mask & (1u << port_id)))
            continue;

        struct fdir_port_stats *stats = &ctx->port_stats[port_id];

        printf("\nPort %u:\n", port_id);
        printf("  Flow matches: %lu\n", stats->flow_matches);
        printf("  Flow misses: %lu\n", stats->flow_misses);
        printf("  Queue stats:\n");

        for (uint16_t q = 0; q < FDIR_MAX_QUEUES; q++) {
            if (stats->queue_stats[q] > 0) {
                printf("    Queue %u: %lu packets\n", q, stats->queue_stats[q]);
            }
        }
    }

    printf("=======================\n\n");
}

/**
 * 重置所有统计信息
 */
int fdir_stats_reset_all(struct fdir_context *ctx)
{
    uint16_t port_id;

    if (!ctx || !ctx->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_mutex_lock(&ctx->stats_lock);

    RTE_ETH_FOREACH_DEV(port_id) {
        if (!(ctx->enabled_port_mask & (1u << port_id)))
            continue;

        memset(&ctx->port_stats[port_id], 0, sizeof(ctx->port_stats[port_id]));
        rte_eth_stats_reset(port_id);
    }

    pthread_mutex_unlock(&ctx->stats_lock);

    return FDIR_SUCCESS;
}

/**
 * 解析IPv4地址
 */
int fdir_parse_ipv4(const char *ip_str, uint32_t *ip_addr)
{
    struct in_addr addr;

    if (!ip_str || !ip_addr) {
        return FDIR_INVALID_PARAM;
    }

    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return FDIR_INVALID_PARAM;
    }

    *ip_addr = ntohl(addr.s_addr);
    return FDIR_SUCCESS;
}

/**
 * 解析IPv6地址
 */
int fdir_parse_ipv6(const char *ip_str, uint8_t *ip_addr)
{
    struct in6_addr addr;

    if (!ip_str || !ip_addr) {
        return FDIR_INVALID_PARAM;
    }

    if (inet_pton(AF_INET6, ip_str, &addr) != 1) {
        return FDIR_INVALID_PARAM;
    }

    memcpy(ip_addr, addr.s6_addr, 16);
    return FDIR_SUCCESS;
}

/**
 * 解析MAC地址
 */
int fdir_parse_mac(const char *mac_str, struct rte_ether_addr *mac_addr)
{
    if (!mac_str || !mac_addr) {
        return FDIR_INVALID_PARAM;
    }

    /* 格式: XX:XX:XX:XX:XX:XX */
    if (sscanf(mac_str, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
               &mac_addr->addr_bytes[0], &mac_addr->addr_bytes[1],
               &mac_addr->addr_bytes[2], &mac_addr->addr_bytes[3],
               &mac_addr->addr_bytes[4], &mac_addr->addr_bytes[5]) != 6) {
        return FDIR_INVALID_PARAM;
    }

    return FDIR_SUCCESS;
}

/**
 * 格式化IPv4地址
 */
const char *fdir_format_ipv4(uint32_t ip_addr, char *buf, size_t buf_len)
{
    struct in_addr addr;

    if (!buf || buf_len < IPV4_ADDR_STR_LEN) {
        return NULL;
    }

    addr.s_addr = htonl(ip_addr);
    inet_ntop(AF_INET, &addr, buf, buf_len);

    return buf;
}

/**
 * 格式化IPv6地址
 */
const char *fdir_format_ipv6(const uint8_t *ip_addr, char *buf, size_t buf_len)
{
    struct in6_addr addr;

    if (!ip_addr || !buf || buf_len < IPV6_ADDR_STR_LEN) {
        return NULL;
    }

    memcpy(addr.s6_addr, ip_addr, 16);
    inet_ntop(AF_INET6, &addr, buf, buf_len);

    return buf;
}

/**
 * 格式化MAC地址
 */
const char *fdir_format_mac(const struct rte_ether_addr *mac_addr,
                           char *buf, size_t buf_len)
{
    if (!mac_addr || !buf || buf_len < MAC_ADDR_STR_LEN) {
        return NULL;
    }

    snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_addr->addr_bytes[0], mac_addr->addr_bytes[1],
             mac_addr->addr_bytes[2], mac_addr->addr_bytes[3],
             mac_addr->addr_bytes[4], mac_addr->addr_bytes[5]);

    return buf;
}

#if FDIR_DEBUG
/**
 * 调试：打印flow规则
 */
void fdir_debug_print_flow_rule(struct fdir_flow_rule *rule)
{
    char buf[256];

    if (!rule) {
        printf("Flow rule is NULL\n");
        return;
    }

    printf("\n=== Flow Rule Debug ===\n");
    printf("ID: %u\n", rule->id);
    printf("Name: %s\n", rule->name);
    printf("Description: %s\n", rule->description);
    printf("Priority: %u\n", rule->priority);
    printf("Port: %u\n", rule->port_id);
    printf("Queue: %u\n", rule->action.queue);
    printf("Active: %s\n", rule->active ? "Yes" : "No");
    printf("Ingress: %s\n", rule->ingress ? "Yes" : "No");
    printf("Egress: %s\n", rule->egress ? "Yes" : "No");

    printf("\nMatch Conditions:\n");
    if (rule->match.src_ip_mask) {
        printf("  Src IP: %s\n",
               fdir_format_ipv4(rule->match.src_ip, buf, sizeof(buf)));
    }
    if (rule->match.dst_ip_mask) {
        printf("  Dst IP: %s\n",
               fdir_format_ipv4(rule->match.dst_ip, buf, sizeof(buf)));
    }
    if (rule->match.src_port_mask) {
        printf("  Src Port: %u\n", rule->match.src_port);
    }
    if (rule->match.dst_port_mask) {
        printf("  Dst Port: %u\n", rule->match.dst_port);
    }
    if (rule->match.vlan_present) {
        printf("  VLAN: %u\n", rule->match.vlan_tci);
    }

    printf("========================\n\n");
}

/**
 * 调试：打印端口配置
 */
void fdir_debug_print_port_config(struct fdir_port_config *port_cfg)
{
    if (!port_cfg) {
        printf("Port config is NULL\n");
        return;
    }

    printf("\n=== Port Config Debug ===\n");
    printf("Port ID: %u\n", port_cfg->port_id);
    printf("Rx Queues: %u\n", port_cfg->nb_rx_queues);
    printf("Tx Queues: %u\n", port_cfg->nb_tx_queues);
    printf("Rx Desc: %u\n", port_cfg->nb_rx_desc);
    printf("Tx Desc: %u\n", port_cfg->nb_tx_desc);
    printf("Promiscuous: %s\n", port_cfg->promiscuous ? "Yes" : "No");
    printf("RSS Enable: %s\n", port_cfg->rss_enable ? "Yes" : "No");
    printf("RSS HF: 0x%lx\n", port_cfg->rss_hf);
    printf("=============================\n\n");
}

/**
 * 调试：打印mbuf
 */
void fdir_debug_print_mbuf(struct rte_mbuf *mbuf)
{
    if (!mbuf) {
        printf("Mbuf is NULL\n");
        return;
    }

    printf("\n=== Mbuf Debug ===\n");
    printf("Addr: %p\n", mbuf);
    printf("Buf Addr: %p\n", mbuf->buf_addr);
    printf("Data Off: %u\n", mbuf->data_off);
    printf("Data Len: %u\n", mbuf->data_len);
    printf("Pkt Len: %u\n", mbuf->pkt_len);
    printf("Nb Segs: %u\n", mbuf->nb_segs);
    printf("Port: %u\n", mbuf->port);
    printf("Queue: %u\n", mbuf->queue);
    printf("===================\n\n");
}
#endif /* FDIR_DEBUG */