/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <arpa/inet.h>
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
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_spinlock.h>
#include <rte_rwlock.h>
#include <rte_ring.h>
#include <rte_hash.h>
#include <rte_log.h>
#include "dpdk_utils.h"
#include "fdir_config.h"

/* 全局变量 */
static struct {
    bool initialized;
    uint32_t lcore_count;
    uint32_t socket_count;
    struct fdir_timer_config timer_cfg;
    pthread_mutex_t log_mutex;
} g_dpdk_ctx = {0};

/**
 * EAL初始化
 */
int fdir_eal_init(struct fdir_eal_config *config)
{
    int ret;

    if (!config) {
        printf("Error: Invalid EAL config\n");
        return FDIR_INVALID_PARAM;
    }

    /* 初始化EAL */
    ret = rte_eal_init(config->argc, config->argv);
    if (ret < 0) {
        printf("Error: EAL initialization failed\n");
        return FDIR_ERROR;
    }

    /* 获取基本信息 */
    g_dpdk_ctx.lcore_count = rte_lcore_count();
    g_dpdk_ctx.socket_count = rte_socket_count();
    g_dpdk_ctx.initialized = true;

    /* 初始化日志互斥锁 */
    pthread_mutex_init(&g_dpdk_ctx.log_mutex, NULL);

    /* 初始化定时器 */
    fdir_timer_init(NULL);

    printf("DPDK EAL initialized\n");
    printf("  Master lcore: %u\n", rte_get_master_lcore());
    printf("  Lcore count: %u\n", g_dpdk_ctx.lcore_count);
    printf("  Socket count: %u\n", g_dpdk_ctx.socket_count);
    printf("  Memory channels: %u\n", rte_memory_get_nchannel());
    printf("  Memory rank: %u\n", rte_memory_get_nrank());

    return FDIR_SUCCESS;
}

/**
 * EAL清理
 */
int fdir_eal_cleanup(void)
{
    if (!g_dpdk_ctx.initialized) {
        return FDIR_SUCCESS;
    }

    /* 清理定时器 */
    fdir_timer_cleanup();

    /* 清理日志互斥锁 */
    pthread_mutex_destroy(&g_dpdk_ctx.log_mutex);

    /* 清理EAL */
    rte_eal_cleanup();

    memset(&g_dpdk_ctx, 0, sizeof(g_dpdk_ctx));

    return FDIR_SUCCESS;
}

/**
 * 获取lcore数量
 */
uint32_t fdir_get_lcore_count(void)
{
    return g_dpdk_ctx.lcore_count;
}

/**
 * 获取socket数量
 */
uint32_t fdir_get_socket_count(void)
{
    return g_dpdk_ctx.socket_count;
}

/**
 * 获取lcore的NUMA节点
 */
uint32_t fdir_get_numa_node(uint32_t lcore_id)
{
    return rte_lcore_to_socket_id(lcore_id);
}

/**
 * 检查lcore是否启用
 */
bool fdir_is_lcore_enabled(uint32_t lcore_id)
{
    return rte_lcore_is_enabled(lcore_id);
}

/**
 * 内存分配
 */
void *fdir_malloc(const char *type, size_t size, unsigned int align)
{
    return rte_zmalloc(type, size, align);
}

/**
 * 内存清零分配
 */
void *fdir_zmalloc(const char *type, size_t size, unsigned int align)
{
    return rte_zmalloc(type, size, align);
}

/**
 * 内存重新分配
 */
void *fdir_realloc(void *ptr, size_t size)
{
    return rte_realloc(ptr, size, 0);
}

/**
 * 释放内存
 */
void fdir_free(void *ptr)
{
    rte_free(ptr);
}

/**
 * 创建内存池
 */
int fdir_mempool_create(struct fdir_mempool_config *config,
                       struct rte_mempool **mp)
{
    if (!config || !mp) {
        return FDIR_INVALID_PARAM;
    }

    unsigned int flags = 0;
    if (config->single_file) {
        flags |= MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET;
    }

    *mp = rte_mempool_create(config->name,
                           config->nb_elements,
                           config->element_size,
                           config->cache_size,
                           0,
                           NULL, NULL, NULL, NULL,
                           config->socket_id,
                           flags);

    if (!*mp) {
        printf("Error: Failed to create mempool %s\n", config->name);
        return FDIR_NO_MEMORY;
    }

    printf("Created mempool %s\n", config->name);
    return FDIR_SUCCESS;
}

/**
 * 销毁内存池
 */
int fdir_mempool_destroy(struct rte_mempool *mp)
{
    if (!mp) {
        return FDIR_SUCCESS;
    }

    rte_mempool_free(mp);
    return FDIR_SUCCESS;
}

/**
 * 从内存池分配对象
 */
void *fdir_mempool_alloc(struct rte_mempool *mp)
{
    if (!mp) {
        return NULL;
    }

    void *obj;
    if (rte_mempool_get(mp, &obj) < 0) {
        return NULL;
    }

    return obj;
}

/**
 * 释放对象到内存池
 */
void fdir_mempool_free(struct rte_mempool *mp, void *obj)
{
    if (!mp || !obj) {
        return;
    }

    rte_mempool_put(mp, obj);
}

/**
 * 获取内存池可用对象数量
 */
uint32_t fdir_mempool_avail_count(struct rte_mempool *mp)
{
    if (!mp) {
        return 0;
    }

    return rte_mempool_avail_count(mp);
}

/**
 * 获取内存池使用中的对象数量
 */
uint32_t fdir_mempool_in_use_count(struct rte_mempool *mp)
{
    if (!mp) {
        return 0;
    }

    return rte_mempool_in_use_count(mp);
}

/**
 * 创建Ring
 */
int fdir_ring_create(struct fdir_ring_config *config, struct rte_ring **ring)
{
    if (!config || !ring) {
        return FDIR_INVALID_PARAM;
    }

    *ring = rte_ring_create(config->name, config->count, config->socket_id,
                           config->flags);

    if (!*ring) {
        printf("Error: Failed to create ring %s\n", config->name);
        return FDIR_ERROR;
    }

    printf("Created ring %s with %u elements\n", config->name, config->count);
    return FDIR_SUCCESS;
}

/**
 * 销毁Ring
 */
int fdir_ring_destroy(struct rte_ring *ring)
{
    if (!ring) {
        return FDIR_SUCCESS;
    }

    rte_ring_free(ring);
    return FDIR_SUCCESS;
}

/**
 * Ring入队
 */
int fdir_ring_enqueue(struct rte_ring *ring, void *obj)
{
    if (!ring || !obj) {
        return FDIR_INVALID_PARAM;
    }

    return rte_ring_enqueue(ring, obj);
}

/**
 * Ring出队
 */
int fdir_ring_dequeue(struct rte_ring *ring, void **obj)
{
    if (!ring || !obj) {
        return FDIR_INVALID_PARAM;
    }

    return rte_ring_dequeue(ring, obj);
}

/**
 * Ring批量入队
 */
int fdir_ring_enqueue_bulk(struct rte_ring *ring, void **obj, unsigned int n)
{
    if (!ring || !obj) {
        return FDIR_INVALID_PARAM;
    }

    return rte_ring_enqueue_bulk(ring, (void * const *)obj, n, NULL);
}

/**
 * Ring批量出队
 */
int fdir_ring_dequeue_bulk(struct rte_ring *ring, void **obj, unsigned int n)
{
    if (!ring || !obj) {
        return FDIR_INVALID_PARAM;
    }

    return rte_ring_dequeue_bulk(ring, obj, n, NULL);
}

/**
 * 获取Ring中元素数量
 */
int fdir_ring_count(struct rte_ring *ring)
{
    if (!ring) {
        return 0;
    }

    return rte_ring_count(ring);
}

/**
 * 获取Ring空闲空间
 */
int fdir_ring_free_count(struct rte_ring *ring)
{
    if (!ring) {
        return 0;
    }

    return rte_ring_free_count(ring);
}

/**
 * 检查Ring是否满
 */
bool fdir_ring_full(struct rte_ring *ring)
{
    if (!ring) {
        return true;
    }

    return rte_ring_full(ring);
}

/**
 * 检查Ring是否空
 */
bool fdir_ring_empty(struct rte_ring *ring)
{
    if (!ring) {
        return true;
    }

    return rte_ring_empty(ring);
}

/**
 * 创建Hash表
 */
int fdir_hash_create(struct fdir_hash_config *config, struct rte_hash **hash)
{
    if (!config || !hash) {
        return FDIR_INVALID_PARAM;
    }

    struct rte_hash_parameters params = {
        .name = config->name,
        .entries = config->entries,
        .key_len = config->key_len,
        .socket_id = config->socket_id,
        .hash_func = rte_jhash,
        .extra_flag = config->extra_flags
    };

    *hash = rte_hash_create(&params);
    if (!*hash) {
        printf("Error: Failed to create hash %s\n", config->name);
        return FDIR_ERROR;
    }

    printf("Created hash %s with %u entries\n", config->name, config->entries);
    return FDIR_SUCCESS;
}

/**
 * 销毁Hash表
 */
int fdir_hash_destroy(struct rte_hash *hash)
{
    if (!hash) {
        return FDIR_SUCCESS;
    }

    rte_hash_free(hash);
    return FDIR_SUCCESS;
}

/**
 * 添加键值对到Hash表
 */
int fdir_hash_add_key_data(struct rte_hash *hash, const void *key, void *data)
{
    if (!hash || !key) {
        return FDIR_INVALID_PARAM;
    }

    return rte_hash_add_key_data(hash, key, data);
}

/**
 * 从Hash表删除键
 */
int fdir_hash_del_key(struct rte_hash *hash, const void *key)
{
    if (!hash || !key) {
        return FDIR_INVALID_PARAM;
    }

    return rte_hash_del_key(hash, key);
}

/**
 * 查找Hash表中的值
 */
int fdir_hash_lookup_data(const struct rte_hash *hash, const void *key, void **data)
{
    if (!hash || !key || !data) {
        return FDIR_INVALID_PARAM;
    }

    return rte_hash_lookup_data(hash, key, data);
}

/**
 * Hash表批量查找
 */
int fdir_hash_lookup_bulk_data(const struct rte_hash *hash, const void **keys,
                              uint32_t num_keys, void **data)
{
    if (!hash || !keys || !data) {
        return FDIR_INVALID_PARAM;
    }

    uint64_t hit_mask = 0;
    return rte_hash_lookup_bulk_data(hash, keys, num_keys, &hit_mask, data);
}

/**
 * 获取Hash表中元素数量
 */
int fdir_hash_count(const struct rte_hash *hash)
{
    if (!hash) {
        return 0;
    }

    return rte_hash_count(hash);
}

/**
 * 重置Hash表
 */
void fdir_hash_reset(struct rte_hash *hash)
{
    if (hash) {
        rte_hash_reset(hash);
    }
}

/**
 * 初始化定时器
 */
int fdir_timer_init(struct fdir_timer_config *config)
{
    /* 初始化DPDK定时器子系统 */
    rte_timer_subsystem_init();

    if (config) {
        g_dpdk_ctx.timer_cfg = *config;
    } else {
        /* 使用默认配置 */
        g_dpdk_ctx.timer_cfg.hz = rte_get_timer_hz();
        g_dpdk_ctx.timer_cfg.cycles_per_sec = rte_get_tsc_hz();
        g_dpdk_ctx.timer_cfg.tsc_hz = rte_get_tsc_hz();
        g_dpdk_ctx.timer_cfg.timer_resolution = 1000; /* 1ms */
    }

    return FDIR_SUCCESS;
}

/**
 * 清理定时器
 */
void fdir_timer_cleanup(void)
{
    rte_timer_subsystem_finalize();
}

/**
 * 获取TSC周期
 */
uint64_t fdir_get_tsc_cycles(void)
{
    return rte_get_tsc_cycles();
}

/**
 * 获取TSC频率
 */
uint64_t fdir_get_tsc_hz(void)
{
    return rte_get_tsc_hz();
}

/**
 * 获取定时器周期
 */
uint64_t fdir_get_timer_cycles(void)
{
    return rte_get_timer_cycles();
}

/**
 * 获取定时器频率
 */
uint64_t fdir_get_timer_hz(void)
{
    return rte_get_timer_hz();
}

/**
 * 周期转换为微秒
 */
double fdir_cycles_to_usec(uint64_t cycles)
{
    return (double)cycles * 1000000.0 / g_dpdk_ctx.timer_cfg.tsc_hz;
}

/**
 * 周期转换为毫秒
 */
double fdir_cycles_to_msec(uint64_t cycles)
{
    return (double)cycles * 1000.0 / g_dpdk_ctx.timer_cfg.tsc_hz;
}

/**
 * 周期转换为秒
 */
double fdir_cycles_to_sec(uint64_t cycles)
{
    return (double)cycles / g_dpdk_ctx.timer_cfg.tsc_hz;
}

/**
 * 微秒转换为周期
 */
uint64_t fdir_usec_to_cycles(double usec)
{
    return (uint64_t)(usec * g_dpdk_ctx.timer_cfg.tsc_hz / 1000000.0);
}

/**
 * 毫秒转换为周期
 */
uint64_t fdir_msec_to_cycles(double msec)
{
    return (uint64_t)(msec * g_dpdk_ctx.timer_cfg.tsc_hz / 1000.0);
}

/**
 * 秒转换为周期
 */
uint64_t fdir_sec_to_cycles(double sec)
{
    return (uint64_t)(sec * g_dpdk_ctx.timer_cfg.tsc_hz);
}

/**
 * 延迟微秒
 */
void fdir_delay_us(unsigned int us)
{
    rte_delay_us(us);
}

/**
 * 延迟毫秒
 */
void fdir_delay_ms(unsigned int ms)
{
    rte_delay_ms(ms);
}

/**
 * 延迟秒
 */
void fdir_delay_sec(unsigned int sec)
{
    rte_delay_us(sec * 1000000);
}

/**
 * 获取端口信息
 */
int fdir_get_port_info(uint16_t port_id, struct fdir_port_info *info)
{
    struct rte_eth_dev_info dev_info;
    struct rte_eth_link link;
    int ret;

    if (!info || !fdir_port_is_valid(port_id)) {
        return FDIR_INVALID_PARAM;
    }

    memset(info, 0, sizeof(*info));
    info->port_id = port_id;

    /* 获取设备信息 */
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret < 0) {
        return FDIR_ERROR;
    }

    info->max_rx_queues = dev_info.max_rx_queues;
    info->max_tx_queues = dev_info.max_tx_queues;
    info->rx_offload_capa = dev_info.rx_offload_capa;
    info->tx_offload_capa = dev_info.tx_offload_capa;
    info->rx_queue_offload_capa = dev_info.rx_queue_offload_capa;
    info->tx_queue_offload_capa = dev_info.tx_queue_offload_capa;
    info->dev_flags = dev_info.dev_flags ? *(dev_info.dev_flags) : 0;
    strncpy(info->driver_name, (const char *)dev_info.driver_name, sizeof(info->driver_name) - 1);

    /* 获取MAC地址 */
    rte_eth_macaddr_get(port_id, &info->mac_addr);

    /* 获取链路信息 */
    ret = rte_eth_link_get(port_id, &link);
    if (ret == 0) {
        info->link_speed = link.link_speed;
        info->link_duplex = link.link_duplex;
        info->link_autoneg = link.link_autoneg;
        info->link_status = link.link_status;
    }

    /* 获取MTU */
    rte_eth_dev_get_mtu(port_id, &info->mtu);

    return FDIR_SUCCESS;
}

/**
 * 获取端口列表
 */
int fdir_get_port_list(uint16_t *ports, uint16_t max_ports)
{
    uint16_t port_id;
    uint16_t count = 0;

    RTE_ETH_FOREACH_DEV(port_id) {
        if (ports && count < max_ports) {
            ports[count] = port_id;
        }
        count++;
    }

    return count;
}

/**
 * 获取端口数量
 */
uint16_t fdir_get_nb_ports(void)
{
    return rte_eth_dev_count_avail();
}

/**
 * 检查端口是否有效
 */
int fdir_port_is_valid(uint16_t port_id)
{
    return rte_eth_dev_is_valid_port(port_id);
}

/**
 * 检查MAC地址是否为零
 */
int fdir_mac_addr_is_zero(const struct rte_ether_addr *mac_addr)
{
    if (!mac_addr) {
        return 1;
    }

    return rte_is_zero_ether_addr(mac_addr);
}

/**
 * 检查MAC地址是否为广播地址
 */
int fdir_mac_addr_is_broadcast(const struct rte_ether_addr *mac_addr)
{
    if (!mac_addr) {
        return 0;
    }

    return rte_is_broadcast_ether_addr(mac_addr);
}

/**
 * 检查MAC地址是否为多播地址
 */
int fdir_mac_addr_is_multicast(const struct rte_ether_addr *mac_addr)
{
    if (!mac_addr) {
        return 0;
    }

    return rte_is_multicast_ether_addr(mac_addr);
}

/**
 * 检查MAC地址是否为单播地址
 */
int fdir_mac_addr_is_unicast(const struct rte_ether_addr *mac_addr)
{
    if (!mac_addr) {
        return 0;
    }

    return rte_is_unicast_ether_addr(mac_addr);
}

/**
 * 检查MAC地址是否有效
 */
int fdir_mac_addr_is_valid(const struct rte_ether_addr *mac_addr)
{
    if (!mac_addr) {
        return 0;
    }

    return rte_is_valid_assigned_ether_addr(mac_addr);
}

/**
 * 复制MAC地址
 */
int fdir_mac_addr_copy(struct rte_ether_addr *dst, const struct rte_ether_addr *src)
{
    if (!dst || !src) {
        return FDIR_INVALID_PARAM;
    }

    rte_ether_addr_copy(src, dst);
    return FDIR_SUCCESS;
}

/**
 * 格式化MAC地址
 */
int fdir_mac_addr_format(const struct rte_ether_addr *mac_addr,
                        char *buf, size_t buf_len)
{
    if (!mac_addr || !buf || buf_len < 18) {
        return FDIR_INVALID_PARAM;
    }

    snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_addr->addr_bytes[0], mac_addr->addr_bytes[1],
             mac_addr->addr_bytes[2], mac_addr->addr_bytes[3],
             mac_addr->addr_bytes[4], mac_addr->addr_bytes[5]);

    return FDIR_SUCCESS;
}

/**
 * 解析MAC地址
 */
int fdir_mac_addr_parse(const char *str, struct rte_ether_addr *mac_addr)
{
    if (!str || !mac_addr) {
        return FDIR_INVALID_PARAM;
    }

    /* 格式: XX:XX:XX:XX:XX:XX */
    if (sscanf(str, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
               &mac_addr->addr_bytes[0], &mac_addr->addr_bytes[1],
               &mac_addr->addr_bytes[2], &mac_addr->addr_bytes[3],
               &mac_addr->addr_bytes[4], &mac_addr->addr_bytes[5]) != 6) {
        return FDIR_INVALID_PARAM;
    }

    return FDIR_SUCCESS;
}

/**
 * 检查IPv4地址是否有效
 */
int fdir_ipv4_addr_is_valid(uint32_t addr)
{
    /* 排除0.0.0.0和255.255.255.255 */
    if (addr == 0 || addr == 0xFFFFFFFF) {
        return 0;
    }
    return 1;
}

/**
 * 检查IPv4地址是否为单播地址
 */
int fdir_ipv4_addr_is_unicast(uint32_t addr)
{
    if (!fdir_ipv4_addr_is_valid(addr)) {
        return 0;
    }

    /* 排除多播地址 (224.0.0.0/4) */
    if ((addr & 0xF0000000) == 0xE0000000) {
        return 0;
    }

    return 1;
}

/**
 * 检查IPv4地址是否为多播地址
 */
int fdir_ipv4_addr_is_multicast(uint32_t addr)
{
    /* 多播地址范围: 224.0.0.0 - 239.255.255.255 */
    return (addr & 0xF0000000) == 0xE0000000;
}

/**
 * 检查IPv4地址是否为广播地址
 */
int fdir_ipv4_addr_is_broadcast(uint32_t addr)
{
    return addr == 0xFFFFFFFF;
}

/**
 * 格式化IPv4地址
 */
int fdir_ipv4_addr_format(uint32_t addr, char *buf, size_t buf_len)
{
    struct in_addr in_addr;

    if (!buf || buf_len < 16) {
        return FDIR_INVALID_PARAM;
    }

    in_addr.s_addr = htonl(addr);
    if (!inet_ntop(AF_INET, &in_addr, buf, buf_len)) {
        return FDIR_ERROR;
    }

    return FDIR_SUCCESS;
}

/**
 * 解析IPv4地址
 */
int fdir_ipv4_addr_parse(const char *str, uint32_t *addr)
{
    struct in_addr in_addr;

    if (!str || !addr) {
        return FDIR_INVALID_PARAM;
    }

    if (inet_pton(AF_INET, str, &in_addr) != 1) {
        return FDIR_INVALID_PARAM;
    }

    *addr = ntohl(in_addr.s_addr);
    return FDIR_SUCCESS;
}

/**
 * 检查IPv6地址是否有效
 */
int fdir_ipv6_addr_is_valid(const uint8_t *addr)
{
    if (!addr) {
        return 0;
    }

    /* 检查是否全零 */
    int zero_count = 0;
    for (int i = 0; i < 16; i++) {
        if (addr[i] == 0) {
            zero_count++;
        }
    }

    /* 全零地址是有效的但特殊 */
    return zero_count < 16 || zero_count == 16;
}

/**
 * 检查IPv6地址是否为单播地址
 */
int fdir_ipv6_addr_is_unicast(const uint8_t *addr)
{
    if (!addr || !fdir_ipv6_addr_is_valid(addr)) {
        return 0;
    }

    /* 排除多播地址 (第一字节高位为1) */
    if (addr[0] & 0x80) {
        return 0;
    }

    return 1;
}

/**
 * 检查IPv6地址是否为多播地址
 */
int fdir_ipv6_addr_is_multicast(const uint8_t *addr)
{
    if (!addr) {
        return 0;
    }

    /* 多播地址: 第一字节为FF */
    return addr[0] == 0xFF;
}

/**
 * 检查IPv6地址是否为链路本地地址
 */
int fdir_ipv6_addr_is_link_local(const uint8_t *addr)
{
    if (!addr) {
        return 0;
    }

    /* 链路本地地址: FE80::/10 */
    return (addr[0] == 0xFE) && ((addr[1] & 0xC0) == 0x80);
}

/**
 * 格式化IPv6地址
 */
int fdir_ipv6_addr_format(const uint8_t *addr, char *buf, size_t buf_len)
{
    struct in6_addr in6_addr;

    if (!addr || !buf || buf_len < 46) {
        return FDIR_INVALID_PARAM;
    }

    memcpy(in6_addr.s6_addr, addr, 16);
    if (!inet_ntop(AF_INET6, &in6_addr, buf, buf_len)) {
        return FDIR_ERROR;
    }

    return FDIR_SUCCESS;
}

/**
 * 解析IPv6地址
 */
int fdir_ipv6_addr_parse(const char *str, uint8_t *addr)
{
    struct in6_addr in6_addr;

    if (!str || !addr) {
        return FDIR_INVALID_PARAM;
    }

    if (inet_pton(AF_INET6, str, &in6_addr) != 1) {
        return FDIR_INVALID_PARAM;
    }

    memcpy(addr, in6_addr.s6_addr, 16);
    return FDIR_SUCCESS;
}

/**
 * 设置线程CPU亲和性
 */
int fdir_set_thread_affinity(pthread_t thread, uint32_t lcore_id)
{
    cpu_set_t cpuset;
    uint32_t cpu_id = rte_lcore_to_cpu_id(lcore_id);

    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);

    return pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
}

/**
 * 获取线程CPU亲和性
 */
int fdir_get_thread_affinity(pthread_t thread, cpu_set_t *cpu_set)
{
    if (!cpu_set) {
        return FDIR_INVALID_PARAM;
    }

    return pthread_getaffinity_np(thread, sizeof(cpu_set_t), cpu_set);
}

/**
 * 设置当前线程CPU亲和性
 */
int fdir_set_cpu_affinity(uint32_t cpu_id)
{
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);

    return sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

/**
 * 获取当前CPU亲和性
 */
int fdir_get_cpu_affinity(cpu_set_t *cpu_set)
{
    if (!cpu_set) {
        return FDIR_INVALID_PARAM;
    }

    return sched_getaffinity(0, sizeof(cpu_set_t), cpu_set);
}

/**
 * 获取当前CPU
 */
uint32_t fdir_get_current_cpu(void)
{
    return sched_getcpu();
}

/**
 * 获取当前NUMA节点
 */
uint32_t fdir_get_current_numa_node(void)
{
    return rte_socket_id();
}

/**
 * 字符串转整数
 */
int fdir_str_to_int(const char *str, int *value)
{
    char *endptr;
    long val;

    if (!str || !value) {
        return FDIR_INVALID_PARAM;
    }

    errno = 0;
    val = strtol(str, &endptr, 0);

    if (errno != 0 || endptr == str) {
        return FDIR_INVALID_PARAM;
    }

    if (val > INT_MAX || val < INT_MIN) {
        return FDIR_INVALID_PARAM;
    }

    *value = (int)val;
    return FDIR_SUCCESS;
}

/**
 * 字符串转无符号32位整数
 */
int fdir_str_to_uint32(const char *str, uint32_t *value)
{
    char *endptr;
    unsigned long val;

    if (!str || !value) {
        return FDIR_INVALID_PARAM;
    }

    errno = 0;
    val = strtoul(str, &endptr, 0);

    if (errno != 0 || endptr == str) {
        return FDIR_INVALID_PARAM;
    }

    if (val > UINT32_MAX) {
        return FDIR_INVALID_PARAM;
    }

    *value = (uint32_t)val;
    return FDIR_SUCCESS;
}

/**
 * 字符串转无符号64位整数
 */
int fdir_str_to_uint64(const char *str, uint64_t *value)
{
    char *endptr;
    unsigned long long val;

    if (!str || !value) {
        return FDIR_INVALID_PARAM;
    }

    errno = 0;
    val = strtoull(str, &endptr, 0);

    if (errno != 0 || endptr == str) {
        return FDIR_INVALID_PARAM;
    }

    if (val > UINT64_MAX) {
        return FDIR_INVALID_PARAM;
    }

    *value = (uint64_t)val;
    return FDIR_SUCCESS;
}

/**
 * 字符串转布尔值
 */
int fdir_str_to_bool(const char *str, bool *value)
{
    if (!str || !value) {
        return FDIR_INVALID_PARAM;
    }

    if (strcasecmp(str, "true") == 0 ||
        strcasecmp(str, "1") == 0 ||
        strcasecmp(str, "yes") == 0 ||
        strcasecmp(str, "on") == 0) {
        *value = true;
        return FDIR_SUCCESS;
    }

    if (strcasecmp(str, "false") == 0 ||
        strcasecmp(str, "0") == 0 ||
        strcasecmp(str, "no") == 0 ||
        strcasecmp(str, "off") == 0) {
        *value = false;
        return FDIR_SUCCESS;
    }

    return FDIR_INVALID_PARAM;
}

/**
 * 去除字符串首尾空白
 */
char *fdir_str_trim(char *str)
{
    char *end;

    if (!str) {
        return NULL;
    }

    /* 去除前导空白 */
    while (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r') {
        str++;
    }

    /* 去除尾随空白 */
    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' ||
                        *end == '\n' || *end == '\r')) {
        end--;
    }
    *(end + 1) = '\0';

    return str;
}

/**
 * 字符串转小写
 */
char *fdir_strlwr(char *str)
{
    if (!str) {
        return NULL;
    }

    for (char *p = str; *p; p++) {
        *p = tolower(*p);
    }

    return str;
}

/**
 * 字符串转大写
 */
char *fdir_strupr(char *str)
{
    if (!str) {
        return NULL;
    }

    for (char *p = str; *p; p++) {
        *p = toupper(*p);
    }

    return str;
}

/**
 * 检查字符串是否为空
 */
int fdir_str_is_empty(const char *str)
{
    if (!str) {
        return 1;
    }

    return strlen(str) == 0;
}

/**
 * 检查字符串是否相等
 */
int fdir_str_is_equal(const char *str1, const char *str2, bool case_sensitive)
{
    if (!str1 || !str2) {
        return 0;
    }

    if (case_sensitive) {
        return strcmp(str1, str2) == 0;
    } else {
        return strcasecmp(str1, str2) == 0;
    }
}

/**
 * CRC32哈希
 */
uint32_t fdir_hash_crc32(const void *data, uint32_t len, uint32_t init_val)
{
    if (!data) {
        return 0;
    }

    return rte_hash_crc(data, len, init_val);
}

/**
 * CRC32C哈希
 */
uint32_t fdir_hash_crc32c(const void *data, uint32_t len, uint32_t init_val)
{
    if (!data) {
        return 0;
    }

    return rte_hash_crc(data, len, init_val);
}

/**
 * Jenkins哈希
 */
uint32_t fdir_hash_jhash(const void *data, uint32_t len, uint32_t init_val)
{
    if (!data) {
        return 0;
    }

    return rte_jhash(data, len, init_val);
}

/**
 * FNV1a哈希
 */
uint32_t fdir_hash_fnv1a(const void *data, uint32_t len)
{
    if (!data) {
        return 0;
    }

    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t hash = 2166136261u;

    for (uint32_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }

    return hash;
}

/**
 * Murmur3哈希（简化版）
 */
uint32_t fdir_hash_murmur3(const void *data, uint32_t len)
{
    if (!data) {
        return 0;
    }

    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t h = 0;
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;
    const uint32_t r1 = 15;
    const uint32_t r2 = 13;
    const uint32_t m = 5;
    const uint32_t n = 0xe6546b64;

    int nblocks = len / 4;
    const uint32_t *blocks = (const uint32_t *)bytes;

    for (int i = 0; i < nblocks; i++) {
        uint32_t k = blocks[i];
        k *= c1;
        k = (k << r1) | (k >> (32 - r1));
        k *= c2;

        h ^= k;
        h = (h << r2) | (h >> (32 - r2));
        h = h * m + n;
    }

    const uint8_t *tail = bytes + nblocks * 4;
    uint32_t k1 = 0;

    switch (len & 3) {
    case 3:
        k1 ^= tail[2] << 16;
    case 2:
        k1 ^= tail[1] << 8;
    case 1:
        k1 ^= tail[0];
        k1 *= c1;
        k1 = (k1 << r1) | (k1 >> (32 - r1));
        k1 *= c2;
        h ^= k1;
    }

    h ^= len;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    return h;
}

/**
 * xxHash64（简化版）
 */
uint64_t fdir_hash_xxhash64(const void *data, uint32_t len, uint64_t seed)
{
    if (!data) {
        return 0;
    }

    const uint64_t PRIME64_1 = 11400714785074694791ULL;
    const uint64_t PRIME64_2 = 14029467366897019727ULL;
    const uint64_t PRIME64_3 = 1609587929392839161ULL;
    const uint64_t PRIME64_4 = 9650029242287828579ULL;
    const uint64_t PRIME64_5 = 2870177450012600261ULL;

    const uint8_t *p = (const uint8_t *)data;
    const uint8_t *bend = p + len;

    uint64_t h64 = seed + PRIME64_5;

    if (len >= 32) {
        const uint8_t *limit = bend - 32;
        uint64_t v1 = seed + PRIME64_1 + PRIME64_2;
        uint64_t v2 = seed + PRIME64_2;
        uint64_t v3 = seed + 0;
        uint64_t v4 = seed - PRIME64_1;

        do {
            uint64_t k1 = *((uint64_t *)p);
            k1 *= PRIME64_2;
            k1 = ((k1 << 31) | (k1 >> (64 - 31))) * PRIME64_1;
            v1 += k1;
            v1 = ((v1 << 27) | (v1 >> (64 - 27))) + PRIME64_4;
            p += 8;

            uint64_t k2 = *((uint64_t *)p);
            k2 *= PRIME64_2;
            k2 = ((k2 << 31) | (k2 >> (64 - 31))) * PRIME64_1;
            v2 += k2;
            v2 = ((v2 << 27) | (v2 >> (64 - 27))) + PRIME64_4;
            p += 8;

            uint64_t k3 = *((uint64_t *)p);
            k3 *= PRIME64_2;
            k3 = ((k3 << 31) | (k3 >> (64 - 31))) * PRIME64_1;
            v3 += k3;
            v3 = ((v3 << 27) | (v3 >> (64 - 27))) + PRIME64_4;
            p += 8;

            uint64_t k4 = *((uint64_t *)p);
            k4 *= PRIME64_2;
            k4 = ((k4 << 31) | (k4 >> (64 - 31))) * PRIME64_1;
            v4 += k4;
            v4 = ((v4 << 27) | (v4 >> (64 - 27))) + PRIME64_4;
            p += 8;
        } while (p <= limit);

        h64 = ((v1 << 1) | (v1 >> (64 - 1))) +
              ((v2 << 7) | (v2 >> (64 - 7))) +
              ((v3 << 12) | (v3 >> (64 - 12))) +
              ((v4 << 18) | (v4 >> (64 - 18)));
    }

    h64 += len;

    while (p + 8 <= bend) {
        uint64_t k1 = *((uint64_t *)p);
        k1 *= PRIME64_2;
        k1 = ((k1 << 31) | (k1 >> (64 - 31))) * PRIME64_1;
        h64 ^= k1;
        h64 = ((h64 << 27) | (h64 >> (64 - 27))) * PRIME64_1 + PRIME64_4;
        p += 8;
    }

    if (p + 4 <= bend) {
        h64 ^= *((uint32_t *)p) * PRIME64_1;
        h64 = ((h64 << 23) | (h64 >> (64 - 23))) * PRIME64_2 + PRIME64_3;
        p += 4;
    }

    while (p < bend) {
        h64 ^= *p * PRIME64_5;
        h64 = ((h64 << 11) | (h64 >> (64 - 11))) * PRIME64_1;
        p++;
    }

    h64 ^= h64 >> 33;
    h64 *= PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= PRIME64_3;
    h64 ^= h64 >> 32;

    return h64;
}

/**
 * 错误日志
 */
void fdir_error(const char *func, const char *format, ...)
{
    va_list ap;
    char buf[1024];

    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);

    pthread_mutex_lock(&g_dpdk_ctx.log_mutex);
    fprintf(stderr, "[ERROR] %s: %s\n", func, buf);
    fflush(stderr);
    pthread_mutex_unlock(&g_dpdk_ctx.log_mutex);
}

/**
 * 警告日志
 */
void fdir_warn(const char *func, const char *format, ...)
{
    va_list ap;
    char buf[1024];

    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);

    pthread_mutex_lock(&g_dpdk_ctx.log_mutex);
    fprintf(stderr, "[WARN] %s: %s\n", func, buf);
    fflush(stderr);
    pthread_mutex_unlock(&g_dpdk_ctx.log_mutex);
}

/**
 * 信息日志
 */
void fdir_info(const char *func, const char *format, ...)
{
    va_list ap;
    char buf[1024];

    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);

    pthread_mutex_lock(&g_dpdk_ctx.log_mutex);
    printf("[INFO] %s: %s\n", func, buf);
    fflush(stdout);
    pthread_mutex_unlock(&g_dpdk_ctx.log_mutex);
}

/**
 * 调试日志
 */
void fdir_debug(const char *func, const char *format, ...)
{
#if FDIR_DEBUG
    va_list ap;
    char buf[1024];

    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);

    pthread_mutex_lock(&g_dpdk_ctx.log_mutex);
    printf("[DEBUG] %s: %s\n", func, buf);
    fflush(stdout);
    pthread_mutex_unlock(&g_dpdk_ctx.log_mutex);
#endif
}

#if FDIR_DEBUG
/**
 * 打印十六进制数据
 */
void fdir_print_hexdump(const char *title, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t i;

    if (!buf || len == 0) {
        return;
    }

    printf("%s (%zu bytes):\n", title, len);

    for (i = 0; i < len; i += 16) {
        printf("%04zx: ", i);

        /* 打印十六进制 */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02x ", p[i + j]);
            } else {
                printf("   ");
            }
        }

        printf(" |");

        /* 打印ASCII */
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            if (p[i + j] >= 32 && p[i + j] <= 126) {
                printf("%c", p[i + j]);
            } else {
                printf(".");
            }
        }

        printf("|\n");
    }
}

/**
 * 打印内存
 */
void fdir_print_memory(const void *ptr, size_t size)
{
    const uint32_t *p = (const uint32_t *)ptr;
    size_t count = size / 4;

    printf("Memory at %p (%zu bytes):\n", ptr, size);

    for (size_t i = 0; i < count; i += 4) {
        printf("%08zx: %08x %08x %08x %08x\n",
               i * 4,
               p[i + 0], p[i + 1],
               p[i + 2], p[i + 3]);
    }
}

/**
 * 打印mbuf
 */
void fdir_print_mbuf(const struct rte_mbuf *mbuf)
{
    if (!mbuf) {
        printf("Mbuf is NULL\n");
        return;
    }

    printf("\n=== Mbuf Info ===\n");
    printf("  buf_addr: %p\n", mbuf->buf_addr);
    printf("  buf_physaddr: %p\n", (void *)mbuf->buf_iova);
    printf("  data_off: %u\n", mbuf->data_off);
    printf("  data_len: %u\n", mbuf->data_len);
    printf("  pkt_len: %u\n", mbuf->pkt_len);
    printf("  nb_segs: %u\n", mbuf->nb_segs);
    printf("  port: %u\n", mbuf->port);
    printf("  queue: %u\n", mbuf->queue);
    printf("  ol_flags: 0x%lx\n", mbuf->ol_flags);
    printf("  packet_type: 0x%x\n", mbuf->packet_type);
    printf("  timestamp: %lu\n", mbuf->timestamp);
    printf("================\n\n");
}

/**
 * 打印以太网头部
 */
void fdir_print_eth_hdr(const struct rte_ether_hdr *eth_hdr)
{
    if (!eth_hdr) {
        printf("Ethernet header is NULL\n");
        return;
    }

    printf("\n=== Ethernet Header ===\n");
    printf("  Dst: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
           eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
           eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
    printf("  Src: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
           eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
           eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5]);
    printf("  Type: 0x%04x\n", ntohs(eth_hdr->ether_type));
    printf("======================\n\n");
}

/**
 * 打印IPv4头部
 */
void fdir_print_ipv4_hdr(const struct rte_ipv4_hdr *ipv4_hdr)
{
    if (!ipv4_hdr) {
        printf("IPv4 header is NULL\n");
        return;
    }

    printf("\n=== IPv4 Header ===\n");
    printf("  Version: %u\n", ipv4_hdr->version_ihl >> 4);
    printf("  IHL: %u\n", ipv4_hdr->version_ihl & 0x0f);
    printf("  Type of Service: 0x%02x\n", ipv4_hdr->type_of_service);
    printf("  Total Length: %u\n", ntohs(ipv4_hdr->total_length));
    printf("  Identification: %u\n", ntohs(ipv4_hdr->packet_id));
    printf("  Flags: 0x%02x\n", ntohs(ipv4_hdr->fragment_offset) >> 13);
    printf("  Fragment Offset: %u\n", ntohs(ipv4_hdr->fragment_offset) & 0x1fff);
    printf("  TTL: %u\n", ipv4_hdr->time_to_live);
    printf("  Protocol: %u\n", ipv4_hdr->next_proto_id);
    printf("  Checksum: 0x%04x\n", ntohs(ipv4_hdr->hdr_checksum));
    printf("  Src: %s\n", inet_ntoa(*(struct in_addr *)&ipv4_hdr->src_addr));
    printf("  Dst: %s\n", inet_ntoa(*(struct in_addr *)&ipv4_hdr->dst_addr));
    printf("==================\n\n");
}

/**
 * 打印IPv6头部
 */
void fdir_print_ipv6_hdr(const struct rte_ipv6_hdr *ipv6_hdr)
{
    if (!ipv6_hdr) {
        printf("IPv6 header is NULL\n");
        return;
    }

    char src_str[INET6_ADDRSTRLEN];
    char dst_str[INET6_ADDRSTRLEN];

    printf("\n=== IPv6 Header ===\n");
    printf("  Version: %u\n", ipv6_hdr->vtc_flow >> 28);
    printf("  Traffic Class: %u\n", (ipv6_hdr->vtc_flow >> 20) & 0x0ff);
    printf("  Flow Label: %u\n", ipv6_hdr->vtc_flow & 0x000fffff);
    printf("  Payload Length: %u\n", ntohs(ipv6_hdr->payload_len));
    printf("  Next Header: %u\n", ipv6_hdr->proto);
    printf("  Hop Limit: %u\n", ipv6_hdr->hop_limits);
    inet_ntop(AF_INET6, ipv6_hdr->src_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET6, ipv6_hdr->dst_addr, dst_str, sizeof(dst_str));
    printf("  Src: %s\n", src_str);
    printf("  Dst: %s\n", dst_str);
    printf("===================\n\n");
}

/**
 * 打印TCP头部
 */
void fdir_print_tcp_hdr(const struct rte_tcp_hdr *tcp_hdr)
{
    if (!tcp_hdr) {
        printf("TCP header is NULL\n");
        return;
    }

    printf("\n=== TCP Header ===\n");
    printf("  Src Port: %u\n", ntohs(tcp_hdr->src_port));
    printf("  Dst Port: %u\n", ntohs(tcp_hdr->dst_port));
    printf("  Seq Num: %u\n", ntohl(tcp_hdr->sent_seq));
    printf("  Ack Num: %u\n", ntohl(tcp_hdr->recv_ack));
    printf("  Data Offset: %u\n", tcp_hdr->data_off >> 4);
    printf("  Flags: 0x%02x\n", tcp_hdr->tcp_flags);
    printf("    SYN: %s\n", (tcp_hdr->tcp_flags & 0x02) ? "1" : "0");
    printf("    ACK: %s\n", (tcp_hdr->tcp_flags & 0x10) ? "1" : "0");
    printf("    FIN: %s\n", (tcp_hdr->tcp_flags & 0x01) ? "1" : "0");
    printf("    RST: %s\n", (tcp_hdr->tcp_flags & 0x04) ? "1" : "0");
    printf("  Window: %u\n", ntohs(tcp_hdr->rx_win));
    printf("  Checksum: 0x%04x\n", ntohs(tcp_hdr->cksum));
    printf("  Urgent Ptr: %u\n", ntohs(tcp_hdr->tcp_urp));
    printf("==================\n\n");
}

/**
 * 打印UDP头部
 */
void fdir_print_udp_hdr(const struct rte_udp_hdr *udp_hdr)
{
    if (!udp_hdr) {
        printf("UDP header is NULL\n");
        return;
    }

    printf("\n=== UDP Header ===\n");
    printf("  Src Port: %u\n", ntohs(udp_hdr->src_port));
    printf("  Dst Port: %u\n", ntohs(udp_hdr->dst_port));
    printf("  Length: %u\n", ntohs(udp_hdr->dgram_len));
    printf("  Checksum: 0x%04x\n", ntohs(udp_hdr->dgram_cksum));
    printf("==================\n\n");
}

/**
 * 打印VLAN头部
 */
void fdir_print_vlan_hdr(const struct rte_vlan_hdr *vlan_hdr)
{
    if (!vlan_hdr) {
        printf("VLAN header is NULL\n");
        return;
    }

    printf("\n=== VLAN Header ===\n");
    printf("  TCI: 0x%04x\n", ntohs(vlan_hdr->vlan_tci));
    printf("    PCP: %u\n", ntohs(vlan_hdr->vlan_tci) >> 13);
    printf("    DEI: %u\n", (ntohs(vlan_hdr->vlan_tci) >> 12) & 0x01);
    printf("    VID: %u\n", ntohs(vlan_hdr->vlan_tci) & 0x0fff);
    printf("  Ethertype: 0x%04x\n", ntohs(vlan_hdr->eth_proto));
    printf("===================\n\n");
}
#endif /* FDIR_DEBUG */