/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024
 */

#ifndef DPDK_UTILS_H
#define DPDK_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_spinlock.h>
#include <rte_rwlock.h>
#include <rte_jhash.h>
#include <rte_hash.h>
#include <rte_fbk_hash.h>
#include <rte_hash_crc.h>
#include "fdir_config.h"

/* DPDK初始化配置 */
struct fdir_eal_config {
    char *program_name;               /* 程序名称 */
    int argc;                         /* 参数个数 */
    char **argv;                      /* 参数数组 */
    uint32_t master_lcore;            /* 主核心 */
    uint32_t *coremask;               /* 核心掩码 */
    uint32_t nb_channels;             /* 通道数 */
    uint32_t socket_id;               /* Socket ID */
    char *proc_type;                  /* 进程类型 */
    char *file_prefix;                /* 文件前缀 */
    bool hugepage_unlink;             /* 解链hugepage */
    bool no_huge;                     /* 禁用hugepage */
    bool no_pci;                      /* 禁用PCI */
    bool no_shconf;                   /* 禁用共享配置 */
    bool in_memory;                   /* 内存模式 */
    uint32_t vfio_intr;               /* VFIO中断 */
    uint32_t xen_dom0;                /* Xen Dom0 */
};

/* 内存池配置 */
struct fdir_mempool_config {
    char name[64];                    /* 内存池名称 */
    uint32_t nb_elements;             /* 元素数量 */
    uint16_t element_size;            /* 元素大小 */
    uint16_t cache_size;              /* 缓存大小 */
    uint32_t socket_id;               /* Socket ID */
    bool single_file;                 /* 单文件模式 */
    unsigned int flags;               /* 标志 */
};

/* Ring配置 */
struct fdir_ring_config {
    char name[64];                    /* Ring名称 */
    uint32_t count;                   /* 元素数量 */
    uint32_t socket_id;               /* Socket ID */
    unsigned int flags;               /* 标志 */
};

/* Hash配置 */
struct fdir_hash_config {
    char name[64];                    /* Hash表名称 */
    uint32_t entries;                 /* 条目数量 */
    uint32_t key_len;                 /* 键长度 */
    uint32_t socket_id;               /* Socket ID */
    uint8_t hash_func;                /* 哈希函数 */
    uint32_t extra_flags;             /* 额外标志 */
};

/* 时间管理 */
struct fdir_timer_config {
    uint64_t hz;                      /* 频率 */
    uint64_t cycles_per_sec;          /* 每秒周期数 */
    uint64_t tsc_hz;                  /* TSC频率 */
    uint64_t timer_resolution;        /* 定时器分辨率 */
};

/* 网卡信息 */
struct fdir_port_info {
    uint16_t port_id;                 /* 端口ID */
    char name[RTE_ETH_NAME_MAX_LEN];  /* 端口名称 */
    struct rte_ether_addr mac_addr;   /* MAC地址 */
    uint32_t link_speed;              /* 链路速度 */
    uint8_t link_duplex;              /* 双工模式 */
    uint8_t link_autoneg;             /* 自动协商 */
    uint8_t link_status;              /* 链路状态 */
    uint16_t mtu;                     /* MTU */
    uint16_t max_rx_queues;           /* 最大接收队列数 */
    uint16_t max_tx_queues;           /* 最大发送队列数 */
    uint64_t rx_offload_capa;         /* 接收卸载能力 */
    uint64_t tx_offload_capa;         /* 发送卸载能力 */
    uint64_t rx_queue_offload_capa;   /* 接收队列卸载能力 */
    uint64_t tx_queue_offload_capa;   /* 发送队列卸载能力 */
    uint64_t dev_flags;               /* 设备标志 */
    char driver_name[64];             /* 驱动名称 */
};

/* 函数声明 */

/* EAL初始化 */
int fdir_eal_init(struct fdir_eal_config *config);
int fdir_eal_cleanup(void);
uint32_t fdir_get_lcore_count(void);
uint32_t fdir_get_socket_count(void);
uint32_t fdir_get_numa_node(uint32_t lcore_id);
bool fdir_is_lcore_enabled(uint32_t lcore_id);

/* 内存管理 */
void *fdir_malloc(const char *type, size_t size, unsigned int align);
void *fdir_zmalloc(const char *type, size_t size, unsigned int align);
void *fdir_realloc(void *ptr, size_t size);
void fdir_free(void *ptr);
int fdir_mempool_create(struct fdir_mempool_config *config,
                       struct rte_mempool **mp);
int fdir_mempool_destroy(struct rte_mempool *mp);
void *fdir_mempool_alloc(struct rte_mempool *mp);
void fdir_mempool_free(struct rte_mempool *mp, void *obj);
uint32_t fdir_mempool_avail_count(struct rte_mempool *mp);
uint32_t fdir_mempool_in_use_count(struct rte_mempool *mp);

/* Ring操作 */
int fdir_ring_create(struct fdir_ring_config *config, struct rte_ring **ring);
int fdir_ring_destroy(struct rte_ring *ring);
int fdir_ring_enqueue(struct rte_ring *ring, void *obj);
int fdir_ring_dequeue(struct rte_ring *ring, void **obj);
int fdir_ring_enqueue_bulk(struct rte_ring *ring, void **obj, unsigned int n);
int fdir_ring_dequeue_bulk(struct rte_ring *ring, void **obj, unsigned int n);
int fdir_ring_count(struct rte_ring *ring);
int fdir_ring_free_count(struct rte_ring *ring);
bool fdir_ring_full(struct rte_ring *ring);
bool fdir_ring_empty(struct rte_ring *ring);

/* Hash操作 */
int fdir_hash_create(struct fdir_hash_config *config, struct rte_hash **hash);
int fdir_hash_destroy(struct rte_hash *hash);
int fdir_hash_add_key_data(struct rte_hash *hash, const void *key, void *data);
int fdir_hash_del_key(struct rte_hash *hash, const void *key);
int fdir_hash_lookup_data(const struct rte_hash *hash, const void *key, void **data);
int fdir_hash_lookup_bulk_data(const struct rte_hash *hash, const void **keys,
                              uint32_t num_keys, void **data);
int fdir_hash_count(const struct rte_hash *hash);
void fdir_hash_reset(struct rte_hash *hash);

/* 时间管理 */
int fdir_timer_init(struct fdir_timer_config *config);
void fdir_timer_cleanup(void);
uint64_t fdir_get_tsc_cycles(void);
uint64_t fdir_get_tsc_hz(void);
uint64_t fdir_get_timer_cycles(void);
uint64_t fdir_get_timer_hz(void);
double fdir_cycles_to_usec(uint64_t cycles);
double fdir_cycles_to_msec(uint64_t cycles);
double fdir_cycles_to_sec(uint64_t cycles);
uint64_t fdir_usec_to_cycles(double usec);
uint64_t fdir_msec_to_cycles(double msec);
uint64_t fdir_sec_to_cycles(double sec);
void fdir_delay_us(unsigned int us);
void fdir_delay_ms(unsigned int ms);
void fdir_delay_sec(unsigned int sec);

/* 网卡操作 */
int fdir_get_port_info(uint16_t port_id, struct fdir_port_info *info);
int fdir_get_port_list(uint16_t *ports, uint16_t max_ports);
uint16_t fdir_get_nb_ports(void);
int fdir_port_is_valid(uint16_t port_id);
int fdir_port_is_bonding(uint16_t port_id);
int fdir_port_is_virtual(uint16_t port_id);

/* MAC地址操作 */
int fdir_mac_addr_is_zero(const struct rte_ether_addr *mac_addr);
int fdir_mac_addr_is_broadcast(const struct rte_ether_addr *mac_addr);
int fdir_mac_addr_is_multicast(const struct rte_ether_addr *mac_addr);
int fdir_mac_addr_is_unicast(const struct rte_ether_addr *mac_addr);
int fdir_mac_addr_is_valid(const struct rte_ether_addr *mac_addr);
int fdir_mac_addr_copy(struct rte_ether_addr *dst,
                      const struct rte_ether_addr *src);
int fdir_mac_addr_format(const struct rte_ether_addr *mac_addr,
                        char *buf, size_t buf_len);
int fdir_mac_addr_parse(const char *str, struct rte_ether_addr *mac_addr);

/* IP地址操作 */
int fdir_ipv4_addr_is_valid(uint32_t addr);
int fdir_ipv4_addr_is_unicast(uint32_t addr);
int fdir_ipv4_addr_is_multicast(uint32_t addr);
int fdir_ipv4_addr_is_broadcast(uint32_t addr);
int fdir_ipv4_addr_format(uint32_t addr, char *buf, size_t buf_len);
int fdir_ipv4_addr_parse(const char *str, uint32_t *addr);
int fdir_ipv6_addr_is_valid(const uint8_t *addr);
int fdir_ipv6_addr_is_unicast(const uint8_t *addr);
int fdir_ipv6_addr_is_multicast(const uint8_t *addr);
int fdir_ipv6_addr_is_link_local(const uint8_t *addr);
int fdir_ipv6_addr_format(const uint8_t *addr, char *buf, size_t buf_len);
int fdir_ipv6_addr_parse(const char *str, uint8_t *addr);

/* 端口操作 */
int fdir_port_is_valid(uint16_t port);
int fdir_port_is_reserved(uint16_t port);
int fdir_port_is_well_known(uint16_t port);
const char *fdir_port_get_service_name(uint16_t port);

/* 字符串操作 */
int fdir_str_to_int(const char *str, int *value);
int fdir_str_to_uint32(const char *str, uint32_t *value);
int fdir_str_to_uint64(const char *str, uint64_t *value);
int fdir_str_to_bool(const char *str, bool *value);
int fdir_str_to_mac(const char *str, struct rte_ether_addr *mac_addr);
int fdir_str_to_ipv4(const char *str, uint32_t *addr);
int fdir_str_to_ipv6(const char *str, uint8_t *addr);
int fdir_str_to_port(const char *str, uint16_t *port);
char *fdir_str_trim(char *str);
char *fdir_strlwr(char *str);
char *fdir_strupr(char *str);
int fdir_str_is_empty(const char *str);
int fdir_str_is_equal(const char *str1, const char *str2, bool case_sensitive);

/* 哈希函数 */
uint32_t fdir_hash_crc32(const void *data, uint32_t len, uint32_t init_val);
uint32_t fdir_hash_crc32c(const void *data, uint32_t len, uint32_t init_val);
uint32_t fdir_hash_jhash(const void *data, uint32_t len, uint32_t init_val);
uint32_t fdir_hash_fnv1a(const void *data, uint32_t len);
uint32_t fdir_hash_murmur3(const void *data, uint32_t len);
uint64_t fdir_hash_xxhash64(const void *data, uint32_t len, uint64_t seed);

/* 错误处理 */
void fdir_panic(const char *func, const char *format, ...);
void fdir_error(const char *func, const char *format, ...);
void fdir_warn(const char *func, const char *format, ...);
void fdir_info(const char *func, const char *format, ...);
void fdir_debug(const char *func, const char *format, ...);

/* 日志管理 - 使用DPDK内置日志 */
int fdir_log_set_level(int level);
int fdir_log_set_file(const char *filename);
int fdir_log_set_pattern(const char *pattern);
void fdir_log_print(int level, const char *func,
                   const char *format, ...);

/* CPU亲和性 */
int fdir_set_thread_affinity(pthread_t thread, uint32_t lcore_id);
int fdir_get_thread_affinity(pthread_t thread, cpu_set_t *cpu_set);
int fdir_set_cpu_affinity(uint32_t cpu_id);
int fdir_get_cpu_affinity(cpu_set_t *cpu_set);
uint32_t fdir_get_current_cpu(void);
uint32_t fdir_get_current_numa_node(void);

/* 统计和监控 */
int fdir_stats_init(void);
int fdir_stats_cleanup(void);
int fdir_stats_register(const char *name, void *stats);
int fdir_stats_unregister(const char *name);
int fdir_stats_get(const char *name, void *stats);
int fdir_stats_reset(const char *name);
int fdir_stats_print_name(const char *name);

/* 调试函数 */
#if FDIR_DEBUG
void fdir_print_hexdump(const char *title, const void *buf, size_t len);
void fdir_print_memory(const void *ptr, size_t size);
void fdir_print_mbuf(const struct rte_mbuf *mbuf);
void fdir_print_eth_hdr(const struct rte_ether_hdr *eth_hdr);
void fdir_print_ipv4_hdr(const struct rte_ipv4_hdr *ipv4_hdr);
void fdir_print_ipv6_hdr(const struct rte_ipv6_hdr *ipv6_hdr);
void fdir_print_tcp_hdr(const struct rte_tcp_hdr *tcp_hdr);
void fdir_print_udp_hdr(const struct rte_udp_hdr *udp_hdr);
void fdir_print_vlan_hdr(const struct rte_vlan_hdr *vlan_hdr);
#endif

#endif /* DPDK_UTILS_H */