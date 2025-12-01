// include/dpdk_utils.h
#ifndef DPDK_UTILS_H
#define DPDK_UTILS_H

#include <rte_eal.h>
#include <rte_ring.h>

#ifdef __cplusplus
extern "C" {
#endif

// 打印DPDK信息
void print_dpdk_info(void);

// 检查DPDK环境
int check_dpdk_environment(void);

// 安全创建ring
struct rte_ring *safe_ring_create(const char *name, unsigned count, 
                                  int socket_id, unsigned flags);

#ifdef __cplusplus
}
#endif

#endif // DPDK_UTILS_H