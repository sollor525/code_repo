// src/dpdk_utils.c
#include <stdio.h>
#include <string.h>
#include "dpdk_utils.h"

void print_dpdk_info(void) {
    printf("DPDK信息:\n");
    printf("  Lcore数量: %u\n", rte_lcore_count());
    printf("  Socket数量: %u\n", rte_socket_count());

    if (rte_eal_has_hugepages()) {
        printf("  Hugepages: 可用\n");
    } else {
        printf("  Hugepages: 不可用\n");
    }
}

int check_dpdk_environment(void) {
    unsigned int lcore_count = rte_lcore_count();
    if (lcore_count < 2) {
        fprintf(stderr, "错误: 需要至少2个lcore\n");
        return -1;
    }
    
    if (!rte_eal_has_hugepages()) {
        fprintf(stderr, "警告: Hugepages未启用\n");
    }
    
    return 0;
}

struct rte_ring *safe_ring_create(const char *name, unsigned count, 
                                  int socket_id, unsigned flags) {
    // 确保count是2的幂次方
    if (count & (count - 1)) {
        // 找到最接近的2的幂次方
        count = 1 << (32 - __builtin_clz(count - 1));
        printf("调整ring大小为 %u (2的幂次方)\n", count);
    }
    
    struct rte_ring *ring = rte_ring_create(name, count, socket_id, flags);
    if (!ring) {
        fprintf(stderr, "Ring创建失败\n");
    }
    
    return ring;
}