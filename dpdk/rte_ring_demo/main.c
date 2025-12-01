// main.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include "include/dpdk_utils.h"

#define RING_SIZE      4096
#define NUM_ITEMS      10000
#define NUM_PRODUCERS  1
#define NUM_CONSUMERS  1

static struct rte_ring *ring = NULL;
static volatile int running = 1;
static rte_atomic32_t produced_count = RTE_ATOMIC32_INIT(0);
static rte_atomic32_t consumed_count = RTE_ATOMIC32_INIT(0);

// 信号处理
static void signal_handler(int signum) {
    printf("\n收到信号 %d，正在停止...\n", signum);
    running = 0;
}

// 工作项结构
struct work_item {
    uint64_t id;
    char data[256];
    uint64_t timestamp;
};

// 生产者函数
static int producer_func(__attribute__((unused)) void *arg) {
    unsigned int lcore_id = rte_lcore_id();
    printf("生产者启动在 lcore %u\n", lcore_id);
    
    uint64_t local_count = 0;
    
    while (running && local_count < NUM_ITEMS / NUM_PRODUCERS) {
        struct work_item *item = malloc(sizeof(struct work_item));
        if (!item) {
            fprintf(stderr, "内存分配失败\n");
            break;
        }
        
        item->id = rte_atomic32_add_return(&produced_count, 1);
        snprintf(item->data, sizeof(item->data), 
                "Item %lu from producer %u", item->id, lcore_id);
        item->timestamp = rte_get_timer_cycles();
        
        // 入队
        if (rte_ring_enqueue(ring, item) != 0) {
            free(item);
            rte_delay_us(100);
            continue;
        }
        
        local_count++;
        
        if (local_count % 1000 == 0) {
            printf("生产者 %u: 生产 %lu 项\n", lcore_id, local_count);
        }
        
        rte_delay_us(10);
    }
    
    printf("生产者 %u 退出，共生产 %lu 项\n", lcore_id, local_count);
    return 0;
}

// 消费者函数
static int consumer_func(__attribute__((unused)) void *arg) {
    unsigned int lcore_id = rte_lcore_id();
    printf("消费者启动在 lcore %u\n", lcore_id);
    
    uint64_t local_count = 0;
    
    while (running || !rte_ring_empty(ring)) {
        struct work_item *item = NULL;
        
        if (rte_ring_dequeue(ring, (void **)&item) == 0) {
            if (item) {
                local_count++;
                rte_atomic32_add(&consumed_count, 1);
                
                // 简单处理
                size_t len = strlen(item->data);
                (void)len; // 避免未使用警告
                
                free(item);
                
                if (local_count % 1000 == 0) {
                    printf("消费者 %u: 消费 %lu 项\n", lcore_id, local_count);
                }
            }
        } else {
            if (!running) break;
            rte_delay_us(100);
        }
    }
    
    printf("消费者 %u 退出，共消费 %lu 项\n", lcore_id, local_count);
    return 0;
}

int main(int argc, char **argv) {
    int ret;
    
    printf("DPDK Ring Demo v1.0\n");
    printf("编译时间: %s %s\n", __DATE__, __TIME__);
    
    // 注册信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 初始化DPDK EAL - 使用可写的字符数组
    static char core_list[] = "0,1,2";
    static char socket_mem[] = "256,0";
    static char file_prefix[] = "ring_demo";

    char *eal_args[] = {
        argv[0],
        "-l", core_list,
        "--socket-mem", socket_mem,
        "--no-pci",
        "--no-hpet",
        "--file-prefix", file_prefix,
        NULL
    };

    int eal_argc = sizeof(eal_args) / sizeof(eal_args[0]) - 1;
    ret = rte_eal_init(eal_argc, eal_args);
    
    if (ret < 0) {
        fprintf(stderr, "DPDK EAL初始化失败\n");
        return EXIT_FAILURE;
    }
    
    printf("DPDK初始化成功\n");
    print_dpdk_info();
    
    // 创建ring
    ring = rte_ring_create("demo_ring", RING_SIZE, 
                          rte_socket_id(), 
                          RING_F_SP_ENQ | RING_F_SC_DEQ);
    
    if (!ring) {
        fprintf(stderr, "Ring创建失败\n");
        rte_eal_cleanup();
        return EXIT_FAILURE;
    }
    
    printf("Ring创建成功: %s (容量: %u)\n", ring->name, ring->size);
    
    // 启动生产者
    unsigned int lcore_id;
    int producer_launched = 0;
    
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (producer_launched < NUM_PRODUCERS) {
            ret = rte_eal_remote_launch(producer_func, NULL, lcore_id);
            if (ret == 0) {
                printf("在 lcore %u 启动生产者\n", lcore_id);
                producer_launched++;
            }
        }
    }
    
    // 启动消费者
    int consumer_launched = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (consumer_launched < NUM_CONSUMERS) {
            ret = rte_eal_remote_launch(consumer_func, NULL, lcore_id);
            if (ret == 0) {
                printf("在 lcore %u 启动消费者\n", lcore_id);
                consumer_launched++;
            }
        }
    }
    
    printf("启动 %d 生产者，%d 消费者\n", producer_launched, consumer_launched);
    
    // 主循环：监控进度
    int timeout = 30;
    while (running && timeout > 0) {
        sleep(1);
        timeout--;
        
        printf("进度: 生产 %d / 消费 %d, Ring: %u 项\n",
               rte_atomic32_read(&produced_count),
               rte_atomic32_read(&consumed_count),
               rte_ring_count(ring));
        
        if (rte_atomic32_read(&produced_count) >= NUM_ITEMS &&
            rte_atomic32_read(&consumed_count) >= NUM_ITEMS) {
            break;
        }
    }
    
    // 停止
    running = 0;
    rte_eal_mp_wait_lcore();
    
    // 清理
    while (!rte_ring_empty(ring)) {
        struct work_item *item;
        if (rte_ring_dequeue(ring, (void **)&item) == 0 && item) {
            free(item);
        }
    }
    
    printf("\n最终统计:\n");
    printf("总生产: %d\n", rte_atomic32_read(&produced_count));
    printf("总消费: %d\n", rte_atomic32_read(&consumed_count));
    
    rte_eal_cleanup();
    printf("程序退出\n");
    
    return EXIT_SUCCESS;
}