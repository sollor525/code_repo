/**
 * TLS JA4/JA3 Fingerprint Extractor - 高级C API使用示例
 *
 * 演示高级功能：多线程处理、批量分析、性能优化等
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include "tls_ja4.h"

#define MAX_PACKETS 1000
#define NUM_THREADS 4

// 数据包结构
typedef struct {
    unsigned char* data;
    size_t length;
    uint64_t timestamp;
    int packet_id;
} PacketData;

// 线程工作数据
typedef struct {
    int thread_id;
    PacketData* packets;
    int packet_count;
    int processed_count;
    int ja3_success_count;
    int ja4_success_count;
} ThreadData;

// 性能统计
typedef struct {
    uint64_t total_time_us;
    int total_packets;
    int ja3_success_count;
    int ja4_success_count;
    double packets_per_second;
} PerformanceStats;

/**
 * 获取当前时间戳（微秒）
 */
uint64_t get_timestamp_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/**
 * 生成模拟TLS Client Hello数据包
 */
void generate_test_packets(PacketData* packets, int count) {
    printf("📦 生成 %d 个测试数据包...\n", count);

    // 基础Client Hello模板
    const unsigned char client_hello_template[] = {
        // TLS Record Layer
        0x16,                         // Content Type: Handshake
        0x03, 0x03,                   // TLS Version: TLS 1.2
        0x00, 0x5a,                   // Length: 90 bytes

        // Handshake Protocol
        0x01,                         // Handshake Type: Client Hello
        0x00, 0x00, 0x56,             // Length: 86 bytes
        0x03, 0x03,                   // TLS Version: TLS 1.2

        // Random (32 bytes) - 使用包ID作为随机变化
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,

        0x00,                         // Session ID Length: 0

        // Cipher Suites (可变长度)
        0x00, 0x08,                   // Length: 8 bytes
        0x13, 0x01, 0x13, 0x02,       // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
        0xc0, 0x2b, 0xc0, 0x2f,       // ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256

        // Compression Methods (1 byte)
        0x01,                         // Length: 1
        0x00,                         // NULL compression

        // Extensions (可变内容)
        0x00, 0x2e,                   // Length: 46 bytes
        0x00, 0x0b,                   // Extension: ec_point_formats
        0x00, 0x02,                   // Length: 2
        0x01, 0x00,                   // Uncompressed, ansiX962_compressed_prime
        0x00, 0x0a,                   // Extension: supported_groups
        0x00, 0x06,                   // Length: 6
        0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, // x25519, secp256r1, x448
        0x00, 0x23,                   // Extension: supported_versions
        0x00, 0x03,                   // Length: 3
        0x02, 0x03, 0x04,             // TLS 1.2, TLS 1.3
        0x00, 0x0d,                   // Extension: signature_algorithms
        0x00, 0x14,                   // Length: 20
        0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x02, 0x03,
        0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01,
        0x02, 0x01, 0x04, 0x02,
        0x00, 0x05,                   // Extension: status_request
        0x00, 0x00,                   // Length: 0
        0x00, 0x12,                   // Extension: signed_certificate_timestamp
        0x00, 0x00,                   // Length: 0
        0x00, 0x33,                   // Extension: key_share
        0x00, 0x01,                   // Length: 1
        0x00, 0x1d                    // x25519
    };

    for (int i = 0; i < count; i++) {
        packets[i].length = sizeof(client_hello_template);
        packets[i].data = malloc(packets[i].length);
        packets[i].packet_id = i;
        packets[i].timestamp = get_timestamp_us();

        if (packets[i].data) {
            // 复制模板数据
            memcpy(packets[i].data, client_hello_template, packets[i].length);

            // 添加一些变化：修改Random部分以包含包ID
            unsigned char* random_field = packets[i].data + 11; // Random字段起始位置
            for (int j = 0; j < 4; j++) {
                random_field[j] = (i >> (j * 8)) & 0xFF;
            }

            // 随机修改一些密码套件
            if (i % 3 == 0) {
                packets[i].data[38] = 0xc0;  // 修改第一个密码套件
                packets[i].data[39] = 0x09;  // ECDHE-ECDSA-AES128-SHA
            } else if (i % 3 == 1) {
                packets[i].data[38] = 0xc0;  // 修改第一个密码套件
                packets[i].data[39] = 0x13;  // ECDHE-RSA-AES128-SHA
            }
        }
    }

    printf("✅ 测试数据包生成完成\n");
}

/**
 * 清理测试数据包
 */
void cleanup_packets(PacketData* packets, int count) {
    for (int i = 0; i < count; i++) {
        if (packets[i].data) {
            free(packets[i].data);
        }
    }
}

/**
 * 线程工作函数
 */
void* worker_thread(void* arg) {
    ThreadData* thread_data = (ThreadData*)arg;
    printf("🧵 线程 %d 开始工作...\n", thread_data->thread_id);

    // 每个线程使用独立的上下文
    TlsJa4Context* ctx = tls_init();
    if (!ctx) {
        printf("❌ 线程 %d 无法初始化上下文\n", thread_data->thread_id);
        return NULL;
    }

    // 注意：当前版本的C API暂不包含缓存管理函数
    // 这些功能将在未来版本中提供

    for (int i = 0; i < thread_data->packet_count; i++) {
        PacketData* packet = &thread_data->packets[i];

        if (!packet || !packet->data) {
            continue;
        }

        thread_data->processed_count++;

        // JA3分析
        TlsJa3Result ja3_result = {0};
        int ja3_ret = tls_calculate_ja3(packet->data, packet->length, &ja3_result);
        if (ja3_ret == TLS_JA4_SUCCESS) {
            thread_data->ja3_success_count++;
        }

        // JA4分析
        TlsJa4Result ja4_result = {0};
        int ja4_ret = tls_calculate_ja4(packet->data, packet->length, &ja4_result);
        if (ja4_ret == TLS_JA4_SUCCESS) {
            thread_data->ja4_success_count++;
        }

        // 每100个包输出一次进度
        if (thread_data->processed_count % 100 == 0) {
            printf("🧵 线程 %d 已处理 %d 个数据包\n",
                   thread_data->thread_id, thread_data->processed_count);
        }
    }

    // 清理上下文
    tls_cleanup(ctx);

    printf("🧵 线程 %d 工作完成: 处理=%d, JA3成功=%d, JA4成功=%d\n",
           thread_data->thread_id, thread_data->processed_count,
           thread_data->ja3_success_count, thread_data->ja4_success_count);

    return NULL;
}

/**
 * 多线程性能测试
 */
PerformanceStats demo_multithreading(PacketData* packets, int packet_count) {
    printf("\n🚀 === 多线程性能测试 ===\n");
    printf("📊 总数据包数: %d\n", packet_count);
    printf("🧵 线程数: %d\n", NUM_THREADS);

    PerformanceStats stats = {0};
    uint64_t start_time = get_timestamp_us();

    // 创建线程数据
    ThreadData thread_data[NUM_THREADS];
    pthread_t threads[NUM_THREADS];

    // 分配数据包给各个线程
    int packets_per_thread = packet_count / NUM_THREADS;
    int remaining_packets = packet_count % NUM_THREADS;

    int current_packet = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].packets = &packets[current_packet];
        thread_data[i].packet_count = packets_per_thread;
        if (i < remaining_packets) {
            thread_data[i].packet_count++;
        }
        thread_data[i].processed_count = 0;
        thread_data[i].ja3_success_count = 0;
        thread_data[i].ja4_success_count = 0;

        current_packet += thread_data[i].packet_count;
    }

    // 创建并启动线程
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, worker_thread, &thread_data[i]) != 0) {
            printf("❌ 无法创建线程 %d\n", i);
            return stats;
        }
    }

    // 等待所有线程完成
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);

        // 统计结果
        stats.total_packets += thread_data[i].processed_count;
        stats.ja3_success_count += thread_data[i].ja3_success_count;
        stats.ja4_success_count += thread_data[i].ja4_success_count;
    }

    uint64_t end_time = get_timestamp_us();
    stats.total_time_us = end_time - start_time;
    stats.packets_per_second = (double)stats.total_packets * 1000000.0 / stats.total_time_us;

    printf("✅ 多线程测试完成\n");
    return stats;
}

/**
 * 单线程性能测试（用于对比）
 */
PerformanceStats demo_single_threading(PacketData* packets, int packet_count) {
    printf("\n🐌 === 单线程性能测试（对比） ===\n");
    printf("📊 数据包数: %d\n", packet_count);

    PerformanceStats stats = {0};
    uint64_t start_time = get_timestamp_us();

    TlsJa4Context* ctx = tls_init();
    if (!ctx) {
        printf("❌ 无法初始化上下文\n");
        return stats;
    }

    for (int i = 0; i < packet_count; i++) {
        if (!packets[i].data) continue;

        stats.total_packets++;

        // JA3分析
        TlsJa3Result ja3_result = {0};
        int ja3_ret = tls_calculate_ja3(packets[i].data, packets[i].length, &ja3_result);
        if (ja3_ret == TLS_JA4_SUCCESS) {
            stats.ja3_success_count++;
        }

        // JA4分析
        TlsJa4Result ja4_result = {0};
        int ja4_ret = tls_calculate_ja4(packets[i].data, packets[i].length, &ja4_result);
        if (ja4_ret == TLS_JA4_SUCCESS) {
            stats.ja4_success_count++;
        }

        // 每100个包输出一次进度
        if (stats.total_packets % 100 == 0) {
            printf("📊 已处理 %d 个数据包\n", stats.total_packets);
        }
    }

    tls_cleanup(ctx);

    uint64_t end_time = get_timestamp_us();
    stats.total_time_us = end_time - start_time;
    stats.packets_per_second = (double)stats.total_packets * 1000000.0 / stats.total_time_us;

    printf("✅ 单线程测试完成\n");
    return stats;
}

/**
 * 打印性能统计
 */
void print_performance_stats(const PerformanceStats* stats, const char* test_name) {
    printf("\n📈 === %s 性能统计 ===\n", test_name);
    printf("  总处理时间: %.2f ms\n", stats->total_time_us / 1000.0);
    printf("  处理数据包数: %d\n", stats->total_packets);
    printf("  JA3成功数: %d (%.1f%%)\n", stats->ja3_success_count,
           (double)stats->ja3_success_count * 100.0 / stats->total_packets);
    printf("  JA4成功数: %d (%.1f%%)\n", stats->ja4_success_count,
           (double)stats->ja4_success_count * 100.0 / stats->total_packets);
    printf("  处理速度: %.0f 包/秒\n", stats->packets_per_second);
    printf("  平均处理时间: %.2f 微秒/包\n",
           (double)stats->total_time_us / stats->total_packets);
}

/**
 * 性能对比分析
 */
void compare_performance(const PerformanceStats* single_stats, const PerformanceStats* multi_stats) {
    printf("\n🔄 === 性能对比分析 ===\n");

    double speedup = multi_stats->packets_per_second / single_stats->packets_per_second;
    printf("  多线程加速比: %.2fx\n", speedup);

    double efficiency = speedup / NUM_THREADS * 100.0;
    printf("  并行效率: %.1f%%\n", efficiency);

    if (speedup > NUM_THREADS * 0.8) {
        printf("  ✅ 并行性能优秀\n");
    } else if (speedup > NUM_THREADS * 0.5) {
        printf("  ⚠️  并行性能良好\n");
    } else {
        printf("  ❌ 并行性能需要优化\n");
    }
}

/**
 * 演示内存管理和缓存优化
 */
void demo_memory_optimization() {
    printf("\n💾 === 内存管理和缓存优化演示 ===\n");

    // 初始化上下文
    TlsJa4Context* ctx = tls_init();
    if (!ctx) {
        printf("❌ 上下文初始化失败\n");
        return;
    }

    printf("📝 注意: 当前版本为简化API，暂不支持缓存管理功能\n");
    printf("📝 完整的缓存管理功能将在未来版本中提供\n");
    printf("📝 包括以下功能:\n");
    printf("   - tls_ja4_set_cache_limits: 设置缓存限制\n");
    printf("   - tls_ja4_get_cache_stats: 获取缓存统计\n");
    printf("   - tls_ja4_cleanup_timeout_cache: 清理超时缓存\n");

    // 清理上下文
    tls_cleanup(ctx);
    printf("✅ 内存优化演示完成\n");
}

/**
 * 主函数
 */
int main() {
    printf("🚀 TLS JA4/JA3 Fingerprint Extractor - C API高级示例\n");
    printf("====================================================\n");

    // 生成测试数据
    PacketData packets[MAX_PACKETS];
    generate_test_packets(packets, MAX_PACKETS);

    // 内存优化演示
    demo_memory_optimization();

    // 单线程性能测试
    PerformanceStats single_stats = demo_single_threading(packets, 200);
    print_performance_stats(&single_stats, "单线程");

    // 多线程性能测试
    PerformanceStats multi_stats = demo_multithreading(packets, MAX_PACKETS);
    print_performance_stats(&multi_stats, "多线程");

    // 性能对比
    compare_performance(&single_stats, &multi_stats);

    // 清理资源
    cleanup_packets(packets, MAX_PACKETS);

    printf("\n✨ 所有高级演示完成!\n");
    printf("💡 提示:\n");
    printf("  - 多线程可显著提高处理性能\n");
    printf("  - 每个线程应使用独立的TLS上下文\n");
    printf("  - 合理配置缓存可优化内存使用\n");
    printf("  - JA4通常比JA3有更好的性能表现\n");

    return 0;
}