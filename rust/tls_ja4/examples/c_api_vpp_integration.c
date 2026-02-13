/**
 * TLS JA4/JA3 Fingerprint Extractor - VPP集成示例
 *
 * 演示如何在VPP (Vector Packet Processing)环境中集成TLS JA4/JA3指纹提取
 * 包含节点注册、数据处理、性能监控等完整流程
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>
#include "tls_ja4.h"

/*
 * VPP相关定义（模拟VPP环境）
 * 注意：这是示例代码，实际VPP集成需要包含VPP头文件
 */

#define VLIB_NODE_NAME_MAX_LEN 64
#define VLIB_BUFFER_DATA_SIZE 2048

// 模拟VPP buffer结构
typedef struct {
    unsigned char data[VLIB_BUFFER_DATA_SIZE];
    unsigned int length;
    unsigned int current_length;
    void* opaque[10];  // 用于存储私有数据
} vlib_buffer_t;

// 模拟VPP节点结构
typedef struct {
    char name[VLIB_NODE_NAME_MAX_LEN];
    int index;
    void* function;
    int flags;
} vlib_node_registration_t;

// 模拟VPP框架结构
typedef struct {
    vlib_node_registration_t** nodes;
    int node_count;
    pthread_mutex_t node_mutex;
} vlib_main_t;

// 全局VPP主框架（模拟）
static vlib_main_t vlib_main;
static vlib_main_t* vm = &vlib_main;

// 模拟的VPP节点函数类型
typedef int (*vlib_node_function_t)(vlib_main_t* vm, vlib_buffer_t** buffers, int count);

/**
 * TLS指纹提取节点上下文
 */
typedef struct {
    TlsJa4Context* tls_ctx;        // TLS分析上下文
    uint64_t packets_processed;    // 已处理数据包总数
    uint64_t fingerprints_found;   // 发现的指纹数量
    uint64_t errors;               // 错误计数
    pthread_mutex_t stats_mutex;   // 统计信息锁
    uint64_t start_time;           // 节点启动时间
    unsigned int worker_id;        // Worker线程ID
} tls_ja4_node_ctx_t;

/**
 * TLS指纹提取结果缓存
 */
typedef struct {
    char ja4_fingerprint[64];
    char ja3_fingerprint[64];
    uint32_t ja4_len;
    uint32_t ja3_len;
    uint16_t tls_version;
    uint8_t is_valid;
    uint64_t timestamp;
} tls_fingerprint_cache_t;

// 节点上下文数组（支持多个worker线程）
static tls_ja4_node_ctx_t node_contexts[16];
static int max_workers = 1;

/**
 * 获取当前时间戳（毫秒）
 */
static uint64_t get_timestamp_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL;
}

/**
 * 初始化VPP框架（模拟）
 */
static void init_vlib_main() {
    pthread_mutex_init(&vlib_main.node_mutex, NULL);
    vlib_main.nodes = NULL;
    vlib_main.node_count = 0;
    printf("🔧 VPP框架初始化完成\n");
}

/**
 * 注册VPP节点（模拟）
 */
static int register_vlib_node(vlib_node_registration_t* node) {
    pthread_mutex_lock(&vlib_main.node_mutex);

    vlib_main.nodes = realloc(vlib_main.nodes,
                             (vlib_main.node_count + 1) * sizeof(vlib_node_registration_t*));
    if (!vlib_main.nodes) {
        pthread_mutex_unlock(&vlib_main.node_mutex);
        return -1;
    }

    vlib_main.nodes[vlib_main.node_count] = node;
    node->index = vlib_main.node_count;
    vlib_main.node_count++;

    pthread_mutex_unlock(&vlib_main.node_mutex);

    printf("📝 注册节点: %s (索引: %d)\n", node->name, node->index);
    return 0;
}

/**
 * 从VPP buffer中提取TCP载荷
 */
static unsigned char* extract_tcp_payload(vlib_buffer_t* buffer, unsigned int* payload_len) {
    if (!buffer || !payload_len) {
        return NULL;
    }

    // 模拟TCP/IP头部解析
    // 假设我们已经有了一个指向TCP载荷的指针
    // 在实际VPP环境中，需要解析以太网、IP、TCP头部

    // 这里简化处理：假设buffer->data中的数据已经是TCP载荷
    *payload_len = buffer->current_length;

    if (*payload_len == 0) {
        return NULL;
    }

    return buffer->data;
}

/**
 * 检查是否为TLS数据包
 */
static int is_tls_packet(const unsigned char* payload, unsigned int len) {
    return tls_is_tls_packet(payload, len) == TLS_JA4_SUCCESS;
}

/**
 * 检查是否为TLS Client Hello
 */
static int is_tls_client_hello(const unsigned char* payload, unsigned int len) {
    return tls_is_client_hello(payload, len) == TLS_JA4_SUCCESS;
}

/**
 * 分析单个TLS数据包
 */
static int analyze_tls_packet(tls_ja4_node_ctx_t* ctx,
                             const unsigned char* payload,
                             unsigned int len,
                             tls_fingerprint_cache_t* cache) {
    if (!ctx || !payload || !cache || len == 0) {
        return -1;
    }

    // 清空缓存
    memset(cache, 0, sizeof(tls_fingerprint_cache_t));
    cache->timestamp = get_timestamp_ms();

    // JA3分析
    TlsJa3Result ja3_result = {0};
    int ja3_ret = tls_calculate_ja3(payload, len, &ja3_result);
    if (ja3_ret == TLS_JA4_SUCCESS) {
        cache->ja3_len = ja3_result.fingerprint.fingerprint_len;
        if (cache->ja3_len > 0 && cache->ja3_len < sizeof(cache->ja3_fingerprint)) {
            memcpy(cache->ja3_fingerprint, ja3_result.fingerprint.fingerprint, cache->ja3_len);
            cache->ja3_fingerprint[cache->ja3_len] = '\0';
        }
    }

    // JA4分析
    TlsJa4Result ja4_result = {0};
    int ja4_ret = tls_calculate_ja4(payload, len, &ja4_result);
    if (ja4_ret == TLS_JA4_SUCCESS) {
        cache->ja4_len = ja4_result.fingerprint.fingerprint_len;
        if (cache->ja4_len > 0 && cache->ja4_len < sizeof(cache->ja4_fingerprint)) {
            memcpy(cache->ja4_fingerprint, ja4_result.fingerprint.fingerprint, cache->ja4_len);
            cache->ja4_fingerprint[cache->ja4_len] = '\0';
        }
        cache->tls_version = ja4_result.fingerprint.tls_version;
        cache->is_valid = 1;
    }

    // 更新统计信息
    pthread_mutex_lock(&ctx->stats_mutex);
    ctx->packets_processed++;
    if (cache->is_valid) {
        ctx->fingerprints_found++;
    } else {
        ctx->errors++;
    }
    pthread_mutex_unlock(&ctx->stats_mutex);

    return cache->is_valid ? 0 : -1;
}

/**
 * VPP TLS指纹提取节点主函数
 */
static int tls_ja4_node_function(vlib_main_t* vm, vlib_buffer_t** buffers, int buffer_count) {
    if (!vm || !buffers || buffer_count <= 0) {
        return 0;
    }

    // 获取当前worker的上下文（这里简化为使用第一个上下文）
    tls_ja4_node_ctx_t* ctx = &node_contexts[0];
    int processed_packets = 0;

    for (int i = 0; i < buffer_count; i++) {
        vlib_buffer_t* buffer = buffers[i];
        if (!buffer) {
            continue;
        }

        // 提取TCP载荷
        unsigned int payload_len = 0;
        unsigned char* payload = extract_tcp_payload(buffer, &payload_len);
        if (!payload || payload_len == 0) {
            continue;
        }

        // 快速检查：是否为TLS数据包
        if (!is_tls_packet(payload, payload_len)) {
            continue;
        }

        // 更详细检查：是否为Client Hello
        if (!is_tls_client_hello(payload, payload_len)) {
            continue;
        }

        // 分析TLS数据包
        tls_fingerprint_cache_t cache;
        int ret = analyze_tls_packet(ctx, payload, payload_len, &cache);
        if (ret == 0) {
            // 成功提取指纹
            printf("🎯 发现TLS指纹: JA4=%s, JA3=%s\n",
                   cache.ja4_fingerprint, cache.ja3_fingerprint);

            // 在实际VPP环境中，这里可以：
            // 1. 将指纹信息存储到buffer的opaque字段
            // 2. 更新流表
            // 3. 发送到其他节点进行进一步处理
            // 4. 触发安全事件

            processed_packets++;
        }
    }

    return processed_packets;
}

/**
 * 打印节点统计信息
 */
static void print_node_statistics(tls_ja4_node_ctx_t* ctx) {
    if (!ctx) return;

    pthread_mutex_lock(&ctx->stats_mutex);

    uint64_t current_time = get_timestamp_ms();
    uint64_t runtime_ms = current_time - ctx->start_time;
    double runtime_sec = runtime_ms / 1000.0;

    printf("\n📊 === TLS JA4节点统计信息 ===\n");
    printf("  Worker ID: %u\n", ctx->worker_id);
    printf("  运行时间: %.2f 秒\n", runtime_sec);
    printf("  处理数据包: %lu\n", ctx->packets_processed);
    printf("  提取指纹: %lu\n", ctx->fingerprints_found);
    printf("  错误数量: %lu\n", ctx->errors);
    printf("  成功率: %.2f%%\n",
           ctx->packets_processed > 0 ?
           (double)ctx->fingerprints_found * 100.0 / ctx->packets_processed : 0.0);
    printf("  处理速度: %.0f 包/秒\n",
           runtime_sec > 0 ? (double)ctx->packets_processed / runtime_sec : 0.0);

    // 注意：当前版本的C API暂不包含缓存统计功能
    // 这些功能将在未来版本中提供

    pthread_mutex_unlock(&ctx->stats_mutex);
}

/**
 * 初始化TLS JA4节点
 */
static int init_tls_ja4_node(int worker_id) {
    if (worker_id >= 16) {
        printf("❌ Worker ID 超出范围: %d\n", worker_id);
        return -1;
    }

    tls_ja4_node_ctx_t* ctx = &node_contexts[worker_id];

    // 初始化TLS上下文
    ctx->tls_ctx = tls_init();
    if (!ctx->tls_ctx) {
        printf("❌ Worker %d: TLS上下文初始化失败\n", worker_id);
        return -1;
    }

    // 注意：当前版本的C API暂不包含缓存管理函数
    // 这些功能将在未来版本中提供

    // 初始化统计信息
    ctx->packets_processed = 0;
    ctx->fingerprints_found = 0;
    ctx->errors = 0;
    ctx->start_time = get_timestamp_ms();
    ctx->worker_id = worker_id;

    pthread_mutex_init(&ctx->stats_mutex, NULL);

    printf("✅ Worker %d: TLS JA4节点初始化完成\n", worker_id);
    return 0;
}

/**
 * 清理TLS JA4节点
 */
static void cleanup_tls_ja4_node(int worker_id) {
    if (worker_id >= 16) {
        return;
    }

    tls_ja4_node_ctx_t* ctx = &node_contexts[worker_id];

    // 打印最终统计
    print_node_statistics(ctx);

    // 清理TLS上下文
    if (ctx->tls_ctx) {
        tls_cleanup(ctx->tls_ctx);
        ctx->tls_ctx = NULL;
    }

    // 清理互斥锁
    pthread_mutex_destroy(&ctx->stats_mutex);

    printf("🧹 Worker %d: TLS JA4节点清理完成\n", worker_id);
}

/**
 * 生成模拟的VPP buffer数据
 */
static void generate_test_buffers(vlib_buffer_t** buffers, int count) {
    printf("📦 生成 %d 个测试buffer...\n", count);

    // TLS Client Hello模板数据
    const unsigned char tls_data[] = {
        0x16, 0x03, 0x03, 0x00, 0x4a,  // TLS Record
        0x01, 0x00, 0x00, 0x46,        // Client Hello
        0x03, 0x03,                     // TLS 1.2
        // Random (32 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x00,                           // Session ID Length
        0x00, 0x04,                     // Cipher Suites Length
        0x13, 0x01, 0x13, 0x02,         // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
        0x01,                           // Compression Methods Length
        0x00,                           // NULL Compression
        0x00, 0x1a,                     // Extensions Length
        // Extensions...
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
        0x00, 0x0a, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17,
        0x00, 0x23, 0x00, 0x03, 0x02, 0x03, 0x04,
        0x00, 0x0d, 0x00, 0x10, 0x04, 0x03, 0x08, 0x04,
        0x04, 0x01, 0x02, 0x03, 0x08, 0x05, 0x05, 0x01
    };

    for (int i = 0; i < count; i++) {
        buffers[i] = calloc(1, sizeof(vlib_buffer_t));
        if (buffers[i]) {
            buffers[i]->length = sizeof(tls_data);
            buffers[i]->current_length = sizeof(tls_data);
            memcpy(buffers[i]->data, tls_data, sizeof(tls_data));

            // 添加一些变化：修改Random部分
            buffers[i]->data[11] = (i >> 8) & 0xFF;
            buffers[i]->data[12] = i & 0xFF;
        }
    }

    printf("✅ 测试buffer生成完成\n");
}

/**
 * 清理测试buffer
 */
static void cleanup_test_buffers(vlib_buffer_t** buffers, int count) {
    for (int i = 0; i < count; i++) {
        if (buffers[i]) {
            free(buffers[i]);
        }
    }
}

/**
 * 演示VPP节点注册和数据处理
 */
static void demo_vpp_node_processing() {
    printf("\n🚀 === VPP节点处理演示 ===\n");

    // 注册TLS JA4节点
    static vlib_node_registration_t tls_ja4_node = {
        .name = "tls-ja4-extractor",
        .function = (vlib_node_function_t)tls_ja4_node_function,
        .flags = 0
    };

    if (register_vlib_node(&tls_ja4_node) != 0) {
        printf("❌ 节点注册失败\n");
        return;
    }

    // 初始化节点
    if (init_tls_ja4_node(0) != 0) {
        printf("❌ 节点初始化失败\n");
        return;
    }

    // 生成测试数据
    const int test_buffer_count = 100;
    vlib_buffer_t* test_buffers[test_buffer_count];
    generate_test_buffers(test_buffers, test_buffer_count);

    // 模拟VPP处理：分批次调用节点函数
    printf("🔄 模拟VPP数据处理...\n");
    const int batch_size = 10;
    int total_processed = 0;

    for (int i = 0; i < test_buffer_count; i += batch_size) {
        int current_batch = (i + batch_size < test_buffer_count) ? batch_size : (test_buffer_count - i);
        vlib_buffer_t* batch[batch_size];

        for (int j = 0; j < current_batch; j++) {
            batch[j] = test_buffers[i + j];
        }

        int processed = tls_ja4_node_function(vm, batch, current_batch);
        total_processed += processed;

        printf("📦 批次 %d-%d: 处理了 %d 个有效数据包\n",
               i, i + current_batch - 1, processed);

        // 模拟处理延迟
        usleep(1000);  // 1ms
    }

    printf("✅ 总共处理了 %d 个有效的TLS数据包\n", total_processed);

    // 清理测试数据
    cleanup_test_buffers(test_buffers, test_buffer_count);

    // 清理节点
    cleanup_tls_ja4_node(0);
}

/**
 * 演示多Worker线程环境
 */
static void demo_multiworker_environment() {
    printf("\n🧵 === 多Worker环境演示 ===\n");

    const int num_workers = 4;
    max_workers = num_workers;

    // 初始化多个Worker的节点
    printf("🔧 初始化 %d 个Worker节点...\n", num_workers);
    for (int i = 0; i < num_workers; i++) {
        if (init_tls_ja4_node(i) != 0) {
            printf("❌ Worker %d 初始化失败\n", i);
            continue;
        }
    }

    // 为每个Worker生成测试数据
    printf("📦 为每个Worker生成测试数据...\n");
    for (int worker_id = 0; worker_id < num_workers; worker_id++) {
        const int test_buffers = 50;
        vlib_buffer_t* buffers[test_buffers];
        generate_test_buffers(buffers, test_buffers);

        // 模拟Worker处理数据
        int processed = 0;
        for (int i = 0; i < test_buffers; i++) {
            // 简化处理：每个buffer单独处理
            processed += tls_ja4_node_function(vm, &buffers[i], 1);
        }

        printf("🧵 Worker %d: 处理了 %d/%d 个数据包\n",
               worker_id, processed, test_buffers);

        cleanup_test_buffers(buffers, test_buffers);
    }

    // 打印所有Worker的统计信息
    printf("\n📊 === 所有Worker统计信息 ===\n");
    for (int i = 0; i < num_workers; i++) {
        print_node_statistics(&node_contexts[i]);
    }

    // 清理所有Worker
    printf("\n🧹 清理所有Worker节点...\n");
    for (int i = 0; i < num_workers; i++) {
        cleanup_tls_ja4_node(i);
    }
}

/**
 * 演示性能监控和调优
 */
static void demo_performance_monitoring() {
    printf("\n📈 === 性能监控和调优演示 ===\n");

    // 初始化监控节点
    if (init_tls_ja4_node(0) != 0) {
        printf("❌ 监控节点初始化失败\n");
        return;
    }

    tls_ja4_node_ctx_t* ctx = &node_contexts[0];

    // 测试不同批次大小的性能
    int batch_sizes[] = {1, 10, 50, 100, 200};
    int num_tests = sizeof(batch_sizes) / sizeof(batch_sizes[0]);

    printf("🔄 测试不同批次大小的处理性能...\n");
    for (int test = 0; test < num_tests; test++) {
        int batch_size = batch_sizes[test];
        printf("\n📊 测试批次大小: %d\n", batch_size);

        // 重置统计
        ctx->packets_processed = 0;
        ctx->fingerprints_found = 0;
        ctx->start_time = get_timestamp_ms();

        // 生成测试数据
        vlib_buffer_t* buffers[batch_size];
        generate_test_buffers(buffers, batch_size);

        // 处理数据
        uint64_t start_time = get_timestamp_ms();
        int processed = tls_ja4_node_function(vm, buffers, batch_size);
        uint64_t end_time = get_timestamp_ms();

        // 计算性能指标
        double processing_time_ms = end_time - start_time;
        double throughput = batch_size * 1000.0 / processing_time_ms;  // 包/秒

        printf("  处理时间: %.2f ms\n", processing_time_ms);
        printf("  有效处理: %d 包\n", processed);
        printf("  吞吐量: %.0f 包/秒\n", throughput);
        printf("  平均延迟: %.2f μs/包\n", processing_time_ms * 1000.0 / batch_size);

        cleanup_test_buffers(buffers, batch_size);
    }

    // 清理监控节点
    cleanup_tls_ja4_node(0);
}

/**
 * 主函数
 */
int main() {
    printf("🚀 TLS JA4/JA3 Fingerprint Extractor - VPP集成示例\n");
    printf("===================================================\n");

    // 初始化VPP框架
    init_vlib_main();

    // VPP节点处理演示
    demo_vpp_node_processing();

    // 多Worker环境演示
    demo_multiworker_environment();

    // 性能监控演示
    demo_performance_monitoring();

    printf("\n✨ 所有VPP集成演示完成!\n");
    printf("💡 VPP集成要点:\n");
    printf("  - 每个Worker线程应使用独立的TLS上下文\n");
    printf("  - 预处理检查可显著提高性能\n");
    printf("  - 合理配置缓存大小以平衡内存和性能\n");
    printf("  - 批处理大小对吞吐量有重要影响\n");
    printf("  - 统计信息监控对性能调优很重要\n");

    return 0;
}