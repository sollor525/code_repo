/**
 * @file test_performance.c
 * @brief Hook性能测试 - 测试在高并发场景下的性能影响
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define NUM_THREADS 10
#define NUM_OPERATIONS_PER_THREAD 1000

typedef struct {
    int thread_id;
    int num_operations;
    double total_time;
    int success_count;
} thread_data_t;

void* ssl_thread_worker(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    struct timespec start_time, end_time;

    // 创建SSL上下文
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        printf("线程 %d: 创建SSL上下文失败\n", data->thread_id);
        return NULL;
    }

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    for (int i = 0; i < data->num_operations; i++) {
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            continue;
        }

        // 执行各种SSL操作（会失败，但测试Hook性能）
        SSL_connect(ssl);
        SSL_write(ssl, "test", 4);
        SSL_read(ssl, NULL, 0);

        SSL_free(ssl);
        data->success_count++;
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);

    // 计算总时间（秒）
    data->total_time = (end_time.tv_sec - start_time.tv_sec) +
                      (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    SSL_CTX_free(ctx);
    return NULL;
}

int run_performance_test() {
    printf("=== Hook性能测试 ===\n");
    printf("线程数: %d\n", NUM_THREADS);
    printf("每线程操作数: %d\n", NUM_OPERATIONS_PER_THREAD);
    printf("总操作数: %d\n", NUM_THREADS * NUM_OPERATIONS_PER_THREAD);
    printf("\n开始性能测试...\n");

    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // 创建线程
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].num_operations = NUM_OPERATIONS_PER_THREAD;
        thread_data[i].total_time = 0;
        thread_data[i].success_count = 0;

        if (pthread_create(&threads[i], NULL, ssl_thread_worker, &thread_data[i]) != 0) {
            printf("创建线程 %d 失败\n", i);
            return -1;
        }
    }

    // 等待所有线程完成
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);

    double total_time = (end_time.tv_sec - start_time.tv_sec) +
                       (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    // 统计结果
    int total_success = 0;
    double total_thread_time = 0;
    double min_time = 999999;
    double max_time = 0;

    for (int i = 0; i < NUM_THREADS; i++) {
        total_success += thread_data[i].success_count;
        total_thread_time += thread_data[i].total_time;
        if (thread_data[i].total_time < min_time) {
            min_time = thread_data[i].total_time;
        }
        if (thread_data[i].total_time > max_time) {
            max_time = thread_data[i].total_time;
        }
    }

    printf("\n=== 性能测试结果 ===\n");
    printf("总耗时: %.3f 秒\n", total_time);
    printf("成功操作数: %d / %d\n", total_success, NUM_THREADS * NUM_OPERATIONS_PER_THREAD);
    printf("平均每秒操作数: %.1f\n", total_success / total_time);
    printf("平均每操作耗时: %.6f 毫秒\n", (total_time * 1000) / total_success);
    printf("线程平均耗时: %.3f 秒\n", total_thread_time / NUM_THREADS);
    printf("最快线程: %.3f 秒\n", min_time);
    printf("最慢线程: %.3f 秒\n", max_time);
    printf("线程执行时间差异: %.3f 秒\n", max_time - min_time);

    return 0;
}

int run_baseline_test() {
    printf("\n=== 基准性能测试（无Hook） ===\n");

    // 创建单个SSL上下文进行基准测试
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        printf("基准测试失败: 无法创建SSL上下文\n");
        return -1;
    }

    struct timespec start_time, end_time;
    const int base_operations = 10000;

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    for (int i = 0; i < base_operations; i++) {
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            continue;
        }

        SSL_connect(ssl);
        SSL_write(ssl, "test", 4);
        SSL_read(ssl, NULL, 0);

        SSL_free(ssl);
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);

    double base_time = (end_time.tv_sec - start_time.tv_sec) +
                      (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    printf("基准测试完成:\n");
    printf("  操作数: %d\n", base_operations);
    printf("  总耗时: %.3f 秒\n", base_time);
    printf("  平均每操作耗时: %.6f 毫秒\n", (base_time * 1000) / base_operations);

    SSL_CTX_free(ctx);
    return 0;
}

int main() {
    printf("=== TLS Hook性能测试程序 ===\n");

    // 设置密钥日志文件
    setenv("SSLKEYLOGFILE", "/tmp/performance_test.log", 1);

    // 初始化OpenSSL
    SSL_library_init();
    SSL_load_error_strings();

    printf("测试时间: %ld\n", time(NULL));

    // 运行基准测试
    run_baseline_test();

    // 运行多线程性能测试
    run_performance_test();

    printf("\n=== 测试完成 ===\n");
    printf("注意: 本测试主要测量Hook的性能开销，而非密钥提取功能\n");

    return 0;
}