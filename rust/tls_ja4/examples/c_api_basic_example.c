/**
 * TLS JA4/JA3 Fingerprint Extractor - 基础C API使用示例
 *
 * 演示如何使用C API进行TLS指纹提取的基本功能
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "tls_ja4.h"

/**
 * 打印JA3指纹结果
 */
void print_ja3_result(const TlsJa3Result* result) {
    if (!result) {
        printf("❌ JA3结果为空\n");
        return;
    }

    printf("\n📊 JA3分析结果:\n");
    printf("  状态码: %d\n", result->status_code);
    printf("  是否Client Hello: %s\n", result->is_client_hello ? "是" : "否");
    printf("  分析是否完成: %s\n", result->is_complete ? "是" : "否");
    printf("  时间戳: %lu ms\n", result->timestamp);

    if (result->is_complete && result->fingerprint.fingerprint_len > 0) {
        printf("  JA3指纹: %.*s\n", result->fingerprint.fingerprint_len, result->fingerprint.fingerprint);
        printf("  TLS版本: 0x%04x\n", result->fingerprint.tls_version);
        printf("  密码套件数量: %u\n", result->fingerprint.cipher_count);
        printf("  扩展数量: %u\n", result->fingerprint.extension_count);
    }
}

/**
 * 打印JA4指纹结果
 */
void print_ja4_result(const TlsJa4Result* result) {
    if (!result) {
        printf("❌ JA4结果为空\n");
        return;
    }

    printf("\n📊 JA4分析结果:\n");
    printf("  状态码: %d\n", result->status_code);
    printf("  是否Client Hello: %s\n", result->is_client_hello ? "是" : "否");
    printf("  分析是否完成: %s\n", result->is_complete ? "是" : "否");
    printf("  数据库匹配: %s\n", result->is_match ? "匹配" : "不匹配");
    printf("  时间戳: %lu ms\n", result->timestamp);

    if (result->is_complete && result->fingerprint.fingerprint_len > 0) {
        printf("  JA4指纹: %.*s\n", result->fingerprint.fingerprint_len, result->fingerprint.fingerprint);
        printf("  TLS版本: 0x%04x\n", result->fingerprint.tls_version);
        printf("  密码套件数量: %u\n", result->fingerprint.cipher_count);
        printf("  扩展数量: %u\n", result->fingerprint.extension_count);
    }
}

/**
 * 演示基本的TLS检测和指纹提取
 */
void demo_basic_fingerprinting() {
    printf("🔍 === 基础指纹提取演示 ===\n");

    // 示例TLS Client Hello数据（使用与Rust测试相同的格式）
    const unsigned char tls_client_hello[] = {
        // TLS Handshake (74 bytes)
        0x16, 0x03, 0x01, 0x00, 0x4a,  // TLS Handshake header
        0x01, 0x00, 0x00, 0x46,        // Client Hello header
        0x03, 0x03,                     // TLS 1.2
        // Random (32 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,                           // Session ID length
        0x00, 0x04,                     // Cipher suites length
        0x00, 0x2f, 0x00, 0x35,         // Cipher suites
        0x01,                           // Compression methods length
        0x00,                           // Compression methods
        0x00, 0x1a,                     // Extensions length
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,  // Supported groups
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,  // EC point formats
        0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x00, 0x0a,  // Signature algorithms
    };

    const size_t data_len = sizeof(tls_client_hello);

    printf("📦 输入数据长度: %zu 字节\n", data_len);

    // 1. 检测是否为TLS报文
    int tls_result = tls_is_tls_packet(tls_client_hello, data_len);
    printf("🔍 TLS检测结果: %s\n",
           tls_result == TLS_JA4_SUCCESS ? "✅ TLS报文" : "❌ 非TLS报文");

    if (tls_result != TLS_JA4_SUCCESS) {
        printf("❌ 数据不是TLS报文，跳过后续分析\n");
        return;
    }

    // 2. 检测是否为Client Hello
    int ch_result = tls_is_client_hello(tls_client_hello, data_len);
    printf("🔍 Client Hello检测结果: %s\n",
           ch_result == TLS_JA4_SUCCESS ? "✅ Client Hello" : "❌ 非Client Hello");

    if (ch_result != TLS_JA4_SUCCESS) {
        printf("❌ 数据不是Client Hello，跳过后续分析\n");
        return;
    }

    // 3. 计算JA3指纹
    TlsJa3Result ja3_result = {0};
    int ja3_ret = tls_calculate_ja3(tls_client_hello, data_len, &ja3_result);
    printf("🔍 JA3计算结果: %s\n",
           ja3_ret == TLS_JA4_SUCCESS ? "✅ 成功" : "❌ 失败");

    if (ja3_ret == TLS_JA4_SUCCESS) {
        print_ja3_result(&ja3_result);
    } else {
        printf("❌ JA3计算失败，错误码: %d\n", ja3_ret);
    }

    // 4. 计算JA4指纹
    TlsJa4Result ja4_result = {0};
    int ja4_ret = tls_calculate_ja4(tls_client_hello, data_len, &ja4_result);
    printf("🔍 JA4计算结果: %s\n",
           ja4_ret == TLS_JA4_SUCCESS ? "✅ 成功" : "❌ 失败");

    if (ja4_ret == TLS_JA4_SUCCESS) {
        print_ja4_result(&ja4_result);
    } else {
        printf("❌ JA4计算失败，错误码: %d\n", ja4_ret);
    }
}

/**
 * 演示错误处理
 */
void demo_error_handling() {
    printf("\n⚠️  === 错误处理演示 ===\n");

    // 测试NULL指针
    printf("🔍 测试NULL指针输入:\n");
    int null_result = tls_is_tls_packet(NULL, 100);
    printf("  NULL指针检测结果: %d (应该是错误码)\n", null_result);

    // 测试空数据
    printf("🔍 测试空数据:\n");
    int empty_result = tls_is_tls_packet((const unsigned char*)"test", 0);
    printf("  空数据检测结果: %d (应该是错误码)\n", empty_result);

    // 测试非TLS数据
    printf("🔍 测试非TLS数据:\n");
    const unsigned char http_data[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    int http_result = tls_is_tls_packet(http_data, sizeof(http_data) - 1);
    printf("  HTTP数据检测结果: %d (应该是TLS_JA4_NOT_TLS)\n", http_result);

    // 测试TLS但非Client Hello数据
    printf("🔍 测试TLS非Client Hello数据:\n");
    const unsigned char tls_server_hello[] = {
        0x16, 0x03, 0x03, 0x00, 0x2a,  // TLS Record Layer
        0x02, 0x00, 0x00, 0x26,        // Server Hello
        0x03, 0x03,                    // TLS 1.2
        // ... 其他数据
    };

    int sh_result = tls_is_client_hello(tls_server_hello, sizeof(tls_server_hello));
    printf("  Server Hello检测结果: %d (应该是TLS_JA4_NOT_CLIENT_HELLO)\n", sh_result);
}

/**
 * 演示上下文管理
 */
void demo_context_management() {
    printf("\n🔧 === 上下文管理演示 ===\n");

    // 初始化上下文
    printf("🔧 初始化TLS上下文...\n");
    TlsJa4Context* ctx = tls_init();

    if (!ctx) {
        printf("❌ 上下文初始化失败\n");
        return;
    }

    printf("✅ 上下文初始化成功: %p\n", (void*)ctx);

    // 注意：当前版本的C API暂不包含缓存管理函数
    // 这些功能将在未来版本中提供：
    // - tls_ja4_set_cache_limits
    // - tls_ja4_get_cache_stats
    // - tls_ja4_cleanup_timeout_cache

    printf("📝 注意: 当前版本为简化API，暂不支持缓存管理功能\n");
    printf("📝 完整的缓存管理功能将在未来版本中提供\n");

    // 清理上下文
    printf("🧹 清理上下文...\n");
    tls_cleanup(ctx);
    printf("✅ 上下文清理完成\n");
}

/**
 * 主函数
 */
int main() {
    printf("🚀 TLS JA4/JA3 Fingerprint Extractor - C API基础示例\n");
    printf("==================================================\n");

    // 运行各个演示
    demo_basic_fingerprinting();
    demo_error_handling();
    demo_context_management();

    printf("\n✨ 所有演示完成!\n");
    return 0;
}