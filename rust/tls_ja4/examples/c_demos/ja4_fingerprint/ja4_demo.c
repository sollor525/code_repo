/*
 * JA4指纹计算演示程序
 *
 * 该程序演示如何使用JA4指纹计算C API来分析TLS数据包
 * 并验证指纹计算的可行性和正确性
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>

// JA4 C API类型定义
typedef struct {
    uint8_t ja4[64];           /* JA4指纹，固定长度缓冲区 */
    uint32_t ja4_len;          /* JA4指纹实际长度 */
    uint8_t ja3[64];           /* JA3指纹，固定长度缓冲区 */
    uint32_t ja3_len;          /* JA3指纹实际长度 */
    uint16_t tls_version;      /* TLS版本 */
    uint16_t cipher_count;     /* 密码套件数量 */
    uint16_t extension_count;  /* 扩展数量 */
} TlsJa4Fingerprint;

typedef struct {
    TlsJa4Fingerprint fingerprint; /* 指纹数据 */
    uint8_t is_client_hello;       /* 是否为Client Hello */
    uint8_t is_complete;           /* 分析是否完成 */
    int32_t status_code;          /* 返回状态码 */
    uint32_t cached_bytes;        /* 缓存字节数 */
    uint32_t flow_id;             /* 流ID */
    uint64_t timestamp;           /* 时间戳（毫秒） */
    uint8_t is_match;             /* 是否匹配数据库 */
} TlsJa4Result;

typedef struct {
    void* _internal; /* 内部上下文指针 */
} TlsJa4Context;

// 错误码定义
#define TLS_JA4_SUCCESS                 0
#define TLS_JA4_INVALID_PARAMETER      -1
#define TLS_JA4_NOT_TLS                -2
#define TLS_JA4_NOT_CLIENT_HELLO       -3
#define TLS_JA4_INSUFFICIENT_DATA      -4

// 外部函数声明（模拟Rust导出的C函数）
extern int32_t tls_ja4_is_tls_packet(const uint8_t* tcp_payload, uint32_t payload_len);
extern int32_t tls_ja4_is_client_hello(const uint8_t* tcp_payload, uint32_t payload_len);
extern int32_t tls_ja4_analyze_client_hello(const uint8_t* tls_payload, uint32_t payload_len, TlsJa4Result* result);
extern TlsJa4Context* tls_ja4_init(void);
extern void tls_ja4_cleanup(TlsJa4Context* ctx);

// 测试用例结构体
typedef struct {
    const char* name;
    const char* description;
    const uint8_t* data;
    uint32_t data_len;
    int32_t expected_tls;
    int32_t expected_ch;
    const char* expected_ja4;
} TestCase;

// 测试用例数据
static const uint8_t test_data_1[] = {
    // TLS 1.2 Client Hello
    0x16, 0x03, 0x01, 0x00, 0xdc,  // TLS Handshake, Version 1.2, Length 220
    0x01, 0x00, 0x00, 0xd8,        // Client Hello, Length 216
    0x03, 0x03,                     // TLS Version 1.2
    // Random (32 bytes)
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x00,                          // Session ID Length
    0x00, 0x08,                    // Cipher Suites Length (8)
    0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b,  // Cipher Suites
    0x01,                          // Compression Methods Length
    0x00,                          // Compression Methods
    0x00, 0x9e,                    // Extensions Length (158)
    // Extensions
    0x00, 0x00, 0x00, 0x05, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,  // Server Name Indication
    0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,  // EC Point Formats
    0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,  // Supported Groups
    0x00, 0x23, 0x00, 0x00,  // Session Ticket
    0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x05, 0x03, 0x06, 0x01, 0x06, 0x03,  // Signature Algorithms
    0x00, 0x35, 0x00, 0x00,  // ALPN
    0x00, 0x2d, 0x00, 0x02, 0x01, 0x01,  // Supported Versions
    0x00, 0x33, 0x00, 0x2b, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x99, 0xf4, 0x49, 0x6a, 0xe2, 0xeb, 0x6a, 0x1b,  // Key Share
    0xc4, 0x1a, 0x9e, 0x8a, 0x1a, 0x7a, 0x6c, 0x7d, 0x1e, 0x6d, 0xc9, 0xda, 0xd5, 0xe1, 0x1c, 0x7e, 0x4a, 0x91, 0x6c, 0x6a, 0x7d, 0x1e,
    0x00, 0x2b, 0x00, 0x02, 0x03, 0x04  // PSK Key Exchange Modes
};

static const uint8_t test_data_2[] = {
    // 非TLS数据包
    0x45, 0x00, 0x00, 0x28,  // IPv4 Header
    0x08, 0x11, 0x22, 0x33,  // Some non-TLS payload
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff
};

static const uint8_t test_data_3[] = {
    // TLS 1.3 Client Hello
    0x16, 0x03, 0x01, 0x00, 0xc2,  // TLS Handshake, Version 1.2, Length 194
    0x01, 0x00, 0x00, 0xbe,        // Client Hello, Length 190
    0x03, 0x03,                     // TLS Version 1.2
    // Random (32 bytes)
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0x20,                          // Session ID Length (32)
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x00, 0x04,                    // Cipher Suites Length (4)
    0x13, 0x01, 0x13, 0x03,        // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
    0x01,                          // Compression Methods Length
    0x00,                          // Compression Methods
    0x00, 0x62,                    // Extensions Length (98)
    // Extensions
    0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,  // PSK Key Exchange Modes
    0x00, 0x33, 0x00, 0x2b, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x99, 0xf4, 0x49, 0x6a, 0xe2, 0xeb, 0x6a, 0x1b,  // Key Share
    0xc4, 0x1a, 0x9e, 0x8a, 0x1a, 0x7a, 0x6c, 0x7d, 0x1e, 0x6d, 0xc9, 0xda, 0xd5, 0xe1, 0x1c, 0x7e, 0x4a, 0x91, 0x6c, 0x6a, 0x7d, 0x1e,
    0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x05, 0x03, 0x06, 0x01, 0x06, 0x03,  // Signature Algorithms
    0x00, 0x35, 0x00, 0x01, 0x02,  // ALPN
    0x00, 0x2d, 0x00, 0x02, 0x03, 0x04   // Supported Versions
};

// 测试用例数组
static TestCase test_cases[] = {
    {
        .name = "TLS 1.2 Client Hello",
        .description = "标准的TLS 1.2 Client Hello消息",
        .data = test_data_1,
        .data_len = sizeof(test_data_1),
        .expected_tls = TLS_JA4_SUCCESS,
        .expected_ch = TLS_JA4_SUCCESS,
        .expected_ja4 = NULL  // 将在运行时验证
    },
    {
        .name = "Non-TLS Packet",
        .description = "非TLS数据包（IPv4头）",
        .data = test_data_2,
        .data_len = sizeof(test_data_2),
        .expected_tls = TLS_JA4_NOT_TLS,
        .expected_ch = TLS_JA4_NOT_CLIENT_HELLO,
        .expected_ja4 = NULL
    },
    {
        .name = "TLS 1.3 Client Hello",
        .description = "TLS 1.3 Client Hello消息",
        .data = test_data_3,
        .data_len = sizeof(test_data_3),
        .expected_tls = TLS_JA4_SUCCESS,
        .expected_ch = TLS_JA4_SUCCESS,
        .expected_ja4 = NULL
    }
};

// 测试函数
void test_tls_detection() {
    printf("=== TLS检测测试 ===\n");

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(TestCase); i++) {
        TestCase* tc = &test_cases[i];
        printf("\n测试 %zu: %s\n", i + 1, tc->name);
        printf("描述: %s\n", tc->description);

        int32_t is_tls = tls_ja4_is_tls_packet(tc->data, tc->data_len);
        int32_t is_ch = tls_ja4_is_client_hello(tc->data, tc->data_len);

        printf("期望 TLS检测: %d, 实际: %d\n", tc->expected_tls, is_tls);
        printf("期望 Client Hello检测: %d, 实际: %d\n", tc->expected_ch, is_ch);

        if (is_tls == tc->expected_tls && is_ch == tc->expected_ch) {
            printf("✅ 通过\n");
        } else {
            printf("❌ 失败\n");
        }
    }
}

void test_fingerprint_calculation() {
    printf("\n=== JA4指纹计算测试 ===\n");

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(TestCase); i++) {
        TestCase* tc = &test_cases[i];

        // 只测试有效的TLS Client Hello
        if (tc->expected_tls != TLS_JA4_SUCCESS || tc->expected_ch != TLS_JA4_SUCCESS) {
            continue;
        }

        printf("\n测试 %zu: %s\n", i + 1, tc->name);

        TlsJa4Result result = {0};
        int32_t ret = tls_ja4_analyze_client_hello(tc->data, tc->data_len, &result);

        printf("分析返回码: %d\n", ret);
        printf("状态码: %d\n", result.status_code);
        printf("是否完成: %d\n", result.is_complete);

        if (ret == TLS_JA4_SUCCESS && result.is_complete) {
            printf("✅ 指纹计算成功\n");

            // 打印JA4指纹
            char ja4_str[65] = {0};
            memcpy(ja4_str, result.fingerprint.ja4, result.fingerprint.ja4_len);
            printf("JA4指纹: %s\n", ja4_str);

            // 打印JA3指纹
            char ja3_str[65] = {0};
            memcpy(ja3_str, result.fingerprint.ja3, result.fingerprint.ja3_len);
            printf("JA3指纹: %s\n", ja3_str);

            printf("TLS版本: 0x%04x\n", result.fingerprint.tls_version);
            printf("密码套件数量: %d\n", result.fingerprint.cipher_count);
            printf("扩展数量: %d\n", result.fingerprint.extension_count);
            printf("时间戳: %lu\n", result.timestamp);
        } else {
            printf("❌ 指纹计算失败\n");
        }
    }
}

void test_performance() {
    printf("\n=== 性能测试 ===\n");

    const int iterations = 10000;
    TestCase* tc = &test_cases[0]; // 使用第一个测试用例

    if (tc->expected_tls != TLS_JA4_SUCCESS || tc->expected_ch != TLS_JA4_SUCCESS) {
        printf("❌ 性能测试跳过：没有有效的测试数据\n");
        return;
    }

    clock_t start = clock();

    for (int i = 0; i < iterations; i++) {
        TlsJa4Result result = {0};
        tls_ja4_analyze_client_hello(tc->data, tc->data_len, &result);
    }

    clock_t end = clock();
    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;

    printf("执行 %d 次指纹计算耗时: %.4f 秒\n", iterations, elapsed);
    printf("平均每次耗时: %.6f 秒\n", elapsed / iterations);
    printf("每秒可处理: %.0f 次\n", iterations / elapsed);
}

void test_edge_cases() {
    printf("\n=== 边界条件测试 ===\n");

    // 测试NULL指针
    printf("测试NULL指针处理:\n");
    int32_t result1 = tls_ja4_is_tls_packet(NULL, 100);
    int32_t result2 = tls_ja4_is_client_hello(NULL, 100);
    printf("TLS检测 NULL指针: %d (期望: %d)\n", result1, TLS_JA4_INVALID_PARAMETER);
    printf("Client Hello检测 NULL指针: %d (期望: %d)\n", result2, TLS_JA4_INVALID_PARAMETER);

    // 测试零长度数据
    printf("\n测试零长度数据:\n");
    uint8_t dummy_data[] = {0x16, 0x03, 0x01};
    int32_t result3 = tls_ja4_is_tls_packet(dummy_data, 0);
    int32_t result4 = tls_ja4_is_client_hello(dummy_data, 0);
    printf("TLS检测零长度: %d (期望: %d)\n", result3, TLS_JA4_INVALID_PARAMETER);
    printf("Client Hello检测零长度: %d (期望: %d)\n", result4, TLS_JA4_INVALID_PARAMETER);

    // 测试过短的数据
    printf("\n测试过短的数据 (3字节):\n");
    int32_t result5 = tls_ja4_is_tls_packet(dummy_data, 3);
    int32_t result6 = tls_ja4_is_client_hello(dummy_data, 3);
    printf("TLS检测过短数据: %d\n", result5);
    printf("Client Hello检测过短数据: %d\n", result6);
}

void test_context_management() {
    printf("\n=== 上下文管理测试 ===\n");

    printf("测试上下文初始化和清理:\n");

    TlsJa4Context* ctx = tls_ja4_init();
    if (ctx != NULL) {
        printf("✅ 上下文初始化成功\n");
        tls_ja4_cleanup(ctx);
        printf("✅ 上下文清理完成\n");
    } else {
        printf("⚠️  上下文初始化返回NULL (可能是简化实现)\n");
    }
}

int main() {
    printf("JA4指纹计算演示程序\n");
    printf("====================\n");
    printf("该程序验证JA4指纹计算的可行性和正确性\n");

    // 运行各项测试
    test_tls_detection();
    test_fingerprint_calculation();
    test_performance();
    test_edge_cases();
    test_context_management();

    printf("\n=== 测试总结 ===\n");
    printf("所有测试已完成。请检查上述输出以验证JA4指纹计算的正确性。\n");
    printf("如果看到有效的JA4/JA3指纹输出，说明API工作正常。\n");

    return 0;
}