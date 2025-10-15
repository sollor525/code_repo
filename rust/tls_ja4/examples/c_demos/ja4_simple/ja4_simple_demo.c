/*
 * 简化的JA4指纹计算演示程序
 * 使用纯TLS载荷数据（不包含IP/TCP头）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

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

// 外部函数声明（模拟Rust导出的C函数）
extern int32_t tls_ja4_is_tls_packet(const uint8_t* tcp_payload, uint32_t payload_len);
extern int32_t tls_ja4_is_client_hello(const uint8_t* tcp_payload, uint32_t payload_len);
extern int32_t tls_ja4_analyze_client_hello(const uint8_t* tls_payload, uint32_t payload_len, TlsJa4Result* result);
extern TlsJa4Context* tls_ja4_init(void);
extern void tls_ja4_cleanup(TlsJa4Context* ctx);

// 真实的TLS Client Hello数据（仅TLS载荷）
// 这是Chrome浏览器的典型Client Hello
static const uint8_t chrome_tls12_hello[] = {
    // TLS Record Layer
    0x16, 0x03, 0x01, 0x00, 0xc7,  // Handshake, Version 1.2, Length 199

    // Handshake Message
    0x01, 0x00, 0x00, 0xc3,        // Client Hello, Length 195
    0x03, 0x03,                     // TLS Version 1.2

    // Random (32 bytes)
    0x8a, 0x8c, 0x1e, 0x73, 0xa2, 0x4f, 0xa5, 0x1e,
    0x6a, 0x3e, 0x4a, 0xe8, 0x9a, 0xc9, 0x6b, 0x19,
    0x54, 0x7e, 0x8a, 0xb7, 0x1f, 0x6c, 0x9a, 0x2d,
    0xc7, 0x5d, 0x8a, 0x9c, 0xa8, 0x1c, 0xd8, 0xc7,

    0x00,                          // Session ID Length
    0x00, 0x1a,                    // Cipher Suites Length (26)
    // Cipher Suites
    0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b,
    0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xc0, 0x13,
    0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f,
    0x00, 0x35,

    0x01,                          // Compression Methods Length
    0x00,                          // Compression Methods

    0x00, 0x6b,                    // Extensions Length (107)

    // Extensions
    0x00, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06,
    0x00, 0x17, 0x00, 0x18, 0x00, 0x19,              // Server Name Indication

    0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,              // EC Point Formats

    0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17,
    0x00, 0x18, 0x00, 0x19,                          // Supported Groups

    0x00, 0x23, 0x00, 0x00,                          // Session Ticket

    0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x03,
    0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05,
    0x05, 0x01, 0x08, 0x06, 0x06, 0x01,              // Signature Algorithms

    0x00, 0x35, 0x00, 0x01,                          // ALPN

    0x00, 0x2d, 0x00, 0x02, 0x03, 0x04,              // Supported Versions

    0x00, 0x33, 0x00, 0x2b, 0x00, 0x24, 0x00, 0x1d,
    0x00, 0x20, 0xd9, 0x2a, 0x3c, 0xf9, 0x66, 0x0b,
    0x3d, 0x7f, 0x6c, 0x8f, 0x6b, 0x8a, 0x1f, 0x4e,
    0x9a, 0x3d, 0x8f, 0xa6, 0x9c, 0x3e, 0x4b, 0x1f,  // Key Share

    0x00, 0x2b, 0x00, 0x02, 0x01, 0x01               // PSK Key Exchange Modes
};

// 简单的TLS 1.3 Client Hello
static const uint8_t simple_tls13_hello[] = {
    // TLS Record Layer
    0x16, 0x03, 0x01, 0x00, 0x5e,  // Handshake, Version 1.2, Length 94

    // Handshake Message
    0x01, 0x00, 0x00, 0x5a,        // Client Hello, Length 90
    0x03, 0x03,                     // TLS Version 1.2

    // Random (32 bytes)
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,

    0x00,                          // Session ID Length

    0x00, 0x04,                    // Cipher Suites Length (4)
    0x13, 0x01, 0x13, 0x02,        // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384

    0x01,                          // Compression Methods Length
    0x00,                          // Compression Methods

    0x00, 0x2a,                    // Extensions Length (42)

    // Extensions
    0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,              // PSK Key Exchange Modes

    0x00, 0x33, 0x00, 0x2b, 0x00, 0x24, 0x00, 0x1d,
    0x00, 0x20, 0x9b, 0xc6, 0x6a, 0x3c, 0x5a, 0x8a,
    0x3d, 0xf9, 0x2e, 0x1d, 0x4c, 0x3a, 0x5a, 0x6b,
    0x7c, 0x8d, 0x9e, 0xaf, 0xb0, 0xc1, 0xd2, 0xe3,  // Key Share

    0x00, 0x0d, 0x00, 0x08, 0x04, 0x03, 0x08, 0x04,
    0x04, 0x01, 0x05, 0x03                              // Signature Algorithms
};

// 测试用例结构体
typedef struct {
    const char* name;
    const uint8_t* data;
    uint32_t data_len;
    int32_t expected_tls;
    int32_t expected_ch;
} TestCase;

static TestCase test_cases[] = {
    {
        .name = "Chrome TLS 1.2 Client Hello",
        .data = chrome_tls12_hello,
        .data_len = sizeof(chrome_tls12_hello),
        .expected_tls = TLS_JA4_SUCCESS,
        .expected_ch = TLS_JA4_SUCCESS
    },
    {
        .name = "Simple TLS 1.3 Client Hello",
        .data = simple_tls13_hello,
        .data_len = sizeof(simple_tls13_hello),
        .expected_tls = TLS_JA4_SUCCESS,
        .expected_ch = TLS_JA4_SUCCESS
    }
};

void test_tls_detection() {
    printf("=== TLS检测测试 ===\n");

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(TestCase); i++) {
        TestCase* tc = &test_cases[i];
        printf("\n测试 %zu: %s\n", i + 1, tc->name);

        int32_t is_tls = tls_ja4_is_tls_packet(tc->data, tc->data_len);
        int32_t is_ch = tls_ja4_is_client_hello(tc->data, tc->data_len);

        printf("数据长度: %u 字节\n", tc->data_len);
        printf("TLS检测: %d (期望: %d)\n", is_tls, tc->expected_tls);
        printf("Client Hello检测: %d (期望: %d)\n", is_ch, tc->expected_ch);

        if (is_tls == tc->expected_tls && is_ch == tc->expected_ch) {
            printf("✅ 检测通过\n");
        } else {
            printf("❌ 检测失败\n");
        }
    }
}

void test_fingerprint_calculation() {
    printf("\n=== JA4指纹计算测试 ===\n");

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(TestCase); i++) {
        TestCase* tc = &test_cases[i];

        printf("\n测试 %zu: %s\n", i + 1, tc->name);
        printf("数据长度: %u 字节\n", tc->data_len);

        TlsJa4Result result = {0};
        int32_t ret = tls_ja4_analyze_client_hello(tc->data, tc->data_len, &result);

        printf("分析返回码: %d\n", ret);
        printf("状态码: %d\n", result.status_code);
        printf("是否完成: %d\n", result.is_complete);

        if (ret == TLS_JA4_SUCCESS && result.is_complete) {
            printf("✅ 指纹计算成功\n");

            // 打印JA4指纹
            if (result.fingerprint.ja4_len > 0) {
                char ja4_str[65] = {0};
                memcpy(ja4_str, result.fingerprint.ja4, result.fingerprint.ja4_len);
                printf("JA4指纹: %s\n", ja4_str);
            }

            // 打印JA3指纹
            if (result.fingerprint.ja3_len > 0) {
                char ja3_str[65] = {0};
                memcpy(ja3_str, result.fingerprint.ja3, result.fingerprint.ja3_len);
                printf("JA3指纹: %s\n", ja3_str);
            }

            printf("TLS版本: 0x%04x\n", result.fingerprint.tls_version);
            printf("密码套件数量: %d\n", result.fingerprint.cipher_count);
            printf("扩展数量: %d\n", result.fingerprint.extension_count);
            printf("时间戳: %lu\n", result.timestamp);
        } else {
            printf("❌ 指纹计算失败\n");

            // 调试信息：显示前几个字节
            printf("数据前16字节: ");
            for (int j = 0; j < 16 && j < tc->data_len; j++) {
                printf("%02x ", tc->data[j]);
            }
            printf("\n");
        }
    }
}

void test_data_validation() {
    printf("\n=== 数据验证测试 ===\n");

    // 测试NULL指针
    printf("测试NULL指针处理:\n");
    int32_t result1 = tls_ja4_is_tls_packet(NULL, 100);
    int32_t result2 = tls_ja4_is_client_hello(NULL, 100);
    printf("TLS检测 NULL指针: %d (期望: %d)\n", result1, TLS_JA4_INVALID_PARAMETER);
    printf("Client Hello检测 NULL指针: %d (期望: %d)\n", result2, TLS_JA4_INVALID_PARAMETER);

    // 测试空数据
    printf("\n测试空数据:\n");
    uint8_t dummy_data[] = {0x16};
    int32_t result3 = tls_ja4_is_tls_packet(dummy_data, 0);
    int32_t result4 = tls_ja4_is_client_hello(dummy_data, 0);
    printf("TLS检测空数据: %d (期望: %d)\n", result3, TLS_JA4_INVALID_PARAMETER);
    printf("Client Hello检测空数据: %d (期望: %d)\n", result4, TLS_JA4_INVALID_PARAMETER);

    // 测试非TLS数据
    printf("\n测试非TLS数据:\n");
    uint8_t non_tls_data[] = {0x45, 0x00, 0x00, 0x28}; // IPv4头部开头
    int32_t result5 = tls_ja4_is_tls_packet(non_tls_data, sizeof(non_tls_data));
    int32_t result6 = tls_ja4_is_client_hello(non_tls_data, sizeof(non_tls_data));
    printf("TLS检测非TLS数据: %d (期望: %d)\n", result5, TLS_JA4_NOT_TLS);
    printf("Client Hello检测非TLS数据: %d (期望: %d)\n", result6, TLS_JA4_NOT_CLIENT_HELLO);
}

int main() {
    printf("简化的JA4指纹计算演示程序\n");
    printf("============================\n");
    printf("该程序使用纯TLS载荷数据验证JA4指纹计算\n");

    // 运行测试
    test_data_validation();
    test_tls_detection();
    test_fingerprint_calculation();

    printf("\n=== 测试总结 ===\n");
    printf("程序执行完成。请查看上述输出验证JA4指纹计算的可行性。\n");
    printf("如果看到有效的JA4/JA3指纹，说明C API工作正常。\n");

    return 0;
}