#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Include the C API header
#include "include/tls_ja4.h"

// Sample IP packet with TLS Client Hello (simplified for testing)
const uint8_t test_ip_packet_with_tls[] = {
    // IP header (20 bytes)
    0x45, 0x00, 0x00, 0x64, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
    0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02,

    // TCP header (20 bytes)
    0x30, 0x39, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x50, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // TLS Client Hello payload
    0x16, 0x03, 0x03, 0x00, 0x31,  // TLS Handshake, TLS 1.2, length 49
    0x01, 0x00, 0x00, 0x2d,        // Client Hello, length 45
    0x03, 0x03,                    // TLS 1.2
    // Random (32 bytes)
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x00,                          // Session ID length 0
    0x00, 0x04,                    // Cipher suites length 4
    0x00, 0x2f, 0x00, 0x35,        // TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA
    0x01,                          // Compression methods length 1
    0x00,                          // Null compression
    0x00, 0x00                     // Extensions length 0
};

// Test TCP payload directly (for tls_ja4_is_tls_packet and tls_ja4_is_client_hello)
const uint8_t test_tls_client_hello[] = {
    0x16, 0x03, 0x03, 0x00, 0x31,  // TLS Handshake, TLS 1.2, length 49
    0x01, 0x00, 0x00, 0x2d,        // Client Hello, length 45
    0x03, 0x03,                    // TLS 1.2
    // Random (32 bytes)
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x00,                          // Session ID length 0
    0x00, 0x04,                    // Cipher suites length 4
    0x00, 0x2f, 0x00, 0x35,        // TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA
    0x01,                          // Compression methods length 1
    0x00,                          // Null compression
    0x00, 0x00                     // Extensions length 0
};

// Non-TLS data for testing
const uint8_t test_non_tls_data[] = {
    0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30
};

void test_tls_detection() {
    printf("=== TLS Detection Tests ===\n");

    // Test TLS packet detection
    int is_tls = tls_ja4_is_tls_packet(test_tls_client_hello, sizeof(test_tls_client_hello));
    printf("TLS packet detection: %s\n", is_tls == TLS_JA4_SUCCESS ? "✅ Success" : "❌ Failed");

    // Test Client Hello detection
    int is_client_hello = tls_ja4_is_client_hello(test_tls_client_hello, sizeof(test_tls_client_hello));
    printf("Client Hello detection: %s\n", is_client_hello == TLS_JA4_SUCCESS ? "✅ Success" : "❌ Failed");

    // Test non-TLS data
    int is_non_tls = tls_ja4_is_tls_packet(test_non_tls_data, sizeof(test_non_tls_data));
    printf("Non-TLS detection: %s\n", is_non_tls == TLS_JA4_NOT_TLS ? "✅ Correctly rejected" : "❌ Incorrectly accepted");
}

void test_packet_analysis() {
    printf("\n=== Packet Analysis Tests ===\n");

    // Initialize context
    TlsJa4Context* ctx = tls_ja4_init();
    if (!ctx) {
        printf("❌ Failed to initialize TLS JA4 context\n");
        return;
    }
    printf("✅ TLS JA4 context initialized successfully\n");

    // Test packet analysis with IP packet
    TlsJa4Result result;
    memset(&result, 0, sizeof(result));

    int analysis_result = tls_ja4_analyze_packet(ctx, test_ip_packet_with_tls, sizeof(test_ip_packet_with_tls), &result);

    printf("Packet analysis result: %d\n", analysis_result);
    printf("Is Client Hello: %d\n", result.is_client_hello);
    printf("Is Complete: %d\n", result.is_complete);
    printf("Status Code: %d\n", result.status_code);
    printf("Cached Bytes: %u\n", result.cached_bytes);
    printf("Flow ID: %u\n", result.flow_id);
    printf("Timestamp: %lu\n", result.timestamp);

    if (result.is_client_hello && result.is_complete) {
        printf("\n=== Fingerprint Results ===\n");
        printf("JA4: %.*s\n", result.fingerprint.ja4_len, result.fingerprint.ja4);
        printf("JA3: %.*s\n", result.fingerprint.ja3_len, result.fingerprint.ja3);
        printf("TLS Version: 0x%04x\n", result.fingerprint.tls_version);
        printf("Cipher Count: %u\n", result.fingerprint.cipher_count);
        printf("Extension Count: %u\n", result.fingerprint.extension_count);
    }

    // Cleanup
    tls_ja4_cleanup(ctx);
    printf("✅ TLS JA4 context cleaned up successfully\n");
}

void test_cache_management() {
    printf("\n=== Cache Management Tests ===\n");

    TlsJa4Context* ctx = tls_ja4_init();
    if (!ctx) {
        printf("❌ Failed to initialize TLS JA4 context\n");
        return;
    }

    // Set cache limits
    int cache_result = tls_ja4_set_cache_limits(ctx, 1000, 1024*1024, 30000);
    printf("Set cache limits: %s\n", cache_result == TLS_JA4_SUCCESS ? "✅ Success" : "❌ Failed");

    // Get cache stats
    uint32_t active_flows = 0;
    uint32_t total_cached_bytes = 0;
    int stats_result = tls_ja4_get_cache_stats(ctx, &active_flows, &total_cached_bytes);
    printf("Get cache stats: %s\n", stats_result == TLS_JA4_SUCCESS ? "✅ Success" : "❌ Failed");
    printf("Active flows: %u\n", active_flows);
    printf("Total cached bytes: %u\n", total_cached_bytes);

    // Cleanup timeout cache
    unsigned int cleanup_result = tls_ja4_cleanup_timeout_cache(ctx, 0);
    printf("Cleanup timeout cache: cleaned %u flows\n", cleanup_result);

    tls_ja4_cleanup(ctx);
    printf("✅ Cache management test completed\n");
}

void test_null_context() {
    printf("\n=== NULL Context Tests ===\n");

    TlsJa4Result result;
    memset(&result, 0, sizeof(result));

    // Test with NULL context (should work with internal context management)
    int analysis_result = tls_ja4_analyze_packet(NULL, test_ip_packet_with_tls, sizeof(test_ip_packet_with_tls), &result);
    printf("NULL context analysis result: %d\n", analysis_result);
    printf("NULL context test: %s\n", analysis_result != TLS_JA4_INVALID_PARAMETER ? "✅ Success" : "❌ Failed");
}

int main() {
    printf("=== Comprehensive TLS JA4 C API Test ===\n\n");

    test_tls_detection();
    test_packet_analysis();
    test_cache_management();
    test_null_context();

    printf("\n=== C API Test Complete ===\n");
    return 0;
}