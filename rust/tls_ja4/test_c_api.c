#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Include the C API header
#include "include/tls_ja4.h"

// Simple test data - a minimal TLS Client Hello
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

int main() {
    printf("=== TLS JA4 C API Test ===\n");

    // Initialize context
    TlsJa4Context* ctx = tls_ja4_init();
    if (!ctx) {
        printf("❌ Failed to initialize TLS JA4 context\n");
        return 1;
    }
    printf("✅ TLS JA4 context initialized successfully\n");

    // Test packet analysis
    TlsJa4Result result;
    memset(&result, 0, sizeof(result));

    // Note: The test data is TCP payload, but tls_ja4_analyze_packet expects full IP packet
    // For testing, we'll use it as TCP payload directly
    int analysis_result = tls_ja4_analyze_packet(ctx, test_tls_client_hello, sizeof(test_tls_client_hello), &result);

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

    // Test cache management
    printf("\n=== Cache Management Tests ===\n");

    // Set cache limits
    int cache_result = tls_ja4_set_cache_limits(ctx, 1000, 1024*1024, 30000);
    printf("Set cache limits: %s\n", cache_result == 0 ? "✅ Success" : "❌ Failed");

    // Get cache stats
    uint32_t active_flows = 0;
    uint32_t total_cached_bytes = 0;
    int stats_result = tls_ja4_get_cache_stats(ctx, &active_flows, &total_cached_bytes);
    printf("Get cache stats: %s\n", stats_result == 0 ? "✅ Success" : "❌ Failed");
    printf("Active flows: %u\n", active_flows);
    printf("Total cached bytes: %u\n", total_cached_bytes);

    // Cleanup timeout cache (with current time)
    unsigned long current_time = 0; // Simplified for test
    unsigned int cleanup_result = tls_ja4_cleanup_timeout_cache(ctx, current_time);
    printf("Cleanup timeout cache: cleaned %u flows\n", cleanup_result);

    // Cleanup context
    tls_ja4_cleanup(ctx);
    printf("✅ TLS JA4 context cleaned up successfully\n");

    printf("\n=== C API Test Complete ===\n");
    return 0;
}