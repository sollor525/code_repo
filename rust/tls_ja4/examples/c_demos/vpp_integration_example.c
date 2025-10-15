/**
 * VPP Integration Example for TLS JA4/JA3 Fingerprinting
 *
 * This example demonstrates how to integrate the TLS JA4 library with VPP
 * for high-performance TLS fingerprint extraction in network traffic.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Include the C API header
#include "include/tls_ja4.h"

/**
 * VPP packet processing function
 * This would be called from VPP's packet processing pipeline
 */
void vpp_process_packet(TlsJa4Context* ctx,
                       const unsigned char* packet_data,
                       unsigned int packet_len,
                       unsigned long current_time_ms) {

    TlsJa4Result result;
    memset(&result, 0, sizeof(result));

    // Analyze the packet
    int ret = tls_ja4_analyze_packet(ctx, packet_data, packet_len, &result);

    switch (ret) {
        case TLS_JA4_SUCCESS:
            // Fingerprint calculation completed successfully
            printf("[VPP] ✅ Fingerprint extracted - JA4: %.*s, JA3: %.*s\n",
                   result.fingerprint.ja4_len, result.fingerprint.ja4,
                   result.fingerprint.ja3_len, result.fingerprint.ja3);

            // Here you would typically:
            // 1. Log the fingerprint for security analysis
            // 2. Send to threat intelligence platform
            // 3. Update flow tracking
            break;

        case TLS_JA4_SEGMENT_CACHED:
            // TCP segment cached, waiting for more data
            printf("[VPP] 🔄 Segment cached - Flow ID: %u, Cached: %u bytes\n",
                   result.flow_id, result.cached_bytes);
            break;

        case TLS_JA4_CACHE_OVERFLOW:
        case TLS_JA4_CACHE_TIMEOUT:
            // Cache overflow or timeout, cache has been cleaned
            printf("[VPP] 🧹 Cache cleaned - Status: %d\n", ret);
            break;

        case TLS_JA4_NOT_TLS:
        case TLS_JA4_NOT_CLIENT_HELLO:
            // Not TLS or not Client Hello, continue processing other packets
            // No action needed for non-TLS traffic
            break;

        default:
            printf("[VPP] ❌ Analysis error - Status: %d\n", ret);
            break;
    }
}

/**
 * VPP worker thread initialization
 * Each VPP worker thread should have its own context
 */
TlsJa4Context* vpp_worker_init() {
    TlsJa4Context* ctx = tls_ja4_init();
    if (!ctx) {
        printf("[VPP] ❌ Failed to initialize TLS JA4 context\n");
        return NULL;
    }

    // Set cache limits appropriate for VPP environment
    tls_ja4_set_cache_limits(ctx, 10000, 10*1024*1024, 30000); // 10k flows, 10MB, 30s timeout

    printf("[VPP] ✅ Worker context initialized\n");
    return ctx;
}

/**
 * VPP worker thread cleanup
 */
void vpp_worker_cleanup(TlsJa4Context* ctx) {
    if (ctx) {
        tls_ja4_cleanup(ctx);
        printf("[VPP] ✅ Worker context cleaned up\n");
    }
}

/**
 * Periodic cache maintenance (called from VPP timer)
 */
void vpp_periodic_maintenance(TlsJa4Context* ctx, unsigned long current_time_ms) {
    if (ctx) {
        unsigned int cleaned = tls_ja4_cleanup_timeout_cache(ctx, current_time_ms);
        if (cleaned > 0) {
            printf("[VPP] 🧹 Periodic cleanup - Removed %u timed-out flows\n", cleaned);
        }

        // Optional: Get cache statistics for monitoring
        uint32_t active_flows = 0;
        uint32_t total_bytes = 0;
        tls_ja4_get_cache_stats(ctx, &active_flows, &total_bytes);

        printf("[VPP] 📊 Cache stats - Active: %u flows, Total: %u bytes\n",
               active_flows, total_bytes);
    }
}

/**
 * Example VPP plugin integration
 */
void vpp_plugin_example() {
    printf("\n=== VPP Integration Example ===\n");

    // Initialize worker context (one per VPP worker thread)
    TlsJa4Context* worker_ctx = vpp_worker_init();
    if (!worker_ctx) {
        return;
    }

    // Simulate packet processing loop
    printf("[VPP] 🔄 Starting packet processing simulation...\n");

    // Example: Process multiple packets
    for (int i = 0; i < 5; i++) {
        printf("\n[VPP] 📦 Processing packet %d\n", i + 1);

        // In real VPP, this would be actual packet data from the network
        // For this example, we'll use dummy data
        unsigned char dummy_packet[100] = {0};
        unsigned int dummy_len = sizeof(dummy_packet);

        vpp_process_packet(worker_ctx, dummy_packet, dummy_len, 0);
    }

    // Periodic maintenance
    printf("\n[VPP] ⏰ Running periodic maintenance...\n");
    vpp_periodic_maintenance(worker_ctx, 60000); // 60 seconds

    // Cleanup
    vpp_worker_cleanup(worker_ctx);

    printf("\n[VPP] ✅ Integration example completed\n");
}

/**
 * Multi-threaded VPP example
 */
void vpp_multithread_example() {
    printf("\n=== VPP Multi-threaded Example ===\n");

    // In VPP, each worker thread has its own context
    const int NUM_WORKERS = 4;
    TlsJa4Context* worker_contexts[NUM_WORKERS];

    // Initialize worker contexts
    for (int i = 0; i < NUM_WORKERS; i++) {
        worker_contexts[i] = vpp_worker_init();
        printf("[VPP] Worker %d context: %p\n", i, (void*)worker_contexts[i]);
    }

    // Simulate packet processing across workers
    printf("\n[VPP] 🔄 Simulating multi-threaded packet processing...\n");

    // Each worker processes packets independently
    for (int worker_id = 0; worker_id < NUM_WORKERS; worker_id++) {
        printf("[VPP Worker %d] Processing packets...\n", worker_id);

        // Process some packets
        for (int pkt = 0; pkt < 3; pkt++) {
            unsigned char dummy_packet[100] = {0};
            vpp_process_packet(worker_contexts[worker_id], dummy_packet, sizeof(dummy_packet), 0);
        }
    }

    // Cleanup all worker contexts
    for (int i = 0; i < NUM_WORKERS; i++) {
        vpp_worker_cleanup(worker_contexts[i]);
    }

    printf("\n[VPP] ✅ Multi-threaded example completed\n");
}

int main() {
    printf("=== TLS JA4 VPP Integration Demonstration ===\n");

    // Test basic integration
    vpp_plugin_example();

    // Test multi-threaded scenario
    vpp_multithread_example();

    printf("\n=== VPP Integration Test Complete ===\n");
    return 0;
}