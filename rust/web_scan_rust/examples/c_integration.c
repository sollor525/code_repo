/* Example C integration with Rust web scan detection engine */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/web_scan_rust.h"

void print_result(const web_scan_result_t *result) {
    printf("Detection Result:\n");
    printf("  Matched: %s\n", result->is_matched ? "Yes" : "No");
    printf("  Rule ID: %u\n", result->rule_id);
    printf("  Action: %d\n", result->action);
    printf("  Protocol: %d\n", result->protocol);
    printf("  Confidence: %u%%\n", result->confidence);
    printf("  Content Length: %u bytes\n", result->content_length);
}

void print_stats(const web_scan_stats_t *stats) {
    printf("Statistics:\n");
    printf("  Packets Processed: %lu\n", stats->packets_processed);
    printf("  Packets Matched: %lu\n", stats->packets_matched);
    printf("  Packets Dropped: %lu\n", stats->packets_dropped);
    printf("  Packets Reset: %lu\n", stats->packets_reset);
    printf("  Packets Alerted: %lu\n", stats->packets_alerted);
    printf("  Avg Processing Time: %lu ns\n", stats->average_processing_time_ns);
    printf("  Peak Processing Time: %lu ns\n", stats->peak_processing_time_ns);
}

int main() {
    printf("=== Web Scan Rust Integration Example ===\n\n");

    // Initialize the engine with Hyperscan enabled
    printf("1. Initializing engine with Hyperscan...\n");
    if (web_scan_rust_init_with_hyperscan(1) != 0) {
        fprintf(stderr, "Failed to initialize engine: %s\n", web_scan_rust_get_last_error());
        return 1;
    }
    printf("   Engine initialized successfully\n");

    // Check if Hyperscan is enabled
    printf("   Hyperscan enabled: %s\n", web_scan_rust_is_hyperscan_enabled() ? "Yes" : "No");
    printf("\n");

    // Create a simple rules file for testing
    printf("2. Creating test rules...\n");
    FILE *rules_file = fopen("/tmp/test_rules.rules", "w");
    if (!rules_file) {
        fprintf(stderr, "Failed to create rules file\n");
        return 1;
    }
    
    fprintf(rules_file, "alert http any any -> any any (msg:\"Admin access\"; content:\"/admin/\"; sid:1001;)\n");
    fprintf(rules_file, "drop http any any -> any any (msg:\"SQL injection\"; content:\"union select\"; sid:1002;)\n");
    fprintf(rules_file, "alert http any any -> any any (msg:\"Login page\"; content:\"login.php\"; sid:1003;)\n");
    fclose(rules_file);

    // Load rules
    if (web_scan_rust_load_rules("/tmp/test_rules.rules") != 0) {
        fprintf(stderr, "Failed to load rules: %s\n", web_scan_rust_get_last_error());
        return 1;
    }
    printf("   Loaded %u rules\n\n", web_scan_rust_get_rule_count());

    // Test payloads
    const char *test_payloads[] = {
        "GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET /search?q=1' union select * from users HTTP/1.1\r\n\r\n",
        "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"test\":\"data\"}"
    };
    
    const char *test_names[] = {
        "Admin access (should match rule 1001)",
        "SQL injection (should match rule 1002)", 
        "Normal request (should not match)",
        "API request (should not match)"
    };

    // Process test payloads
    printf("3. Processing test payloads...\n");
    for (int i = 0; i < 4; i++) {
        printf("\n--- Test %d: %s ---\n", i + 1, test_names[i]);
        
        web_scan_result_t result;
        int ret = web_scan_rust_process_payload(
            (const uint8_t *)test_payloads[i],
            strlen(test_payloads[i]),
            &result
        );
        
        if (ret != 0) {
            fprintf(stderr, "Processing failed: %s\n", web_scan_rust_get_last_error());
            continue;
        }
        
        print_result(&result);
    }

    // Get and display statistics
    printf("\n4. Final statistics:\n");
    web_scan_stats_t stats;
    if (web_scan_rust_get_stats(&stats) == 0) {
        print_stats(&stats);
    }

    // Test engine control
    printf("\n5. Testing engine control...\n");
    printf("   Disabling engine...\n");
    web_scan_rust_set_enabled(false);
    
    web_scan_result_t result;
    web_scan_rust_process_payload(
        (const uint8_t *)test_payloads[0],
        strlen(test_payloads[0]),
        &result
    );
    printf("   Disabled engine result - Matched: %s\n", result.is_matched ? "Yes" : "No");
    
    printf("   Re-enabling engine...\n");
    web_scan_rust_set_enabled(true);

    // Cleanup
    printf("\n6. Cleaning up...\n");
    web_scan_rust_cleanup();
    remove("/tmp/test_rules.rules");
    
    printf("   Example completed successfully!\n");
    return 0;
}