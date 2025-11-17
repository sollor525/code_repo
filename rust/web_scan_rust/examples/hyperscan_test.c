/* Simple test to verify Hyperscan integration */

#include <stdio.h>
#include <stdlib.h>
#include "../include/web_scan_rust.h"

int main() {
    printf("=== Hyperscan Integration Test ===\n\n");

    // Initialize the engine with Hyperscan
    printf("1. Initializing engine with Hyperscan...\n");
    if (web_scan_rust_init_with_hyperscan(1) != 0) {
        fprintf(stderr, "Failed to initialize engine: %s\n", web_scan_rust_get_last_error());
        return 1;
    }
    printf("   Engine initialized successfully\n");

    // Check if Hyperscan is enabled
    printf("2. Checking Hyperscan status...\n");
    printf("   Hyperscan enabled: %s\n", web_scan_rust_is_hyperscan_enabled() ? "Yes" : "No");

    if (!web_scan_rust_is_hyperscan_enabled()) {
        printf("   WARNING: Hyperscan is not enabled!\n");
        printf("   This might be because no rules were loaded.\n");
    }

    // Try to load rules first
    printf("3. Loading test rules...\n");
    FILE *rules_file = fopen("/tmp/hyperscan_test.rules", "w");
    if (rules_file) {
        fprintf(rules_file, "alert http any any -> any any (msg:\"Test admin\"; content:\"/admin/\"; sid:1001;)\n");
        fprintf(rules_file, "alert http any any -> any any (msg:\"Test SQL\"; content:\"union select\"; sid:1002;)\n");
        fclose(rules_file);

        int result = web_scan_rust_load_rules("/tmp/hyperscan_test.rules");
        if (result == 0) {
            printf("   Failed to load rules: %s\n", web_scan_rust_get_last_error());
        } else {
            printf("   Loaded %d rules\n", result);
        }
    }

    // Check Hyperscan status again
    printf("4. Checking Hyperscan status after loading rules...\n");
    printf("   Hyperscan enabled: %s\n", web_scan_rust_is_hyperscan_enabled() ? "Yes" : "No");

    // Test a simple payload
    printf("5. Testing payload with admin path...\n");
    const char *payload = "GET /admin/login.php HTTP/1.1\r\nHost: test.com\r\n\r\n";

    web_scan_result_t result;
    if (web_scan_rust_process_payload((const uint8_t *)payload, strlen(payload), &result) == 0) {
        printf("   Matched: %s\n", result.is_matched ? "Yes" : "No");
        printf("   Rule ID: %u\n", result.rule_id);
        printf("   Action: %u\n", result.action);
    } else {
        printf("   Processing failed: %s\n", web_scan_rust_get_last_error());
    }

    // Cleanup
    printf("6. Cleaning up...\n");
    web_scan_rust_cleanup();
    remove("/tmp/hyperscan_test.rules");

    printf("\nTest completed!\n");
    return 0;
}