#include "src/simple_web_scan_rust.h"
#include <stdio.h>

int main() {
    printf("web_scan_result_t size: %zu\n", sizeof(web_scan_result_t));
    printf("web_scan_stats_t size: %zu\n", sizeof(web_scan_stats_t));
    return 0;
}
