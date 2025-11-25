/* 简化的Web Scan Detection - Rust Implementation
 * 手动定义的C兼容头文件，避免cbindgen问题
 */

#ifndef SIMPLE_WEB_SCAN_RUST_H
#define SIMPLE_WEB_SCAN_RUST_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// 枚举类型定义
typedef enum {
    web_scan_action_t_None = 0,
    web_scan_action_t_Alert = 1,
    web_scan_action_t_Drop = 2,
    web_scan_action_t_Reset = 3,
} web_scan_action_t;

// 统计结构体定义
typedef struct {
    uint64_t packets_processed;
    uint64_t packets_matched;
    uint64_t total_processing_time;
    uint64_t avg_processing_time;
    uint64_t max_processing_time;
    uint64_t min_processing_time;
    uint32_t rules_loaded;
    uint32_t rules_active;
} web_scan_stats_t;

// 结果结构体定义
typedef struct {
    bool is_matched;
    uint32_t rule_id;
    web_scan_action_t action;
    uint32_t content_length;
    uint8_t confidence;
    uint8_t protocol;        // 简化为uint8_t
    uint8_t direction;       // 简化为uint8_t
    uint16_t status_code;    // 简化为uint16_t，0表示无状态码
} web_scan_result_t;

// FFI函数声明
extern int web_scan_rust_init(void);
extern int web_scan_rust_load_rules(const char* path);
extern int web_scan_rust_process_payload(const unsigned char* payload, uint32_t len, web_scan_result_t* result);
extern int web_scan_rust_process_payload_with_session(uint64_t session_id, const unsigned char* payload, uint32_t len, int is_final, int reset_on_request_end, web_scan_result_t* result);
extern int web_scan_rust_get_stats(web_scan_stats_t* stats);
extern const char* web_scan_rust_get_last_error(void);
extern int web_scan_rust_is_hyperscan_enabled(void);

#endif // SIMPLE_WEB_SCAN_RUST_H