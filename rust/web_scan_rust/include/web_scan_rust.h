/* Web Scan Detection - Rust Implementation
 * Auto-generated C bindings
 * DO NOT EDIT MANUALLY
 */

#ifndef WEB_SCAN_RUST_H
#define WEB_SCAN_RUST_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol types */
typedef enum {
    WEB_SCAN_PROTOCOL_UNKNOWN = 0,
    WEB_SCAN_PROTOCOL_HTTP = 1,
    WEB_SCAN_PROTOCOL_HTTPS = 2,
    WEB_SCAN_PROTOCOL_HTTP2 = 3,
} web_scan_protocol_e;

/* Action types */
typedef enum {
    WEB_SCAN_ACTION_NONE = 0,
    WEB_SCAN_ACTION_ALERT = 1,
    WEB_SCAN_ACTION_DROP = 2,
    WEB_SCAN_ACTION_RESET = 3,
} web_scan_action_e;

/* Detection result structure */
typedef struct {
    bool is_matched;
    uint32_t rule_id;
    web_scan_action_e action;
    uint32_t content_length;
    web_scan_protocol_e protocol;
    uint8_t confidence;
} web_scan_result_t;

/* Statistics structure */
typedef struct {
    uint64_t packets_processed;
    uint64_t packets_matched;
    uint64_t packets_dropped;
    uint64_t packets_reset;
    uint64_t packets_alerted;
    uint64_t protocol_detection_errors;
    uint64_t rule_matching_errors;
    uint64_t average_processing_time_ns;
    uint64_t peak_processing_time_ns;
    uint64_t total_processing_time_ns;
} web_scan_stats_t;

/* Core API functions */

/**
 * Initialize the web scan detection engine
 * @return 0 on success, negative error code on failure
 */
int web_scan_rust_init(void);

/**
 * Initialize the web scan detection engine with Hyperscan support
 * Hyperscan acceleration is enabled by default.
 * @return 0 on success, negative error code on failure
 */
int web_scan_rust_init_with_hyperscan(void);

/**
 * Load rules from file
 * @param rules_path Path to the rules file
 * @return 0 on success, negative error code on failure
 */
int web_scan_rust_load_rules(const char *rules_path);

/**
 * Process a packet payload
 * Note: This function creates a new stream for each call, suitable for non-streaming scenarios.
 * For cross-packet matching, use web_scan_rust_process_payload_with_session.
 * @param payload Pointer to payload data
 * @param payload_len Length of payload in bytes
 * @param result Pointer to result structure to fill
 * @return 0 on success, negative error code on failure
 */
int web_scan_rust_process_payload(const uint8_t *payload, uint32_t payload_len, web_scan_result_t *result);

/**
 * Process a packet payload with session management
 * This function maintains independent Hyperscan streams for each session, supporting cross-packet matching.
 * All packets of the same session must use the same session_id.
 * @param session_id Session identifier, use the same ID for all packets of the same session
 * @param payload Pointer to payload data
 * @param payload_len Length of payload in bytes
 * @param is_final Whether this is the last packet of the session (0=no, non-zero=yes)
 * @param reset_on_request_end Whether to reset the stream when request ends (0=no, non-zero=yes, for HTTP request/response streams)
 * @param result Pointer to result structure to fill
 * @return 0 on success, negative error code on failure
 */
int web_scan_rust_process_payload_with_session(uint64_t session_id, const uint8_t *payload, uint32_t payload_len, int is_final, int reset_on_request_end, web_scan_result_t *result);

/**
 * Get current statistics
 * @param stats Pointer to statistics structure to fill
 * @return 0 on success, negative error code on failure
 */
int web_scan_rust_get_stats(web_scan_stats_t *stats);

/**
 * Reset statistics counters
 * @return 0 on success, negative error code on failure
 */
int web_scan_rust_reset_stats(void);

/**
 * Enable or disable the detection engine
 * @param enabled true to enable, false to disable
 * @return 0 on success, negative error code on failure
 */
int web_scan_rust_set_enabled(bool enabled);

/**
 * Set default action for rules without explicit action
 * @param action Default action to use
 * @return 0 on success, negative error code on failure
 */
int web_scan_rust_set_default_action(web_scan_action_e action);

/**
 * Get current rule count
 * @return Number of loaded rules
 */
uint32_t web_scan_rust_get_rule_count(void);

/**
 * Check if Hyperscan is enabled
 * @return 0 if disabled, 1 if enabled, negative error code on failure
 */
int web_scan_rust_is_hyperscan_enabled(void);

/**
 * Reload rules from file
 * @param rules_path Path to the rules file
 * @return Number of loaded rules on success, negative error code on failure
 */
int web_scan_rust_reload_rules(const char *rules_path);

/**
 * Get last error message
 * @return Pointer to error string, or NULL if no error
 */
const char *web_scan_rust_get_last_error(void);

/**
 * Reset a specific session's Hyperscan stream
 * Reset the stream state to allow matching from the beginning again, without closing the stream.
 * This is useful for HTTP request/response streams: when an HTTP request ends,
 * you can reset the stream to prepare for the next request without closing and recreating it.
 * @param session_id Session identifier to reset
 * @return 0 on success, negative error code on failure
 */
int web_scan_rust_reset_session(uint64_t session_id);

/**
 * Close a specific session's Hyperscan stream
 * Call this function when a session ends to clean up resources.
 * @param session_id Session identifier to close
 * @return 0 on success, negative error code on failure
 */
int web_scan_rust_close_session(uint64_t session_id);

/**
 * Close all active sessions' Hyperscan streams
 * This function closes and cleans up all active session streams.
 * @return 0 on success, negative error code on failure
 */
int web_scan_rust_close_all_sessions(void);

/**
 * Cleanup and shutdown the engine
 * @return 0 on success, negative error code on failure
 */
int web_scan_rust_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* WEB_SCAN_RUST_H */