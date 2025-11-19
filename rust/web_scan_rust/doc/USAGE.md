# 使用示例和最佳实践

本文档提供 Web Scan Rust 库的详细使用示例和最佳实践指南。

## 版本信息

- **当前版本**: v0.1.0
- **功能状态**: 所有核心功能已完成并经过测试验证
- **测试覆盖**: 65/65 测试通过 (100%)
- **性能**: 生产级别性能，支持高并发场景

## 目录

- [快速开始](#快速开始)
- [基本使用](#基本使用)
- [会话管理](#会话管理)
- [分段包处理](#分段包处理)
- [Fast Pattern优化](#fast-pattern优化)
- [多内容规则](#多内容规则)
- [HTTP位置验证](#http位置验证)
- [规则语法示例](#规则语法示例)
- [错误处理](#错误处理)
- [性能优化](#性能优化)
- [最佳实践](#最佳实践)
- [常见使用场景](#常见使用场景)

## 快速开始

### 最简单的示例

```c
#include <stdio.h>
#include <string.h>
#include "web_scan_rust.h"

int main() {
    // 1. 初始化引擎
    if (web_scan_rust_init_with_hyperscan() != 0) {
        fprintf(stderr, "Init failed: %s\n", web_scan_rust_get_last_error());
        return 1;
    }
    
    // 2. 加载规则
    if (web_scan_rust_load_rules("rules.rules") != 0) {
        fprintf(stderr, "Load rules failed: %s\n", web_scan_rust_get_last_error());
        return 1;
    }
    
    // 3. 处理数据包
    const char *payload = "GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\n\r\n";
    web_scan_result_t result;
    
    if (web_scan_rust_process_payload(
            (const uint8_t *)payload,
            strlen(payload),
            &result) == 0) {
        
        if (result.is_matched) {
            printf("Threat detected! Rule ID: %u, Action: %d\n",
                   result.rule_id, result.action);
        }
    }
    
    // 4. 清理
    web_scan_rust_cleanup();
    return 0;
}
```

## 基本使用

### 处理单个数据包

```c
#include "web_scan_rust.h"

void process_single_packet(const uint8_t *data, size_t len) {
    web_scan_result_t result;
    
    int ret = web_scan_rust_process_payload(data, len, &result);
    if (ret != 0) {
        fprintf(stderr, "Processing failed: %s\n", 
                web_scan_rust_get_last_error());
        return;
    }
    
    if (result.is_matched) {
        // 处理匹配结果
        switch (result.action) {
            case WEB_SCAN_ACTION_ALERT:
                printf("ALERT: Rule %u matched\n", result.rule_id);
                break;
            case WEB_SCAN_ACTION_DROP:
                printf("DROP: Rule %u matched\n", result.rule_id);
                break;
            case WEB_SCAN_ACTION_RESET:
                printf("RESET: Rule %u matched\n", result.rule_id);
                break;
            default:
                break;
        }
    }
}
```

### 批量处理数据包

```c
void process_multiple_packets(const uint8_t **packets, 
                              const size_t *lengths, 
                              size_t count) {
    web_scan_result_t result;
    size_t matched_count = 0;
    
    for (size_t i = 0; i < count; i++) {
        if (web_scan_rust_process_payload(
                packets[i], lengths[i], &result) == 0) {
            
            if (result.is_matched) {
                matched_count++;
                printf("Packet %zu: Matched rule %u\n", i, result.rule_id);
            }
        }
    }
    
    printf("Total matched: %zu/%zu\n", matched_count, count);
}
```

### 获取统计信息

```c
void print_statistics(void) {
    web_scan_stats_t stats;
    
    if (web_scan_rust_get_stats(&stats) == 0) {
        printf("=== Statistics ===\n");
        printf("Packets Processed: %lu\n", stats.packets_processed);
        printf("Packets Matched: %lu\n", stats.packets_matched);
        printf("Packets Dropped: %lu\n", stats.packets_dropped);
        printf("Packets Reset: %lu\n", stats.packets_reset);
        printf("Packets Alerted: %lu\n", stats.packets_alerted);
        printf("Avg Processing Time: %lu ns\n", 
               stats.average_processing_time_ns);
        printf("Peak Processing Time: %lu ns\n", 
               stats.peak_processing_time_ns);
    }
}
```

## 会话管理

### 跨数据包匹配

会话管理允许跨多个数据包进行匹配，这对于检测分布在多个数据包中的攻击模式非常有用。

```c
#include "web_scan_rust.h"

void process_session_packets(uint64_t session_id,
                              const uint8_t **packets,
                              const size_t *lengths,
                              size_t count,
                              bool is_final) {
    web_scan_result_t result;
    
    for (size_t i = 0; i < count; i++) {
        bool packet_is_final = (i == count - 1) && is_final;
        
        int ret = web_scan_rust_process_payload_with_session(
            session_id,
            packets[i],
            lengths[i],
            packet_is_final ? 1 : 0,  // is_final
            0,  // reset_on_request_end
            &result
        );
        
        if (ret == 0 && result.is_matched) {
            printf("Session %lu, Packet %zu: Matched rule %u\n",
                   session_id, i, result.rule_id);
            // 可以在这里决定是否继续处理后续数据包
            break;
        }
    }
    
    // 会话结束时关闭
    if (is_final) {
        web_scan_rust_close_session(session_id);
    }
}
```

### HTTP 请求/响应流处理

对于 HTTP 请求/响应流，可以在请求结束时重置流以准备下一个请求：

```c
void process_http_request(uint64_t session_id, 
                          const uint8_t *request_data, 
                          size_t request_len) {
    web_scan_result_t result;
    
    // 处理请求
    web_scan_rust_process_payload_with_session(
        session_id,
        request_data,
        request_len,
        0,  // is_final = 0 (可能还有响应)
        1,  // reset_on_request_end = 1 (请求结束时重置)
        &result
    );
    
    if (result.is_matched) {
        printf("Request matched rule %u\n", result.rule_id);
    }
    
    // 注意：流已自动重置，可以继续处理响应
}

void process_http_response(uint64_t session_id,
                           const uint8_t *response_data,
                           size_t response_len,
                           bool is_final) {
    web_scan_result_t result;
    
    web_scan_rust_process_payload_with_session(
        session_id,
        response_data,
        response_len,
        is_final ? 1 : 0,  // is_final
        0,  // reset_on_request_end = 0
        &result
    );
    
    if (is_final) {
        web_scan_rust_close_session(session_id);
    }
}
```

### 会话生命周期管理

```c
typedef struct {
    uint64_t session_id;
    time_t created_at;
    time_t last_used;
    bool active;
} session_info_t;

#define MAX_SESSIONS 10000
session_info_t sessions[MAX_SESSIONS];
size_t session_count = 0;

uint64_t create_session(void) {
    static uint64_t next_id = 1;
    uint64_t session_id = next_id++;
    
    // 记录会话信息
    if (session_count < MAX_SESSIONS) {
        sessions[session_count].session_id = session_id;
        sessions[session_count].created_at = time(NULL);
        sessions[session_count].last_used = time(NULL);
        sessions[session_count].active = true;
        session_count++;
    }
    
    return session_id;
}

void cleanup_inactive_sessions(time_t timeout) {
    time_t now = time(NULL);
    
    for (size_t i = 0; i < session_count; i++) {
        if (sessions[i].active && 
            (now - sessions[i].last_used) > timeout) {
            
            // 关闭超时会话
            web_scan_rust_close_session(sessions[i].session_id);
            sessions[i].active = false;
        }
    }
}
```

## 分段包处理

### 基本分段包处理

```c
void process_segmented_packet(uint64_t session_id,
                              const uint8_t *segment,
                              size_t segment_len,
                              bool is_final) {
    web_scan_result_t result;
    
    // 引擎内部自动处理流缓冲区，无需外部管理
    int ret = web_scan_rust_process_payload_with_session(
        session_id,
        segment,
        segment_len,
        is_final ? 1 : 0,      // is_final
        0,                      // reset_on_request_end = 0
        &result
    );
    
    if (ret == 0) {
        // 处理完成
        if (result.is_matched) {
            printf("Segmented packet matched rule %u\n", result.rule_id);
        }
        
        if (is_final) {
            web_scan_rust_close_session(session_id);
        }
    } else {
        // 错误
        fprintf(stderr, "Error: %s\n", web_scan_rust_get_last_error());
    }
}
```

### 处理多个分段

```c
void process_multiple_segments(uint64_t session_id,
                                const uint8_t **segments,
                                const size_t *segment_lens,
                                size_t segment_count) {
    // 引擎内部自动管理流缓冲区，无需外部管理
    
    for (size_t i = 0; i < segment_count; i++) {
        bool is_final = (i == segment_count - 1);
        
        web_scan_result_t result;
        
        int ret = web_scan_rust_process_payload_with_session(
            session_id,
            segments[i],
            segment_lens[i],
            is_final ? 1 : 0,  // is_final
            0,                 // reset_on_request_end = 0
            &result
        );
        
        if (ret == 0) {
            if (result.is_matched) {
                printf("Segment %zu matched rule %u\n", i, result.rule_id);
            }
        }
    }
    
    web_scan_rust_close_session(session_id);
}
```

## 多内容规则

### 处理多内容规则

多内容规则要求多个模式在不同位置匹配。使用会话管理可以跨数据包匹配：

```c
// 规则示例：
// alert http any any -> any any (msg:"Admin and password";
//   content:"admin"; http.uri; content:"password"; http.request_body; sid:1001;)

void process_multi_content_rule(uint64_t session_id) {
    // 第一个数据包：包含 URI 中的 "admin"
    const char *packet1 = 
        "GET /admin/login HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: 20\r\n"
        "\r\n";
    
    web_scan_result_t result1;
    web_scan_rust_process_payload_with_session(
        session_id,
        (const uint8_t *)packet1,
        strlen(packet1),
        0, 0, &result1
    );
    
    // 第一个包可能不匹配（因为 password 还没出现）
    
    // 第二个数据包：包含 body 中的 "password"
    const char *packet2 = "password=secret";
    
    web_scan_result_t result2;
    web_scan_rust_process_payload_with_session(
        session_id,
        (const uint8_t *)packet2,
        strlen(packet2),
        1, 0, &result2  // is_final = 1
    );
    
    // 现在应该匹配了
    if (result2.is_matched && result2.rule_id == 1001) {
        printf("Multi-content rule matched!\n");
    }
    
    web_scan_rust_close_session(session_id);
}
```

## 错误处理

### 统一的错误处理宏

```c
#include <stdlib.h>

#define CHECK_API(ret, func_name) \
    do { \
        if ((ret) != 0) { \
            const char *err = web_scan_rust_get_last_error(); \
            fprintf(stderr, "%s failed: %s\n", func_name, err ? err : "unknown"); \
            exit(1); \
        } \
    } while(0)

int main() {
    int ret;
    
    ret = web_scan_rust_init_with_hyperscan();
    CHECK_API(ret, "web_scan_rust_init_with_hyperscan");
    
    ret = web_scan_rust_load_rules("rules.rules");
    CHECK_API(ret, "web_scan_rust_load_rules");
    
    // ...
    return 0;
}
```

### 错误恢复

```c
int safe_process_payload(const uint8_t *data, size_t len, 
                        web_scan_result_t *result) {
    int retry_count = 0;
    const int max_retries = 3;
    
    while (retry_count < max_retries) {
        int ret = web_scan_rust_process_payload(data, len, result);
        
        if (ret == 0) {
            return 0;  // 成功
        }
        
        // 检查是否是致命错误
        const char *error = web_scan_rust_get_last_error();
        if (error && strstr(error, "Engine not initialized")) {
            // 尝试重新初始化
            if (web_scan_rust_init_with_hyperscan() == 0) {
                retry_count++;
                continue;
            }
        }
        
        // 其他错误，返回
        return ret;
    }
    
    return -1;  // 重试失败
}
```

## 性能优化

### 1. 重用结果结构体

```c
// 好的做法：重用结构体
web_scan_result_t result;
for (int i = 0; i < count; i++) {
    web_scan_rust_process_payload(packets[i], lens[i], &result);
    // 处理结果
}

// 避免：每次都创建新结构体
for (int i = 0; i < count; i++) {
    web_scan_result_t result;  // 每次都创建
    web_scan_rust_process_payload(packets[i], lens[i], &result);
}
```

### 2. 批量处理

```c
// 批量处理多个数据包
void batch_process(const uint8_t **packets, 
                   const size_t *lengths, 
                   size_t count) {
    web_scan_result_t *results = malloc(count * sizeof(web_scan_result_t));
    
    // 并行处理（如果支持）
    #pragma omp parallel for
    for (size_t i = 0; i < count; i++) {
        web_scan_rust_process_payload(
            packets[i], lengths[i], &results[i]);
    }
    
    // 处理结果
    for (size_t i = 0; i < count; i++) {
        if (results[i].is_matched) {
            handle_match(&results[i]);
        }
    }
    
    free(results);
}
```

### 3. 会话池管理

```c
typedef struct {
    uint64_t session_id;
    bool in_use;
    time_t last_used;
} session_pool_t;

#define POOL_SIZE 1000
session_pool_t session_pool[POOL_SIZE];

uint64_t acquire_session(void) {
    for (int i = 0; i < POOL_SIZE; i++) {
        if (!session_pool[i].in_use) {
            session_pool[i].in_use = true;
            session_pool[i].last_used = time(NULL);
            return session_pool[i].session_id;
        }
    }
    return 0;  // 池已满
}

void release_session(uint64_t session_id) {
    for (int i = 0; i < POOL_SIZE; i++) {
        if (session_pool[i].session_id == session_id) {
            web_scan_rust_reset_session(session_id);
            session_pool[i].in_use = false;
            break;
        }
    }
}
```

## 最佳实践

### 1. 初始化检查

```c
bool is_engine_ready(void) {
    return web_scan_rust_is_hyperscan_enabled() > 0 &&
           web_scan_rust_get_rule_count() > 0 &&
           web_scan_rust_is_enabled() > 0;
}

int main() {
    if (web_scan_rust_init_with_hyperscan() != 0) {
        return 1;
    }
    
    if (web_scan_rust_load_rules("rules.rules") != 0) {
        return 1;
    }
    
    if (!is_engine_ready()) {
        fprintf(stderr, "Engine not ready\n");
        return 1;
    }
    
    // 使用引擎...
    return 0;
}
```

### 2. 资源清理

```c
void cleanup_resources(void) {
    // 关闭所有会话
    web_scan_rust_close_all_sessions();
    
    // 清理引擎
    web_scan_rust_cleanup();
}

// 使用 atexit 确保清理
int main() {
    atexit(cleanup_resources);
    
    // 程序代码...
    return 0;
}
```

### 3. 统计信息监控

```c
void monitor_performance(void) {
    web_scan_stats_t stats;
    if (web_scan_rust_get_stats(&stats) == 0) {
        // 计算匹配率
        double match_rate = 0.0;
        if (stats.packets_processed > 0) {
            match_rate = (double)stats.packets_matched / 
                        stats.packets_processed * 100.0;
        }
        
        printf("Match rate: %.2f%%\n", match_rate);
        
        // 检查性能
        if (stats.average_processing_time_ns > 1000000) {  // > 1ms
            printf("Warning: High processing time\n");
        }
    }
}
```

### 4. 规则热重载

```c
void reload_rules_if_needed(const char *rules_path, time_t *last_reload) {
    struct stat st;
    if (stat(rules_path, &st) == 0) {
        if (st.st_mtime > *last_reload) {
            printf("Reloading rules...\n");
            if (web_scan_rust_reload_rules(rules_path) > 0) {
                *last_reload = st.st_mtime;
                printf("Rules reloaded successfully\n");
            }
        }
    }
}
```

## 总结

使用 Web Scan Rust 库的关键要点：

1. **正确初始化**：确保引擎和规则都已正确加载
2. **使用会话管理**：对于需要跨数据包匹配的场景
3. **及时清理**：关闭不再使用的会话，程序退出前清理资源
4. **错误处理**：检查所有 API 调用的返回值
5. **性能优化**：重用结构体、批量处理、使用会话池
6. **监控统计**：定期检查统计信息，监控性能

更多详细信息请参考 [API 文档](API.md) 和 [集成指南](INTEGRATION.md)。

