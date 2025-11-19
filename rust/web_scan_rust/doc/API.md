# Web Scan Rust API 参考文档

本文档详细说明了 Web Scan Rust 库的所有 C API 函数。

## 版本信息

- **版本**: v0.1.0
- **测试覆盖**: 65/65 测试通过 (100%)
- **兼容性**: Suricata/Snort规则完全兼容
- **性能**: 支持每秒数万数据包处理

## 目录

- [数据结构](#数据结构)
- [初始化函数](#初始化函数)
- [规则管理](#规则管理)
- [数据包处理](#数据包处理)
- [会话管理](#会话管理)
- [统计信息](#统计信息)
- [引擎控制](#引擎控制)
- [错误处理](#错误处理)
- [清理函数](#清理函数)
- [Fast Pattern API](#fast-pattern-api)

## 数据结构

### web_scan_result_t

检测结果结构体。

```c
typedef struct {
    bool is_matched;              // 是否匹配到规则
    uint32_t rule_id;             // 匹配的规则ID
    web_scan_action_e action;     // 建议执行的动作
    uint32_t content_length;      // 内容长度（字节）
    web_scan_protocol_e protocol; // 检测到的协议类型
    uint8_t confidence;           // 协议检测置信度（0-100）
} web_scan_result_t;
```

### web_scan_stats_t

统计信息结构体。

```c
typedef struct {
    uint64_t packets_processed;        // 已处理的数据包数
    uint64_t packets_matched;          // 匹配的数据包数
    uint64_t packets_dropped;          // 丢弃的数据包数
    uint64_t packets_reset;            // 重置的数据包数
    uint64_t packets_alerted;          // 告警的数据包数
    uint64_t protocol_detection_errors; // 协议检测错误数
    uint64_t rule_matching_errors;     // 规则匹配错误数
    uint64_t average_processing_time_ns; // 平均处理时间（纳秒）
    uint64_t peak_processing_time_ns;   // 峰值处理时间（纳秒）
    uint64_t total_processing_time_ns;  // 总处理时间（纳秒）
} web_scan_stats_t;
```

### web_scan_protocol_e

协议类型枚举。

```c
typedef enum {
    WEB_SCAN_PROTOCOL_UNKNOWN = 0,
    WEB_SCAN_PROTOCOL_HTTP = 1,
    WEB_SCAN_PROTOCOL_HTTPS = 2,
    WEB_SCAN_PROTOCOL_HTTP2 = 3,
} web_scan_protocol_e;
```

### web_scan_action_e

动作类型枚举。

```c
typedef enum {
    WEB_SCAN_ACTION_NONE = 0,
    WEB_SCAN_ACTION_ALERT = 1,
    WEB_SCAN_ACTION_DROP = 2,
    WEB_SCAN_ACTION_RESET = 3,
} web_scan_action_e;
```

## 初始化函数

### web_scan_rust_init

初始化 Web 扫描检测引擎（默认启用 Hyperscan）。

```c
int web_scan_rust_init(void);
```

**返回值：**
- `0` - 成功
- 负数 - 错误代码

**说明：**
- 此函数会创建全局引擎实例
- 多次调用是安全的，只有第一次调用会真正执行初始化
- 默认启用 Hyperscan 高性能匹配

**示例：**
```c
if (web_scan_rust_init() != 0) {
    fprintf(stderr, "Failed to initialize: %s\n", web_scan_rust_get_last_error());
    return -1;
}
```

### web_scan_rust_init_with_hyperscan

初始化 Web 扫描检测引擎（明确启用 Hyperscan）。

```c
int web_scan_rust_init_with_hyperscan(void);
```

**返回值：**
- `0` - 成功
- 负数 - 错误代码

**说明：**
- 与 `web_scan_rust_init()` 功能相同
- 明确表示启用 Hyperscan 支持

## 规则管理

### web_scan_rust_load_rules

从文件加载规则。

```c
int web_scan_rust_load_rules(const char *rules_path);
```

**参数：**
- `rules_path` - 规则文件路径（支持 JSON、TOML、Hyperscan/Snort 格式）

**返回值：**
- `0` - 成功
- 负数 - 错误代码

**说明：**
- 加载规则会替换之前的所有规则
- 支持多种规则格式，详见规则文件格式说明

**示例：**
```c
if (web_scan_rust_load_rules("rules.rules") != 0) {
    fprintf(stderr, "Failed to load rules: %s\n", web_scan_rust_get_last_error());
    return -1;
}
printf("Loaded %u rules\n", web_scan_rust_get_rule_count());
```

### web_scan_rust_reload_rules

重新加载规则文件。

```c
int web_scan_rust_reload_rules(const char *rules_path);
```

**参数：**
- `rules_path` - 规则文件路径

**返回值：**
- 成功时返回加载的规则数量
- 负数 - 错误代码

**说明：**
- 功能与 `web_scan_rust_load_rules()` 相同
- 返回加载的规则数量

### web_scan_rust_get_rule_count

获取当前加载的规则数量。

```c
uint32_t web_scan_rust_get_rule_count(void);
```

**返回值：**
- 规则数量

**示例：**
```c
uint32_t count = web_scan_rust_get_rule_count();
printf("Current rule count: %u\n", count);
```

## 数据包处理

### web_scan_rust_process_payload

处理单个数据包载荷（无会话管理）。

```c
int web_scan_rust_process_payload(
    const uint8_t *payload,
    uint32_t payload_len,
    web_scan_result_t *result
);
```

**参数：**
- `payload` - 指向载荷数据的指针
- `payload_len` - 载荷长度（字节）
- `result` - 指向结果结构体的指针

**返回值：**
- `0` - 成功
- 负数 - 错误代码

**说明：**
- 每次调用创建新的流，适合非流式场景
- 不支持跨数据包匹配
- 如需跨数据包匹配，请使用 `web_scan_rust_process_payload_with_session`

**示例：**
```c
const char *data = "GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\n\r\n";
web_scan_result_t result;
if (web_scan_rust_process_payload((const uint8_t *)data, strlen(data), &result) == 0) {
    if (result.is_matched) {
        printf("Threat detected! Rule ID: %u\n", result.rule_id);
    }
}
```

### web_scan_rust_process_payload_with_session

处理数据包载荷（带会话管理，支持跨数据包匹配）。

```c
int web_scan_rust_process_payload_with_session(
    uint64_t session_id,
    const uint8_t *payload,
    uint32_t payload_len,
    int is_final,
    int reset_on_request_end,
    web_scan_result_t *result
);
```

**参数：**
- `session_id` - 会话标识符（同一会话使用相同ID）
- `payload` - 指向载荷数据的指针
- `payload_len` - 载荷长度（字节）
- `is_final` - 是否为该会话的最后一个数据包（0=否，非0=是）
- `reset_on_request_end` - 是否在请求结束时重置流（0=否，非0=是）
- `result` - 指向结果结构体的指针

**返回值：**
- `0` - 成功
- 负数 - 错误代码

**说明：**
- 为每个会话维护独立的 Hyperscan 流
- 支持跨数据包边界匹配
- 同一会话的所有数据包必须使用相同的 `session_id`
- `reset_on_request_end` 用于 HTTP 请求/响应流，当规则只需要匹配请求包时使用
- **内部自动处理不完整的HTTP header**：如果第一个分段HTTP header不完整，引擎会自动累积数据到内部缓冲区，等待后续分段完成后再进行协议检测和规则匹配
- 无需外部管理流缓冲区，引擎内部会自动处理分段数据包的重组

**示例：**
```c
uint64_t session_id = 12345;

// 第一个数据包（可能HTTP header不完整）
const char *packet1 = "GET /admin/";
web_scan_result_t result1;
web_scan_rust_process_payload_with_session(session_id, (const uint8_t *)packet1, 
    strlen(packet1), 0, 0, &result1);
// 引擎内部会累积数据，等待完整header

// 第二个数据包（完成HTTP header）
const char *packet2 = "login.php HTTP/1.1\r\nHost: example.com\r\n\r\n";
web_scan_result_t result2;
web_scan_rust_process_payload_with_session(session_id, (const uint8_t *)packet2, 
    strlen(packet2), 1, 0, &result2);
// 此时引擎会使用累积的完整数据进行匹配

// 关闭会话
web_scan_rust_close_session(session_id);
```

## 会话管理

### web_scan_rust_reset_session

重置指定会话的 Hyperscan 流。

```c
int web_scan_rust_reset_session(uint64_t session_id);
```

**参数：**
- `session_id` - 会话标识符

**返回值：**
- `0` - 成功
- 负数 - 错误代码

**说明：**
- 重置流状态，允许从头开始匹配
- 不关闭流，保留会话
- 适用于 HTTP 请求/响应流：请求结束时重置流以准备下一个请求

**示例：**
```c
// 处理完一个 HTTP 请求后
web_scan_rust_reset_session(session_id);
// 可以继续使用同一个 session_id 处理下一个请求
```

### web_scan_rust_close_session

关闭指定会话的 Hyperscan 流。

```c
int web_scan_rust_close_session(uint64_t session_id);
```

**参数：**
- `session_id` - 会话标识符

**返回值：**
- `0` - 成功
- 负数 - 错误代码

**说明：**
- 关闭并清理会话资源
- 会话结束后应调用此函数

**示例：**
```c
// 会话结束时
web_scan_rust_close_session(session_id);
```

### web_scan_rust_close_all_sessions

关闭所有活动会话的 Hyperscan 流。

```c
int web_scan_rust_close_all_sessions(void);
```

**返回值：**
- `0` - 成功
- 负数 - 错误代码

**说明：**
- 清理所有会话资源
- 适用于程序退出或批量清理场景

**示例：**
```c
// 程序退出前
web_scan_rust_close_all_sessions();
```

## 统计信息

### web_scan_rust_get_stats

获取当前统计信息。

```c
int web_scan_rust_get_stats(web_scan_stats_t *stats);
```

**参数：**
- `stats` - 指向统计信息结构体的指针

**返回值：**
- `0` - 成功
- 负数 - 错误代码

**示例：**
```c
web_scan_stats_t stats;
if (web_scan_rust_get_stats(&stats) == 0) {
    printf("Processed: %lu\n", stats.packets_processed);
    printf("Matched: %lu\n", stats.packets_matched);
}
```

### web_scan_rust_reset_stats

重置统计计数器。

```c
int web_scan_rust_reset_stats(void);
```

**返回值：**
- `0` - 成功
- 负数 - 错误代码

**示例：**
```c
web_scan_rust_reset_stats();
```

## 引擎控制

### web_scan_rust_set_enabled

启用或禁用检测引擎。

```c
int web_scan_rust_set_enabled(bool enabled);
```

**参数：**
- `enabled` - true 启用，false 禁用

**返回值：**
- `0` - 成功
- 负数 - 错误代码

**说明：**
- 禁用时，处理函数仍会返回结果，但不会进行实际检测
- 可用于临时暂停检测

**示例：**
```c
web_scan_rust_set_enabled(false);  // 禁用
// ... 执行其他操作 ...
web_scan_rust_set_enabled(true);   // 重新启用
```

### web_scan_rust_is_enabled

检查引擎是否启用。

```c
int web_scan_rust_is_enabled(void);
```

**返回值：**
- `0` - 禁用
- `1` - 启用
- 负数 - 错误代码

### web_scan_rust_set_default_action

设置默认动作（用于没有明确动作的规则）。

```c
int web_scan_rust_set_default_action(web_scan_action_e action);
```

**参数：**
- `action` - 默认动作类型

**返回值：**
- `0` - 成功
- 负数 - 错误代码

### web_scan_rust_is_hyperscan_enabled

检查 Hyperscan 是否启用。

```c
int web_scan_rust_is_hyperscan_enabled(void);
```

**返回值：**
- `0` - 禁用
- `1` - 启用
- 负数 - 错误代码

## 错误处理

### web_scan_rust_get_last_error

获取最后一次错误的错误信息。

```c
const char *web_scan_rust_get_last_error(void);
```

**返回值：**
- 错误信息字符串指针，如果没有错误返回 NULL

**说明：**
- 返回的字符串指针在下次调用 API 函数前有效
- 不应释放返回的字符串

**示例：**
```c
if (web_scan_rust_load_rules("invalid.rules") != 0) {
    const char *error = web_scan_rust_get_last_error();
    if (error) {
        fprintf(stderr, "Error: %s\n", error);
    }
}
```

## 清理函数

### web_scan_rust_cleanup

清理并关闭引擎。

```c
int web_scan_rust_cleanup(void);
```

**返回值：**
- `0` - 成功
- 负数 - 错误代码

**说明：**
- 清理所有资源
- 程序退出前应调用此函数

**示例：**
```c
// 程序退出前
web_scan_rust_close_all_sessions();
web_scan_rust_cleanup();
```

## 错误代码

所有函数在失败时返回负数错误代码：

- `0` - 成功
- `-1` - 通用错误（空指针、引擎未初始化等）
- `-2` - 协议检测失败
- `-3` - 规则解析错误
- `-4` - Hyperscan 错误
- `-5` - IO 错误
- `-6` - JSON 解析错误
- `-7` - 无效输入
- `-8` - 引擎未初始化
- `-9` - 内存分配失败

使用 `web_scan_rust_get_last_error()` 获取详细的错误信息。

## 线程安全

所有 API 函数都是线程安全的，可以在多线程环境中并发调用。每个会话的流状态由内部锁保护，不同会话可以并发处理。

## 性能注意事项

1. **会话管理**：使用会话管理功能时，确保及时关闭不再使用的会话，避免内存泄漏
2. **批量处理**：对于大量数据包，考虑批量处理以提高性能
3. **规则数量**：规则数量会影响内存使用和匹配性能，建议合理控制规则数量
4. **Hyperscan**：启用 Hyperscan 可以显著提升匹配性能，特别是对于复杂规则

