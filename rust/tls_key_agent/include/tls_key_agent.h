/**
 * @file tls_key_agent.h
 * @brief TLS Key Agent C API 头文件
 * @author sollor525@hotmail.com
 * @version 0.1.0
 * @date 2023-11-04
 */

#ifndef TLS_KEY_AGENT_H
#define TLS_KEY_AGENT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief FFI操作结果枚举
 */
typedef enum {
    TLS_AGENT_SUCCESS = 0,          ///< 成功
    TLS_AGENT_ERROR = -1,           ///< 一般错误
    TLS_AGENT_INVALID_PARAM = -2,   ///< 无效参数
    TLS_AGENT_NOT_INITIALIZED = -3, ///< 未初始化
    TLS_AGENT_ALREADY_INITIALIZED = -4, ///< 已初始化
    TLS_AGENT_BUFFER_TOO_SMALL = -5 ///< 缓冲区太小
} tls_agent_result_t;

/**
 * @brief 初始化TLS Key Agent
 *
 * @param config_path 配置文件路径
 * @return tls_agent_result_t 操作结果
 */
tls_agent_result_t tls_key_agent_init(const char* config_path);

/**
 * @brief 清理TLS Key Agent
 *
 * @return tls_agent_result_t 操作结果
 */
tls_agent_result_t tls_key_agent_cleanup(void);

/**
 * @brief 启动TLS Key Agent
 *
 * @return tls_agent_result_t 操作结果
 */
tls_agent_result_t tls_key_agent_start(void);

/**
 * @brief 停止TLS Key Agent
 *
 * @return tls_agent_result_t 操作结果
 */
tls_agent_result_t tls_key_agent_stop(void);

/**
 * @brief 处理Client Random
 *
 * @param ssl_ptr SSL对象指针
 * @param client_random Client Random数据
 * @param len 数据长度 (应为32字节)
 * @return tls_agent_result_t 操作结果
 */
tls_agent_result_t tls_key_agent_on_client_random(
    void* ssl_ptr,
    const uint8_t* client_random,
    size_t len
);

/**
 * @brief 处理Master Secret
 *
 * @param ssl_ptr SSL对象指针
 * @param master_secret Master Secret数据
 * @param len 数据长度 (应为48字节)
 * @return tls_agent_result_t 操作结果
 */
tls_agent_result_t tls_key_agent_on_master_secret(
    void* ssl_ptr,
    const uint8_t* master_secret,
    size_t len
);

/**
 * @brief 处理连接信息
 *
 * @param ssl_ptr SSL对象指针
 * @param src_ip 源IP地址字符串
 * @param src_port 源端口
 * @param dst_ip 目标IP地址字符串
 * @param dst_port 目标端口
 * @param protocol 协议字符串 ("TCP" 或 "UDP")
 * @return tls_agent_result_t 操作结果
 */
tls_agent_result_t tls_key_agent_on_connection_info(
    void* ssl_ptr,
    const char* src_ip,
    uint16_t src_port,
    const char* dst_ip,
    uint16_t dst_port,
    const char* protocol
);

/**
 * @brief 获取Agent运行状态
 *
 * @return int 1-运行中, 0-未运行
 */
int tls_key_agent_is_running(void);

/**
 * @brief 获取版本信息
 *
 * @return const char* 版本字符串指针
 */
const char* tls_key_agent_get_version(void);

/**
 * @brief 释放版本字符串内存
 *
 * @param version_ptr 版本字符串指针
 */
void tls_key_agent_free_version(const char* version_ptr);

/**
 * @brief TLS会话信息结构体
 */
typedef struct {
    char session_id[256];           ///< 会话ID
    uint8_t client_random[32];      ///< Client Random (32字节)
    uint8_t master_secret[48];      ///< Master Secret (48字节)
    char src_ip[46];                ///< 源IP地址 (支持IPv6)
    uint16_t src_port;              ///< 源端口
    char dst_ip[46];                ///< 目标IP地址 (支持IPv6)
    uint16_t dst_port;              ///< 目标端口
    char protocol[8];               ///< 协议类型 ("TCP" 或 "UDP")
    uint32_t pid;                   ///< 进程ID
    char process_name[256];         ///< 进程名
    char command_line[1024];        ///< 命令行
    uint64_t timestamp;             ///< 时间戳
} tls_agent_session_info_t;

/**
 * @brief 会话回调函数类型
 *
 * @param session_info 会话信息
 * @param user_data 用户数据
 */
typedef void (*tls_agent_session_callback_t)(
    const tls_agent_session_info_t* session_info,
    void* user_data
);

/**
 * @brief 设置会话回调函数
 *
 * @param callback 回调函数指针
 * @param user_data 用户数据
 * @return tls_agent_result_t 操作结果
 */
tls_agent_result_t tls_key_agent_set_session_callback(
    tls_agent_session_callback_t callback,
    void* user_data
);

/**
 * @brief 统计信息结构体
 */
typedef struct {
    uint64_t total_sessions;        ///< 总会话数
    uint64_t active_sessions;       ///< 活跃会话数
    uint64_t captured_sessions;     ///< 已捕获会话数
    uint64_t filtered_sessions;     ///< 被过滤的会话数
    uint64_t bytes_sent;            ///< 发送字节数
    uint64_t bytes_received;        ///< 接收字节数
    uint64_t errors;                ///< 错误计数
    double uptime_seconds;          ///< 运行时间(秒)
} tls_agent_stats_t;

/**
 * @brief 获取统计信息
 *
 * @param stats 统计信息结构体指针
 * @return tls_agent_result_t 操作结果
 */
tls_agent_result_t tls_key_agent_get_stats(
    tls_agent_stats_t* stats
);

/**
 * @brief 日志级别枚举
 */
typedef enum {
    TLS_AGENT_LOG_ERROR = 0,        ///< 错误
    TLS_AGENT_LOG_WARN = 1,         ///< 警告
    TLS_AGENT_LOG_INFO = 2,         ///< 信息
    TLS_AGENT_LOG_DEBUG = 3         ///< 调试
} tls_agent_log_level_t;

/**
 * @brief 设置日志级别
 *
 * @param level 日志级别
 * @return tls_agent_result_t 操作结果
 */
tls_agent_result_t tls_key_agent_set_log_level(
    tls_agent_log_level_t level
);

/**
 * @brief 日志回调函数类型
 *
 * @param level 日志级别
 * @param message 日志消息
 * @param user_data 用户数据
 */
typedef void (*tls_agent_log_callback_t)(
    tls_agent_log_level_t level,
    const char* message,
    void* user_data
);

/**
 * @brief 设置日志回调函数
 *
 * @param callback 回调函数指针
 * @param user_data 用户数据
 * @return tls_agent_result_t 操作结果
 */
tls_agent_result_t tls_key_agent_set_log_callback(
    tls_agent_log_callback_t callback,
    void* user_data
);

#ifdef __cplusplus
}
#endif

#endif /* TLS_KEY_AGENT_H */