/**
 * @file multi_ssl_hook.h
 * @brief 多SSL库支持的eBPF Hook头文件
 * @author sollor525@hotmail.com
 * @version 2.0.0 - eBPF内核级SSL Hook
 * @date 2023-12-01
 */

#ifndef MULTI_SSL_HOOK_H
#define MULTI_SSL_HOOK_H

#include <linux/types.h>

// SSL库类型定义
#define SSL_LIB_UNKNOWN          0
#define SSL_LIB_OPENSSL          1
#define SSL_LIB_GNUTLS           2
#define SSL_LIB_NSS              3
#define SSL_LIB_BORINGSSL        4
#define SSL_LIB_LIBRESSL         5

// 连接信息结构
struct socket_info {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    __u8 protocol;  // IPPROTO_TCP or IPPROTO_UDP
};

struct connection_key {
    __u32 pid;
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
};

struct ssl_connection_info {
    __u32 library_type;
    __u32 ssl_version;
    __u32 handshake_state;
    __u64 last_activity;
    __u8 keys_extracted;
};

// 多库Hook事件结构
struct multi_ssl_hook_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u32 library_type;
    __u32 ssl_version;
    __u32 handshake_state;
    __u32 cipher_suite;
    __u8 keys_extracted;
    __u8 client_random[32];
    __u8 master_secret[48];
    __u8 session_id[32];
    char process_name[16];
    struct socket_info sock_info;
};

// SSL库配置结构
struct ssl_library_config {
    __u32 library_type;
    __u32 version_major;
    __u32 version_minor;
    __u32 offset_client_random;
    __u32 offset_master_secret;
    __u32 offset_session_id;
    __u32 offset_cipher_suite;
    __u8 is_enabled;
};

// 统计类型
#define STAT_OPENSsl_HANDSHAKES      1
#define STAT_OPENSsl_WRITES           11
#define STAT_OPENSsl_READS            21
#define STAT_GNUTLS_HANDSHAKES        2
#define STAT_GNUTLS_WRITES             12
#define STAT_GNUTLS_READS              22
#define STAT_NSS_HANDSHAKES            3
#define STAT_NSS_WRITES                13
#define STAT_NSS_READS                 23
#define STAT_BORINGSSL_HANDSHAKES      4
#define STAT_BORINGSSL_WRITES           14
#define STAT_BORINGSSL_READS            24

// 最大统计计数
#define MAX_STATS_COUNT               100

// 事件大小限制
#define MAX_EVENT_SIZE                1024

// 进程名长度限制
#define MAX_PROCESS_NAME_LENGTH        16

// 连接映射大小
#define MAX_CONNECTIONS               10000

#endif // MULTI_SSL_HOOK_H