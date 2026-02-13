/**
 * @file multi_ssl_hook.c
 * @brief 多SSL库支持的eBPF Hook程序
 * @author sollor525@hotmail.com
 * @version 2.0.0 - eBPF内核级SSL Hook
 * @date 2023-12-01
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "multi_ssl_hook.h"

// SSL库类型枚举
enum ssl_library_type {
    SSL_LIB_OPENSSL = 1,
    SSL_LIB_GNUTLS = 2,
    SSL_LIB_NSS = 3,
    SSL_LIB_BORINGSSL = 4,
    SSL_LIB_LIBRESSL = 5,
    SSL_LIB_UNKNOWN = 0
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

// 内核配置映射
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ssl_library_config);
    __uint(max_entries, 10);
} ssl_library_configs SEC(".maps");

// 连接映射 - 跟踪SSL连接状态
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct connection_key);
    __type(value, struct ssl_connection_info);
    __uint(max_entries, 10000);
} ssl_connections SEC(".maps");

// 事件输出映射
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct multi_ssl_hook_event));
} ssl_events SEC(".maps");

// 统计映射
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 100);
} ssl_stats SEC(".maps");

// 库检测缓冲区
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, char[256]);
    __uint(max_entries, 1);
} lib_detection_buffer SEC(".maps");

// 辅助函数：获取进程名
static __always_inline void get_process_name(char *name, int size) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return;
    }

    bpf_probe_read_kernel_str(name, size, BPF_CORE_READ(task, comm));
}

// 辅助函数：检测SSL库类型
static __always_inline __u32 detect_ssl_library(void *ssl_ptr) {
    // 通过特征结构检测不同SSL库
    char buffer[256];
    int lib_detection_key = 0;

    char *detection_buf = bpf_map_lookup_elem(&lib_detection_buffer, &lib_detection_key);
    if (!detection_buf) {
        return SSL_LIB_UNKNOWN;
    }

    // 检测OpenSSL特征
    // OpenSSL 1.1.x 和 3.x 的特征偏移
    if (bpf_probe_read_user(buffer, 8, ssl_ptr + 0x8) == 0) {
        // OpenSSL SSL对象通常有特定的魔术数字
        if (buffer[0] == 0x23 && buffer[1] == 0x00) { // 简化检测
            return SSL_LIB_OPENSSL;
        }
    }

    // 检测GnuTLS特征
    // GnuTLS session_t结构特征
    if (bpf_probe_read_user(buffer, 4, ssl_ptr + 0x10) == 0) {
        if (buffer[0] == 0x47 && buffer[1] == 0x4E &&
            buffer[2] == 0x55 && buffer[3] == 0x54) { // "GNUT"
            return SSL_LIB_GNUTLS;
        }
    }

    // 检测NSS特征
    // NSS SSL socket特征
    if (bpf_probe_read_user(buffer, 8, ssl_ptr) == 0) {
        if (buffer[4] == 0x4E && buffer[5] == 0x53 &&
            buffer[6] == 0x53 && buffer[7] == 0x53) { // "NSSS"
            return SSL_LIB_NSS;
        }
    }

    // 检测BoringSSL特征
    if (bpf_probe_read_user(buffer, 8, ssl_ptr + 0x20) == 0) {
        if (buffer[0] == 0x42 && buffer[1] == 0x6F &&
            buffer[2] == 0x72 && buffer[3] == 0x69) { // "Bori"
            return SSL_LIB_BORINGSSL;
        }
    }

    return SSL_LIB_UNKNOWN;
}

// 辅助函数：根据库类型提取密钥材料
static __always_inline int extract_keys_by_library(
    __u32 library_type,
    void *ssl_ptr,
    struct multi_ssl_hook_event *event
) {
    struct ssl_library_config *config;
    __u32 config_key = library_type;

    config = bpf_map_lookup_elem(&ssl_library_configs, &config_key);
    if (!config) {
        return 0; // 未找到配置
    }

    if (!config->is_enabled) {
        return 0; // 库未启用
    }

    event->library_type = library_type;

    switch (library_type) {
        case SSL_LIB_OPENSSL:
            return extract_openssl_keys(config, ssl_ptr, event);
        case SSL_LIB_GNUTLS:
            return extract_gnutls_keys(config, ssl_ptr, event);
        case SSL_LIB_NSS:
            return extract_nss_keys(config, ssl_ptr, event);
        case SSL_LIB_BORINGSSL:
            return extract_boringssl_keys(config, ssl_ptr, event);
        default:
            return 0;
    }
}

// OpenSSL密钥提取
static __always_inline int extract_openssl_keys(
    struct ssl_library_config *config,
    void *ssl_ptr,
    struct multi_ssl_hook_event *event
) {
    // 提取SSL版本信息
    void *session_ptr;
    if (bpf_probe_read_user(&session_ptr, sizeof(session_ptr), ssl_ptr + config->offset_session_id) != 0) {
        return 0;
    }

    if (!session_ptr) {
        return 0;
    }

    // 提取Client Random
    if (bpf_probe_read_user(event->client_random, sizeof(event->client_random),
                          session_ptr + config->offset_client_random) != 0) {
        return 0;
    }

    // 提取Master Secret
    if (bpf_probe_read_user(event->master_secret, sizeof(event->master_secret),
                          session_ptr + config->offset_master_secret) != 0) {
        // Master Secret可能还未生成，这是正常的
    }

    // 提取Session ID
    if (bpf_probe_read_user(event->session_id, sizeof(event->session_id),
                          session_ptr + config->offset_session_id) != 0) {
        // Session ID可能不存在
    }

    // 提取握手状态和密码套件
    __u32 handshake_state;
    if (bpf_probe_read_user(&handshake_state, sizeof(handshake_state),
                          ssl_ptr + 0x40) == 0) { // 估算偏移
        event->handshake_state = handshake_state;
    }

    __u16 cipher_suite;
    if (bpf_probe_read_user(&cipher_suite, sizeof(cipher_suite),
                          ssl_ptr + 0x44) == 0) { // 估算偏移
        event->cipher_suite = cipher_suite;
    }

    event->keys_extracted = 1;
    event->ssl_version = config->version_major << 8 | config->version_minor;

    return 1;
}

// GnuTLS密钥提取
static __always_inline int extract_gnutls_keys(
    struct ssl_library_config *config,
    void *session_ptr,
    struct multi_ssl_hook_event *event
) {
    // GnuTLS使用不同的结构布局
    struct gnutls_session_int {
        __u32 security_parameters;
        __u32 connection_state;
        __u8 client_random[32];
        __u8 master_secret[48];
        __u8 session_id[32];
    };

    struct gnutls_session_int gnutls_session;
    if (bpf_probe_read_user(&gnutls_session, sizeof(gnutls_session), session_ptr) != 0) {
        return 0;
    }

    __builtin_memcpy(event->client_random, gnutls_session.client_random, 32);
    __builtin_memcpy(event->master_secret, gnutls_session.master_secret, 48);
    __builtin_memcpy(event->session_id, gnutls_session.session_id, 32);

    event->handshake_state = gnutls_session.connection_state;
    event->ssl_version = config->version_major << 8 | config->version_minor;
    event->keys_extracted = 1;

    return 1;
}

// NSS密钥提取
static __always_inline int extract_nss_keys(
    struct ssl_library_config *config,
    void *ssl_socket_ptr,
    struct multi_ssl_hook_event *event
) {
    // NSS SSL socket结构
    struct nss_ssl_socket {
        __u32 state;
        __u32 version;
        __u8 client_random[32];
        __u8 master_secret[48];
        __u8 session_id[32];
        __u16 cipher_suite;
    };

    struct nss_ssl_socket nss_ssl;
    if (bpf_probe_read_user(&nss_ssl, sizeof(nss_ssl), ssl_socket_ptr) != 0) {
        return 0;
    }

    __builtin_memcpy(event->client_random, nss_ssl.client_random, 32);
    __builtin_memcpy(event->master_secret, nss_ssl.master_secret, 48);
    __builtin_memcpy(event->session_id, nss_ssl.session_id, 32);

    event->handshake_state = nss_ssl.state;
    event->cipher_suite = nss_ssl.cipher_suite;
    event->ssl_version = nss_ssl.version;
    event->keys_extracted = 1;

    return 1;
}

// BoringSSL密钥提取
static __always_inline int extract_boringssl_keys(
    struct ssl_library_config *config,
    void *ssl_ptr,
    struct multi_ssl_hook_event *event
) {
    // BoringSSL结构与OpenSSL相似，但有不同的偏移
    void *session_ptr;
    if (bpf_probe_read_user(&session_ptr, sizeof(session_ptr), ssl_ptr + 0x20) != 0) {
        return 0;
    }

    if (!session_ptr) {
        return 0;
    }

    // BoringSSL的不同偏移量
    if (bpf_probe_read_user(event->client_random, sizeof(event->client_random),
                          session_ptr + 0x30) != 0) {
        return 0;
    }

    if (bpf_probe_read_user(event->master_secret, sizeof(event->master_secret),
                          session_ptr + 0x60) != 0) {
        // Master Secret可能还未生成
    }

    event->ssl_version = 0x0301; // TLS 1.0+
    event->handshake_state = 1; // 握手完成
    event->keys_extracted = 1;

    return 1;
}

// 通用SSL Hook函数
SEC("uprobe/multi_ssl_handshake")
int multi_ssl_handshake(struct pt_regs *ctx) {
    void *ssl_ptr = (void *)PT_REGS_PARM1(ctx);
    if (!ssl_ptr) {
        return 0;
    }

    // 检测SSL库类型
    __u32 library_type = detect_ssl_library(ssl_ptr);
    if (library_type == SSL_LIB_UNKNOWN) {
        return 0; // 跳过未知库
    }

    // 获取连接信息
    struct multi_ssl_hook_event event = {};
    struct connection_key conn_key = {};

    // 填充基础事件信息
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid();
    event.timestamp = bpf_ktime_get_ns();
    event.keys_extracted = 0;

    // 获取进程名
    get_process_name(event.process_name, sizeof(event.process_name));

    // 获取socket信息
    if (get_socket_info(ctx, &conn_key, &event.sock_info) != 0) {
        return 0;
    }

    // 根据库类型提取密钥材料
    int keys_extracted = extract_keys_by_library(library_type, ssl_ptr, &event);
    if (!keys_extracted) {
        return 0;
    }

    // 发送事件到用户空间
    bpf_perf_event_output(ctx, &ssl_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    // 更新统计
    update_stats(library_type, 1);

    return 0;
}

// SSL写入Hook
SEC("uprobe/multi_ssl_write")
int multi_ssl_write(struct pt_regs *ctx) {
    void *ssl_ptr = (void *)PT_REGS_PARM1(ctx);
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    size_t len = (size_t)PT_REGS_PARM3(ctx);

    if (!ssl_ptr || !buf || len == 0) {
        return 0;
    }

    // 检测SSL库类型
    __u32 library_type = detect_ssl_library(ssl_ptr);
    if (library_type == SSL_LIB_UNKNOWN) {
        return 0;
    }

    // 更新写入统计
    update_stats(library_type + 10, len); // 库类型+10表示写操作

    return 0;
}

// SSL读取Hook
SEC("uprobe/multi_ssl_read")
int multi_ssl_read(struct pt_regs *ctx) {
    void *ssl_ptr = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t len = (size_t)PT_REGS_PARM3(ctx);

    if (!ssl_ptr || !buf || len == 0) {
        return 0;
    }

    // 检测SSL库类型
    __u32 library_type = detect_ssl_library(ssl_ptr);
    if (library_type == SSL_LIB_UNKNOWN) {
        return 0;
    }

    // 更新读取统计
    update_stats(library_type + 20, len); // 库类型+20表示读操作

    return 0;
}

// 更新统计信息
static __always_inline void update_stats(__u32 stat_key, __u64 value) {
    __u64 *count = bpf_map_lookup_elem(&ssl_stats, &stat_key);
    if (count) {
        __sync_fetch_and_add(count, value);
    }
}

// 初始化配置映射的函数
SEC("syscall/enter")
int multi_ssl_config_init(struct pt_regs *ctx) {
    // 这个函数用于初始化SSL库配置
    // 实际配置将在用户空间设置

    __u32 openssl_key = SSL_LIB_OPENSSL;
    struct ssl_library_config openssl_config = {
        .library_type = SSL_LIB_OPENSSL,
        .version_major = 3,
        .version_minor = 0,
        .offset_client_random = 0x20,
        .offset_master_secret = 0x40,
        .offset_session_id = 0x60,
        .offset_cipher_suite = 0x80,
        .is_enabled = 1,
    };
    bpf_map_update_elem(&ssl_library_configs, &openssl_key, &openssl_config, BPF_ANY);

    __u32 gnutls_key = SSL_LIB_GNUTLS;
    struct ssl_library_config gnutls_config = {
        .library_type = SSL_LIB_GNUTLS,
        .version_major = 3,
        .version_minor = 7,
        .offset_client_random = 0x10,
        .offset_master_secret = 0x30,
        .offset_session_id = 0x50,
        .offset_cipher_suite = 0x70,
        .is_enabled = 1,
    };
    bpf_map_update_elem(&ssl_library_configs, &gnutls_key, &gnutls_config, BPF_ANY);

    __u32 nss_key = SSL_LIB_NSS;
    struct ssl_library_config nss_config = {
        .library_type = SSL_LIB_NSS,
        .version_major = 3,
        .version_minor = 0,
        .offset_client_random = 0x15,
        .offset_master_secret = 0x35,
        .offset_session_id = 0x55,
        .offset_cipher_suite = 0x75,
        .is_enabled = 1,
    };
    bpf_map_update_elem(&ssl_library_configs, &nss_key, &nss_config, BPF_ANY);

    __u32 boringssl_key = SSL_LIB_BORINGSSL;
    struct ssl_library_config boringssl_config = {
        .library_type = SSL_LIB_BORINGSSL,
        .version_major = 1,
        .version_minor = 1,
        .offset_client_random = 0x30,
        .offset_master_secret = 0x60,
        .offset_session_id = 0x90,
        .offset_cipher_suite = 0xA0,
        .is_enabled = 1,
    };
    bpf_map_update_elem(&ssl_library_configs, &boringssl_key, &boringssl_config, BPF_ANY);

    return 0;
}

// 许可证信息
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 版本信息
__u32 VERSION SEC("version") = 1;