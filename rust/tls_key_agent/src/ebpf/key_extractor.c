/**
 * @file key_extractor.c
 * @brief eBPF密钥提取器 - 专门负责从SSL结构体中提取Client Random和Master Secret
 * @author sollor525@hotmail.com
 * @version 2.0.0 - eBPF内核级SSL Hook
 * @date 2023-12-01
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/string.h>
#include <bpf/bpf_core_read.h>

#define CLIENT_RANDOM_LEN 32
#define MASTER_SECRET_LEN 48
#define SESSION_ID_LEN 32
#define MAX_KEY_EVENTS 1024
#define EXTRACTION_TIMEOUT_NS 10000000000ULL  // 10秒

/**
 * 提取的密钥信息结构体
 */
struct extracted_key_material {
    __u8 client_random[CLIENT_RANDOM_LEN];
    __u8 master_secret[MASTER_SECRET_LEN];
    __u8 session_id[SESSION_ID_LEN];
    __u64 timestamp;
    __u8 has_client_random;
    __u8 has_master_secret;
    __u8 has_session_id;
    __u8 ssl_version;
    __u16 cipher_suite;
    __u16 padding;
};

/**
 * SSL密钥事件结构体（发送到用户空间）
 */
struct ssl_key_extraction_event {
    __u64 connection_id;
    __u32 pid;
    __u32 fd;
    struct extracted_key_material key_material;
    char process_name[16];
    __u8 extraction_success;
    __u8 padding[7];
};

/**
 * 密钥提取状态跟踪
 */
struct extraction_state {
    __u64 connection_id;
    __u64 start_time;
    __u8 client_random_extracted;
    __u8 master_secret_extracted;
    __u8 extraction_attempts;
    __u8 padding[5];
};

/**
 * 提取的密钥事件映射 - 发送到用户空间
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, struct ssl_key_extraction_event);
    __uint(max_entries, MAX_KEY_EVENTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} extracted_keys SEC(".maps");

/**
 * 密钥提取状态映射
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct extraction_state);
    __uint(max_entries, MAX_KEY_EVENTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} extraction_states SEC(".maps");

/**
 * SSL结构体偏移量配置（需要根据具体版本调整）
 */
struct ssl_offsets {
    __u64 ssl_session_offset;
    __u64 client_random_offset;
    __u64 master_secret_offset;
    __u64 session_id_offset;
    __u64 cipher_suite_offset;
    __u64 ssl_version_offset;
};

/**
 * SSL偏移量配置映射
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct ssl_offsets);
    __uint(max_entries, 10);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ssl_version_offsets SEC(".maps");

/**
 * 辅助函数声明
 */
static __always_inline int is_valid_client_random(const __u8 *random);
static __always_inline int is_valid_master_secret(const __u8 *secret);
static __always_inline int is_valid_session_id(const __u8 *session_id);
static __always_inline int extract_client_random_openssl_1_1_1(void *ssl_ptr, __u8 *client_random);
static __always_inline int extract_client_random_openssl_3_0(void *ssl_ptr, __u8 *client_random);
static __always_inline int extract_master_secret_openssl_1_1_1(void *ssl_ptr, __u8 *master_secret);
static __always_inline int extract_master_secret_openssl_3_0(void *ssl_ptr, __u8 *master_secret);
static __always_inline int extract_session_id_openssl(void *ssl_ptr, __u8 *session_id);
static __always_inline int get_ssl_version(void *ssl_ptr);
static __always_inline struct ssl_offsets *get_ssl_offsets(__u32 version);
static __always_inline void send_key_event(const struct ssl_key_extraction_event *event);
static __always_inline int update_extraction_state(__u64 connection_id, __u8 extraction_type);

/**
 * 验证Client Random的有效性
 */
static __always_inline int is_valid_client_random(const __u8 *random) {
    __u32 zero_count = 0;
    __u32 same_count = 1;
    __u8 first_byte = random[0];

    // 检查是否全为0
    for (int i = 0; i < CLIENT_RANDOM_LEN; i++) {
        if (random[i] == 0) {
            zero_count++;
        }
    }
    if (zero_count == CLIENT_RANDOM_LEN) {
        return 0;
    }

    // 检查是否所有字节都相同
    for (int i = 1; i < CLIENT_RANDOM_LEN; i++) {
        if (random[i] == first_byte) {
            same_count++;
        }
    }
    if (same_count == CLIENT_RANDOM_LEN) {
        return 0;
    }

    // 简单的熵值检查：至少应该有8个不同的字节值
    __u32 unique_bytes = 0;
    for (int i = 0; i < CLIENT_RANDOM_LEN; i++) {
        __u8 found = 0;
        for (int j = 0; j < i; j++) {
            if (random[i] == random[j]) {
                found = 1;
                break;
            }
        }
        if (!found) {
            unique_bytes++;
        }
        if (unique_bytes >= 8) {
            break;
        }
    }

    return unique_bytes >= 8;
}

/**
 * 验证Master Secret的有效性
 */
static __always_inline int is_valid_master_secret(const __u8 *secret) {
    __u32 zero_count = 0;

    // 检查是否全为0
    for (int i = 0; i < MASTER_SECRET_LEN; i++) {
        if (secret[i] == 0) {
            zero_count++;
        }
    }
    if (zero_count > MASTER_SECRET_LEN / 4) {  // 允许部分0，但不能太多
        return 0;
    }

    // Master Secret通常有一定的模式（PRF输出）
    // 检查前几个字节不应该是简单的重复模式
    for (int i = 0; i < 8; i++) {
        if (i > 0 && secret[i] == secret[i-1]) {
            return 0;  // 简单检查连续相同字节
        }
    }

    return 1;
}

/**
 * 验证Session ID的有效性
 */
static __always_inline int is_valid_session_id(const __u8 *session_id) {
    __u32 zero_count = 0;

    // 检查是否全为0
    for (int i = 0; i < SESSION_ID_LEN; i++) {
        if (session_id[i] == 0) {
            zero_count++;
        }
    }

    // Session ID可以全为0（表示没有Session ID），但如果是非空，应该有足够的熵
    if (zero_count != SESSION_ID_LEN) {
        __u32 unique_bytes = 0;
        for (int i = 0; i < SESSION_ID_LEN; i++) {
            __u8 found = 0;
            for (int j = 0; j < i; j++) {
                if (session_id[i] == session_id[j]) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                unique_bytes++;
            }
            if (unique_bytes >= 4) {
                break;
            }
        }
        return unique_bytes >= 4;
    }

    return 1;  // 全0也是有效的（表示没有Session ID）
}

/**
 * 从OpenSSL 1.1.1结构体中提取Client Random
 */
static __always_inline int extract_client_random_openssl_1_1_1(void *ssl_ptr, __u8 *client_random) {
    void *session_ptr;
    void *client_random_ptr;

    // SSL结构体 -> SSL_SESSION指针
    if (bpf_probe_read(&session_ptr, sizeof(void *), ssl_ptr + 0x20)) {  // SSL_SESSION offset
        return -1;
    }

    if (!session_ptr) {
        return -1;
    }

    // SSL_SESSION -> s3 -> client_random
    void *s3_ptr;
    if (bpf_probe_read(&s3_ptr, sizeof(void *), session_ptr + 0x30)) {
        return -1;
    }

    if (!s3_ptr) {
        return -1;
    }

    if (bpf_probe_read(&client_random_ptr, sizeof(void *), s3_ptr + 0x60)) {
        return -1;
    }

    if (!client_random_ptr) {
        return -1;
    }

    // 读取32字节的Client Random
    if (bpf_probe_read(client_random, CLIENT_RANDOM_LEN, client_random_ptr)) {
        return -1;
    }

    return is_valid_client_random(client_random) ? 0 : -1;
}

/**
 * 从OpenSSL 3.0结构体中提取Client Random
 */
static __always_inline int extract_client_random_openssl_3_0(void *ssl_ptr, __u8 *client_random) {
    void *session_ptr;
    void *client_random_ptr;

    // OpenSSL 3.0有不同的结构体布局
    if (bpf_probe_read(&session_ptr, sizeof(void *), ssl_ptr + 0x28)) {  // 调整后的偏移量
        return -1;
    }

    if (!session_ptr) {
        return -1;
    }

    if (bpf_probe_read(&client_random_ptr, sizeof(void *), session_ptr + 0x40)) {
        return -1;
    }

    if (!client_random_ptr) {
        return -1;
    }

    if (bpf_probe_read(client_random, CLIENT_RANDOM_LEN, client_random_ptr)) {
        return -1;
    }

    return is_valid_client_random(client_random) ? 0 : -1;
}

/**
 * 从OpenSSL 1.1.1结构体中提取Master Secret
 */
static __always_inline int extract_master_secret_openssl_1_1_1(void *ssl_ptr, __u8 *master_secret) {
    void *session_ptr;
    void *master_secret_ptr;

    // SSL结构体 -> SSL_SESSION指针
    if (bpf_probe_read(&session_ptr, sizeof(void *), ssl_ptr + 0x20)) {
        return -1;
    }

    if (!session_ptr) {
        return -1;
    }

    // SSL_SESSION -> master_secret
    if (bpf_probe_read(&master_secret_ptr, sizeof(void *), session_ptr + 0x80)) {
        return -1;
    }

    if (!master_secret_ptr) {
        return -1;
    }

    // 读取48字节的Master Secret
    if (bpf_probe_read(master_secret, MASTER_SECRET_LEN, master_secret_ptr)) {
        return -1;
    }

    return is_valid_master_secret(master_secret) ? 0 : -1;
}

/**
 * 从OpenSSL 3.0结构体中提取Master Secret
 */
static __always_inline int extract_master_secret_openssl_3_0(void *ssl_ptr, __u8 *master_secret) {
    void *session_ptr;
    void *master_secret_ptr;

    // OpenSSL 3.0有不同的结构体布局
    if (bpf_probe_read(&session_ptr, sizeof(void *), ssl_ptr + 0x28)) {
        return -1;
    }

    if (!session_ptr) {
        return -1;
    }

    if (bpf_probe_read(&master_secret_ptr, sizeof(void *), session_ptr + 0x90)) {
        return -1;
    }

    if (!master_secret_ptr) {
        return -1;
    }

    if (bpf_probe_read(master_secret, MASTER_SECRET_LEN, master_secret_ptr)) {
        return -1;
    }

    return is_valid_master_secret(master_secret) ? 0 : -1;
}

/**
 * 从SSL结构体中提取Session ID
 */
static __always_inline int extract_session_id_openssl(void *ssl_ptr, __u8 *session_id) {
    void *session_ptr;
    void *session_id_ptr;

    // SSL结构体 -> SSL_SESSION指针
    if (bpf_probe_read(&session_ptr, sizeof(void *), ssl_ptr + 0x20)) {
        return -1;
    }

    if (!session_ptr) {
        return -1;
    }

    // SSL_SESSION -> session_id
    if (bpf_probe_read(&session_id_ptr, sizeof(void *), session_ptr + 0x10)) {
        return -1;
    }

    if (!session_id_ptr) {
        // 清零session_id，表示没有Session ID
        __builtin_memset(session_id, 0, SESSION_ID_LEN);
        return 0;
    }

    // 读取Session ID
    if (bpf_probe_read(session_id, SESSION_ID_LEN, session_id_ptr)) {
        return -1;
    }

    return is_valid_session_id(session_id) ? 0 : -1;
}

/**
 * 获取SSL版本
 */
static __always_inline int get_ssl_version(void *ssl_ptr) {
    __u32 version;

    if (bpf_probe_read(&version, sizeof(__u32), ssl_ptr + 0x04)) {
        return -1;
    }

    return version;
}

/**
 * 根据SSL版本获取对应的偏移量配置
 */
static __always_inline struct ssl_offsets *get_ssl_offsets(__u32 version) {
    return bpf_map_lookup_elem(&ssl_version_offsets, &version);
}

/**
 * 发送密钥提取事件到用户空间
 */
static __always_inline void send_key_event(const struct ssl_key_extraction_event *event) {
    bpf_perf_event_output(ctx, &extracted_keys, BPF_F_CURRENT_CPU, event, sizeof(*event));
}

/**
 * 更新提取状态
 */
static __always_inline int update_extraction_state(__u64 connection_id, __u8 extraction_type) {
    struct extraction_state *state;
    struct extraction_state new_state = {};
    __u64 current_time = bpf_ktime_get_ns();

    state = bpf_map_lookup_elem(&extraction_states, &connection_id);
    if (!state) {
        // 创建新的提取状态
        new_state.connection_id = connection_id;
        new_state.start_time = current_time;
        new_state.extraction_attempts = 1;

        if (extraction_type == 1) {
            new_state.client_random_extracted = 1;
        } else if (extraction_type == 2) {
            new_state.master_secret_extracted = 1;
        }

        bpf_map_update_elem(&extraction_states, &connection_id, &new_state, BPF_ANY);
    } else {
        // 更新现有状态
        state->last_activity_time = current_time;  // 注意：这里需要添加last_activity_time字段
        state->extraction_attempts++;

        if (extraction_type == 1) {
            state->client_random_extracted = 1;
        } else if (extraction_type == 2) {
            state->master_secret_extracted = 1;
        }

        bpf_map_update_elem(&extraction_states, &connection_id, state, BPF_EXIST);
    }

    return 0;
}

/**
 * 通用密钥提取函数
 */
SEC("uprobe/SSL_extract_key_material")
int probe_ssl_extract_key_material(struct pt_regs *ctx) {
    void *ssl_ptr = (void *)PT_REGS_PARM1(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 fd = (__u32)PT_REGS_PARM2(ctx);  // 假设FD作为第二个参数传入
    __u64 connection_id = ((__u64)pid << 32) | (__u64)fd;

    struct ssl_key_extraction_event event = {};
    struct extracted_key_material *key_material = &event.key_material;
    int ssl_version;
    int extraction_success = 0;

    // 获取SSL版本
    ssl_version = get_ssl_version(ssl_ptr);
    if (ssl_version < 0) {
        return 0;
    }

    // 填充事件基本信息
    event.connection_id = connection_id;
    event.pid = pid;
    event.fd = fd;
    bpf_get_current_comm(&event.process_name, sizeof(event.process_name));
    key_material->timestamp = bpf_ktime_get_ns();
    key_material->ssl_version = ssl_version;

    // 尝试提取Client Random
    if (ssl_version == 0x0303 || ssl_version == 0x0304) {  // TLS 1.2/1.3
        if (extract_client_random_openssl_1_1_1(ssl_ptr, key_material->client_random) == 0) {
            key_material->has_client_random = 1;
            extraction_success = 1;
            update_extraction_state(connection_id, 1);
        }
    } else if (ssl_version >= 0x0304) {  // OpenSSL 3.0+
        if (extract_client_random_openssl_3_0(ssl_ptr, key_material->client_random) == 0) {
            key_material->has_client_random = 1;
            extraction_success = 1;
            update_extraction_state(connection_id, 1);
        }
    }

    // 尝试提取Master Secret
    if (ssl_version == 0x0303 || ssl_version == 0x0304) {  // TLS 1.2/1.3
        if (extract_master_secret_openssl_1_1_1(ssl_ptr, key_material->master_secret) == 0) {
            key_material->has_master_secret = 1;
            extraction_success = 1;
            update_extraction_state(connection_id, 2);
        }
    } else if (ssl_version >= 0x0304) {  // OpenSSL 3.0+
        if (extract_master_secret_openssl_3_0(ssl_ptr, key_material->master_secret) == 0) {
            key_material->has_master_secret = 1;
            extraction_success = 1;
            update_extraction_state(connection_id, 2);
        }
    }

    // 尝试提取Session ID
    if (extract_session_id_openssl(ssl_ptr, key_material->session_id) == 0) {
        key_material->has_session_id = 1;
    }

    // 设置提取成功标志
    event.extraction_success = extraction_success;

    // 如果成功提取到任何密钥信息，发送事件
    if (extraction_success) {
        send_key_event(&event);
    }

    return 0;
}

/**
 * 清理过期的提取状态
 */
SEC("perf_event")
int cleanup_extraction_states(struct bpf_perf_event_data *ctx) {
    __u64 current_time = bpf_ktime_get_ns();
    __u64 expiration_time = current_time - EXTRACTION_TIMEOUT_NS;

    // 简化实现：实际需要遍历映射并清理过期条目
    // 这里提供框架

    return 0;
}

char _license[] SEC("license") = "GPL";