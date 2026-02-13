/**
 * @file ssl_hook.c
 * @brief eBPF SSL Hook核心程序 - 通过Uprobe机制Hook SSL函数
 * @author sollor525@hotmail.com
 * @version 2.0.0 - eBPF内核级SSL Hook
 * @date 2023-12-01
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define MAX_PROCESS_NAME_LEN 16
#define CLIENT_RANDOM_LEN 32
#define MASTER_SECRET_LEN 48
#define MAX_CONNECTIONS 10240
#define MAX_EVENTS 1024

/**
 * SSL连接信息结构体
 */
struct ssl_connection_info {
    __u64 connection_id;        // 连接唯一标识
    __u32 pid;                  // 进程ID
    __u32 fd;                   // 文件描述符
    __u32 src_ip;               // 源IP地址
    __u32 dst_ip;               // 目的IP地址
    __u16 src_port;             // 源端口
    __u16 dst_port;             // 目的端口
    __u8 protocol;              // 协议类型 (TCP=6, UDP=17)
    __u8 ssl_version;           // SSL版本
    char process_name[MAX_PROCESS_NAME_LEN]; // 进程名称
};

/**
 * SSL密钥事件结构体
 */
struct ssl_key_event {
    struct ssl_connection_info conn_info;
    __u8 client_random[CLIENT_RANDOM_LEN];  // Client Random
    __u8 master_secret[MASTER_SECRET_LEN];  // Master Secret
    __u64 timestamp;                        // 时间戳
    __u8 has_client_random;                 // 是否包含Client Random
    __u8 has_master_secret;                 // 是否包含Master Secret
};

/**
 * SSL握手状态枚举
 */
enum ssl_handshake_state {
    SSL_HANDSHAKE_NONE = 0,
    SSL_HANDSHAKE_IN_PROGRESS,
    SSL_HANDSHAKE_COMPLETED,
};

/**
 * 连接状态跟踪结构体
 */
struct connection_state {
    struct ssl_connection_info conn_info;
    enum ssl_handshake_state handshake_state;
    __u64 last_activity_time;
    __u8 keys_extracted;  // 是否已提取密钥
};

/**
 * eBPF Maps定义
 */

// 连接信息映射 - key: connection_id, value: connection_state
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct connection_state);
    __uint(max_entries, MAX_CONNECTIONS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ssl_connections SEC(".maps");

// SSL密钥事件映射 - key: CPU ID, value: ssl_key_event
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, struct ssl_key_event);
    __uint(max_entries, MAX_EVENTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ssl_events SEC(".maps");

// 进程过滤配置映射 - key: pid, value: enable_flag
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} process_filter SEC(".maps");

// 源IP过滤配置映射 - key: ip_range_start, value: ip_range_end
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} source_ip_filter SEC(".maps");

/**
 * 辅助函数声明
 */
static __always_inline __u64 generate_connection_id(__u32 pid, __u32 fd);
static __always_inline int extract_fd_from_ssl(void *ssl_ptr);
static __always_inline int get_socket_info(__u32 fd, struct ssl_connection_info *conn_info);
static __always_inline int is_process_allowed(__u32 pid);
static __always_inline int is_source_ip_allowed(__u32 src_ip);
static __always_inline void send_key_event(const struct ssl_key_event *event);
static __always_inline int extract_client_random_from_ssl(void *ssl_ptr, __u8 *client_random);
static __always_inline int extract_master_secret_from_ssl(void *ssl_ptr, __u8 *master_secret);

/**
 * 生成连接唯一标识
 */
static __always_inline __u64 generate_connection_id(__u32 pid, __u32 fd) {
    // 使用PID和FD的组合作为连接ID
    return ((__u64)pid << 32) | (__u64)fd;
}

/**
 * 从SSL指针中提取文件描述符
 * 注意：这是一个简化的实现，实际需要根据具体的SSL库结构调整
 */
static __always_inline int extract_fd_from_ssl(void *ssl_ptr) {
    // 在真实实现中，需要通过SSL结构体内部指针找到对应的socket FD
    // 这里使用简化的方法，可能需要根据具体的OpenSSL版本调整
    void *rbio_ptr;
    int fd = -1;

    // 读取SSL结构的rbio指针
    if (bpf_probe_read(&rbio_ptr, sizeof(void *), ssl_ptr + SSL_RBIO_OFFSET)) {
        return -1;
    }

    // 从BIO结构中提取文件描述符
    if (bpf_probe_read(&fd, sizeof(int), rbio_ptr + BIO_FD_OFFSET)) {
        return -1;
    }

    return fd;
}

/**
 * 获取socket信息
 */
static __always_inline int get_socket_info(__u32 fd, struct ssl_connection_info *conn_info) {
    struct sockaddr_in6 addr;
    socklen_t addr_len = sizeof(addr);
    int ret;

    // 获取socket信息（需要在用户空间实现，这里是简化版本）
    // 实际实现可能需要通过kprobe或tracepoint获取网络信息
    ret = bpf_getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &addr, &addr_len);
    if (ret < 0) {
        return ret;
    }

    // 根据地址类型填充连接信息
    if (addr.sin6_family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
        conn_info->src_ip = bpf_ntohl(addr4->sin_addr.s_addr);
        conn_info->src_port = bpf_ntohs(addr4->sin_port);
        conn_info->dst_ip = 0; // 需要通过其他方式获取
        conn_info->dst_port = 0;
        conn_info->protocol = IPPROTO_TCP;
    } else if (addr.sin6_family == AF_INET6) {
        // IPv6支持（简化处理）
        conn_info->src_ip = 0;
        conn_info->src_port = bpf_ntohs(addr.sin6_port);
        conn_info->dst_ip = 0;
        conn_info->dst_port = 0;
        conn_info->protocol = IPPROTO_TCP;
    }

    return 0;
}

/**
 * 检查进程是否在允许列表中
 */
static __always_inline int is_process_allowed(__u32 pid) {
    __u8 *allowed = bpf_map_lookup_elem(&process_filter, &pid);

    // 如果没有配置过滤规则，默认允许所有进程
    if (!allowed) {
        return 1;
    }

    return *allowed;
}

/**
 * 检查源IP是否在允许列表中
 */
static __always_inline int is_source_ip_allowed(__u32 src_ip) {
    __u32 *ip_range_end;

    // 遍历源IP过滤规则
    for (int i = 0; i < 256; i++) {
        __u32 ip_range_start = i;
        ip_range_end = bpf_map_lookup_elem(&source_ip_filter, &ip_range_start);

        if (ip_range_end && (src_ip >= ip_range_start && src_ip <= *ip_range_end)) {
            return 1;
        }
    }

    // 如果没有配置过滤规则，默认允许所有IP
    return 1;
}

/**
 * 发送密钥事件到用户空间
 */
static __always_inline void send_key_event(const struct ssl_key_event *event) {
    // 使用perf_event_array将事件发送到用户空间
    bpf_perf_event_output(ctx, &ssl_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
}

/**
 * 从SSL结构体中提取Client Random
 */
static __always_inline int extract_client_random_from_ssl(void *ssl_ptr, __u8 *client_random) {
    // 根据OpenSSL内部结构提取Client Random
    // 这需要根据具体的OpenSSL版本调整偏移量
    void *session_ptr;
    void *client_random_ptr;

    // 读取SSL_SESSION指针
    if (bpf_probe_read(&session_ptr, sizeof(void *), ssl_ptr + SSL_SESSION_OFFSET)) {
        return -1;
    }

    if (!session_ptr) {
        return -1;
    }

    // 读取Client Random指针
    if (bpf_probe_read(&client_random_ptr, sizeof(void *), session_ptr + CLIENT_RANDOM_OFFSET)) {
        return -1;
    }

    if (!client_random_ptr) {
        return -1;
    }

    // 读取Client Random数据
    if (bpf_probe_read(client_random, CLIENT_RANDOM_LEN, client_random_ptr)) {
        return -1;
    }

    return 0;
}

/**
 * 从SSL结构体中提取Master Secret
 */
static __always_inline int extract_master_secret_from_ssl(void *ssl_ptr, __u8 *master_secret) {
    // 根据OpenSSL内部结构提取Master Secret
    void *session_ptr;
    void *master_secret_ptr;

    // 读取SSL_SESSION指针
    if (bpf_probe_read(&session_ptr, sizeof(void *), ssl_ptr + SSL_SESSION_OFFSET)) {
        return -1;
    }

    if (!session_ptr) {
        return -1;
    }

    // 读取Master Secret指针
    if (bpf_probe_read(&master_secret_ptr, sizeof(void *), session_ptr + MASTER_SECRET_OFFSET)) {
        return -1;
    }

    if (!master_secret_ptr) {
        return -1;
    }

    // 读取Master Secret数据
    if (bpf_probe_read(master_secret, MASTER_SECRET_LEN, master_secret_ptr)) {
        return -1;
    }

    return 0;
}

/**
 * SSL_do_handshake Hook函数
 */
SEC("uprobe/SSL_do_handshake")
int probe_ssl_do_handshake(struct pt_regs *ctx) {
    void *ssl_ptr = (void *)PT_REGS_PARM1(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int fd;
    __u64 connection_id;
    struct connection_state conn_state = {};
    struct ssl_connection_info *conn_info = &conn_state.conn_info;

    // 检查进程是否被允许
    if (!is_process_allowed(pid)) {
        return 0;
    }

    // 提取文件描述符
    fd = extract_fd_from_ssl(ssl_ptr);
    if (fd < 0) {
        return 0;
    }

    // 生成连接ID
    connection_id = generate_connection_id(pid, fd);

    // 检查是否已经跟踪过此连接
    struct connection_state *existing_state = bpf_map_lookup_elem(&ssl_connections, &connection_id);
    if (existing_state) {
        // 更新握手状态
        existing_state->handshake_state = SSL_HANDSHAKE_IN_PROGRESS;
        existing_state->last_activity_time = bpf_ktime_get_ns();
        return 0;
    }

    // 填充连接信息
    conn_info->connection_id = connection_id;
    conn_info->pid = pid;
    conn_info->fd = fd;
    conn_info->ssl_version = 0; // 可以从SSL结构中提取

    // 获取进程名称
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    __builtin_memcpy(conn_info->process_name, comm, sizeof(comm));

    // 获取socket信息
    get_socket_info(fd, conn_info);

    // 检查源IP是否被允许
    if (!is_source_ip_allowed(conn_info->src_ip)) {
        return 0;
    }

    // 初始化连接状态
    conn_state.handshake_state = SSL_HANDSHAKE_IN_PROGRESS;
    conn_state.last_activity_time = bpf_ktime_get_ns();
    conn_state.keys_extracted = 0;

    // 将连接信息添加到映射中
    bpf_map_update_elem(&ssl_connections, &connection_id, &conn_state, BPF_ANY);

    return 0;
}

/**
 * SSL_write Hook函数 - 在密钥提取的关键时机
 */
SEC("uprobe/SSL_write")
int probe_ssl_write(struct pt_regs *ctx) {
    void *ssl_ptr = (void *)PT_REGS_PARM1(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int fd;
    __u64 connection_id;
    struct connection_state *conn_state;
    struct ssl_key_event key_event = {};

    // 检查进程是否被允许
    if (!is_process_allowed(pid)) {
        return 0;
    }

    // 提取文件描述符
    fd = extract_fd_from_ssl(ssl_ptr);
    if (fd < 0) {
        return 0;
    }

    // 生成连接ID
    connection_id = generate_connection_id(pid, fd);

    // 查找连接状态
    conn_state = bpf_map_lookup_elem(&ssl_connections, &connection_id);
    if (!conn_state) {
        return 0;
    }

    // 检查是否已经提取过密钥
    if (conn_state->keys_extracted) {
        return 0;
    }

    // 检查握手是否完成
    if (conn_state->handshake_state != SSL_HANDSHAKE_IN_PROGRESS) {
        return 0;
    }

    // 填充密钥事件
    __builtin_memcpy(&key_event.conn_info, &conn_state->conn_info, sizeof(struct ssl_connection_info));
    key_event.timestamp = bpf_ktime_get_ns();

    // 尝试提取Client Random
    if (extract_client_random_from_ssl(ssl_ptr, key_event.client_random) == 0) {
        key_event.has_client_random = 1;
    }

    // 尝试提取Master Secret
    if (extract_master_secret_from_ssl(ssl_ptr, key_event.master_secret) == 0) {
        key_event.has_master_secret = 1;
    }

    // 如果成功提取到密钥信息，发送事件
    if (key_event.has_client_random || key_event.has_master_secret) {
        send_key_event(&key_event);

        // 标记已提取密钥
        conn_state->keys_extracted = 1;
        conn_state->handshake_state = SSL_HANDSHAKE_COMPLETED;
        conn_state->last_activity_time = bpf_ktime_get_ns();

        // 更新连接状态
        bpf_map_update_elem(&ssl_connections, &connection_id, conn_state, BPF_EXIST);
    }

    return 0;
}

/**
 * SSL_read Hook函数 - 作为备用的密钥提取点
 */
SEC("uprobe/SSL_read")
int probe_ssl_read(struct pt_regs *ctx) {
    void *ssl_ptr = (void *)PT_REGS_PARM1(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int fd;
    __u64 connection_id;
    struct connection_state *conn_state;
    struct ssl_key_event key_event = {};

    // 检查进程是否被允许
    if (!is_process_allowed(pid)) {
        return 0;
    }

    // 提取文件描述符
    fd = extract_fd_from_ssl(ssl_ptr);
    if (fd < 0) {
        return 0;
    }

    // 生成连接ID
    connection_id = generate_connection_id(pid, fd);

    // 查找连接状态
    conn_state = bpf_map_lookup_elem(&ssl_connections, &connection_id);
    if (!conn_state) {
        return 0;
    }

    // 检查是否已经提取过密钥
    if (conn_state->keys_extracted) {
        return 0;
    }

    // 填充密钥事件
    __builtin_memcpy(&key_event.conn_info, &conn_state->conn_info, sizeof(struct ssl_connection_info));
    key_event.timestamp = bpf_ktime_get_ns();

    // 尝试提取Client Random
    if (extract_client_random_from_ssl(ssl_ptr, key_event.client_random) == 0) {
        key_event.has_client_random = 1;
    }

    // 尝试提取Master Secret
    if (extract_master_secret_from_ssl(ssl_ptr, key_event.master_secret) == 0) {
        key_event.has_master_secret = 1;
    }

    // 如果成功提取到密钥信息，发送事件
    if (key_event.has_client_random || key_event.has_master_secret) {
        send_key_event(&key_event);

        // 标记已提取密钥
        conn_state->keys_extracted = 1;
        conn_state->handshake_state = SSL_HANDSHAKE_COMPLETED;
        conn_state->last_activity_time = bpf_ktime_get_ns();

        // 更新连接状态
        bpf_map_update_elem(&ssl_connections, &connection_id, conn_state, BPF_EXIST);
    }

    return 0;
}

/**
 * 连接清理函数 - 定期清理过期的连接
 */
SEC("perf_event")
int cleanup_expired_connections(struct bpf_perf_event_data *ctx) {
    __u64 current_time = bpf_ktime_get_ns();
    __u64 expiration_time = 300000000000ULL; // 5分钟超时

    // 遍历所有连接（简化实现）
    // 实际实现需要更复杂的遍历机制或使用LRU Map

    return 0;
}

char _license[] SEC("license") = "GPL";

// SSL结构体偏移量定义（需要根据具体的OpenSSL版本调整）
#define SSL_RBIO_OFFSET 0x10
#define SSL_SESSION_OFFSET 0x20
#define BIO_FD_OFFSET 0x20
#define CLIENT_RANDOM_OFFSET 0x30
#define MASTER_SECRET_OFFSET 0x60