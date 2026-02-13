/**
 * @file connection_tracker.c
 * @brief eBPF连接跟踪器 - 专门负责五元组信息收集和连接状态跟踪
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
#include <linux/net.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define MAX_PROCESS_NAME_LEN 16
#define MAX_CONNECTIONS 10240
#define MAX_SOCKETS 1024
#define CONNECTION_TIMEOUT_NS 300000000000ULL  // 5分钟

/**
 * 网络五元组信息结构体
 */
struct five_tuple {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 ip_version;  // IPv4=4, IPv6=6
    __u8 padding[2];
};

/**
 * 扩展的连接信息结构体
 */
struct extended_connection_info {
    struct five_tuple tuple;
    __u64 connection_id;
    __u32 pid;
    __u32 fd;
    char process_name[MAX_PROCESS_NAME_LEN];
    __u64 creation_time;
    __u64 last_activity_time;
    __u8 ssl_version;
    __u8 cipher_suite;
    __u16 padding;
};

/**
 * Socket信息映射 - key: fd, value: extended_connection_info
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct extended_connection_info);
    __uint(max_entries, MAX_SOCKETS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} socket_connections SEC(".maps");

/**
 * 连接ID映射 - key: connection_id, value: extended_connection_info
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct extended_connection_info);
    __uint(max_entries, MAX_CONNECTIONS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_id_map SEC(".maps");

/**
 * 进程到连接的映射 - key: pid, value: connection_count
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} process_connection_count SEC(".maps");

/**
 * IP地址统计映射 - key: ip_address, value: connection_count
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_connection_stats SEC(".maps");

/**
 * 辅助函数声明
 */
static __always_inline __u64 generate_connection_id(__u32 pid, __u32 fd);
static __always_inline int extract_socket_info(struct pt_regs *ctx, __u32 fd, struct extended_connection_info *conn_info);
static __always_inline int get_ipv4_socket_info(__u32 fd, struct five_tuple *tuple);
static __always_inline int get_ipv6_socket_info(__u32 fd, struct five_tuple *tuple);
static __always_inline int update_connection_statistics(const struct extended_connection_info *conn_info);
static __always_inline int cleanup_expired_connections(void);
static __always_inline __u32 ip_to_u32(const __u8 *ip);
static __always_inline void u32_to_ip(__u32 ip_val, __u8 *ip);

/**
 * 生成连接唯一标识
 */
static __always_inline __u64 generate_connection_id(__u32 pid, __u32 fd) {
    // 使用PID、FD和时间戳的组合确保唯一性
    __u64 timestamp = bpf_ktime_get_ns() & 0xFFFFFF;
    return ((__u64)pid << 32) | ((__u64)fd << 16) | timestamp;
}

/**
 * 将IP地址转换为32位整数
 */
static __always_inline __u32 ip_to_u32(const __u8 *ip) {
    return (__u32)ip[0] << 24 | (__u32)ip[1] << 16 | (__u32)ip[2] << 8 | (__u32)ip[3];
}

/**
 * 将32位整数转换为IP地址
 */
static __always_inline void u32_to_ip(__u32 ip_val, __u8 *ip) {
    ip[0] = (ip_val >> 24) & 0xFF;
    ip[1] = (ip_val >> 16) & 0xFF;
    ip[2] = (ip_val >> 8) & 0xFF;
    ip[3] = ip_val & 0xFF;
}

/**
 * 获取IPv4 socket信息
 */
static __always_inline int get_ipv4_socket_info(__u32 fd, struct five_tuple *tuple) {
    struct sockaddr_in local_addr, remote_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    int ret;

    // 获取本地地址信息
    ret = bpf_getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &local_addr, &addr_len);
    if (ret < 0) {
        // 尝试其他方法获取地址
        ret = bpf_getsockname(fd, (struct sockaddr *)&local_addr, &addr_len);
        if (ret < 0) {
            return -1;
        }
    }

    // 获取远程地址信息
    ret = bpf_getpeername(fd, (struct sockaddr *)&remote_addr, &addr_len);
    if (ret < 0) {
        return -1;
    }

    // 填充五元组信息
    if (local_addr.sin_family == AF_INET && remote_addr.sin_family == AF_INET) {
        tuple->src_ip = bpf_ntohl(local_addr.sin_addr.s_addr);
        tuple->src_port = bpf_ntohs(local_addr.sin_port);
        tuple->dst_ip = bpf_ntohl(remote_addr.sin_addr.s_addr);
        tuple->dst_port = bpf_ntohs(remote_addr.sin_port);
        tuple->protocol = IPPROTO_TCP;  // SSL通常使用TCP
        tuple->ip_version = 4;
        return 0;
    }

    return -1;
}

/**
 * 获取IPv6 socket信息
 */
static __always_inline int get_ipv6_socket_info(__u32 fd, struct five_tuple *tuple) {
    struct sockaddr_in6 local_addr, remote_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in6);
    int ret;

    // 获取本地地址信息
    ret = bpf_getsockname(fd, (struct sockaddr *)&local_addr, &addr_len);
    if (ret < 0) {
        return -1;
    }

    // 获取远程地址信息
    ret = bpf_getpeername(fd, (struct sockaddr *)&remote_addr, &addr_len);
    if (ret < 0) {
        return -1;
    }

    // 填充五元组信息（IPv6简化处理，取前32位）
    if (local_addr.sin6_family == AF_INET6 && remote_addr.sin6_family == AF_INET6) {
        // 对于IPv6，我们只记录前32位作为简化处理
        tuple->src_ip = bpf_ntohl(local_addr.sin6_addr.s6_addr32[0]);
        tuple->src_port = bpf_ntohs(local_addr.sin6_port);
        tuple->dst_ip = bpf_ntohl(remote_addr.sin6_addr.s6_addr32[0]);
        tuple->dst_port = bpf_ntohs(remote_addr.sin6_port);
        tuple->protocol = IPPROTO_TCP;
        tuple->ip_version = 6;
        return 0;
    }

    return -1;
}

/**
 * 提取socket信息
 */
static __always_inline int extract_socket_info(struct pt_regs *ctx, __u32 fd, struct extended_connection_info *conn_info) {
    struct five_tuple *tuple = &conn_info->tuple;
    int ret;

    // 尝试获取IPv4信息
    ret = get_ipv4_socket_info(fd, tuple);
    if (ret < 0) {
        // 如果IPv4失败，尝试IPv6
        ret = get_ipv6_socket_info(fd, tuple);
        if (ret < 0) {
            return -1;
        }
    }

    // 填充其他连接信息
    conn_info->pid = bpf_get_current_pid_tgid() >> 32;
    conn_info->fd = fd;
    conn_info->creation_time = bpf_ktime_get_ns();
    conn_info->last_activity_time = conn_info->creation_time;

    // 获取进程名称
    bpf_get_current_comm(&conn_info->process_name, sizeof(conn_info->process_name));

    // 生成连接ID
    conn_info->connection_id = generate_connection_id(conn_info->pid, fd);

    return 0;
}

/**
 * 更新连接统计信息
 */
static __always_inline int update_connection_statistics(const struct extended_connection_info *conn_info) {
    __u32 count;
    __u32 pid = conn_info->pid;
    __u32 src_ip = conn_info->tuple.src_ip;
    __u32 dst_ip = conn_info->tuple.dst_ip;

    // 更新进程连接计数
    __u32 *process_count = bpf_map_lookup_elem(&process_connection_count, &pid);
    if (process_count) {
        count = *process_count + 1;
    } else {
        count = 1;
    }
    bpf_map_update_elem(&process_connection_count, &pid, &count, BPF_ANY);

    // 更新源IP连接统计
    __u32 *src_ip_count = bpf_map_lookup_elem(&ip_connection_stats, &src_ip);
    if (src_ip_count) {
        count = *src_ip_count + 1;
    } else {
        count = 1;
    }
    bpf_map_update_elem(&ip_connection_stats, &src_ip, &count, BPF_ANY);

    // 更新目标IP连接统计
    __u32 *dst_ip_count = bpf_map_lookup_elem(&ip_connection_stats, &dst_ip);
    if (dst_ip_count) {
        count = *dst_ip_count + 1;
    } else {
        count = 1;
    }
    bpf_map_update_elem(&ip_connection_stats, &dst_ip, &count, BPF_ANY);

    return 0;
}

/**
 * 清理过期连接
 */
static __always_inline int cleanup_expired_connections(void) {
    __u64 current_time = bpf_ktime_get_ns();
    __u64 expiration_time = current_time - CONNECTION_TIMEOUT_NS;

    // 简化实现：在实际部署中需要更复杂的清理逻辑
    // 这里提供框架，具体实现需要考虑eBPF的限制

    return 0;
}

/**
 * socket系统调用Hook - 跟踪新创建的socket
 */
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    __u32 domain = ctx->args[0];
    __u32 type = ctx->args[1];
    __u32 protocol = ctx->args[2];
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 只跟踪TCP socket
    if (domain != AF_INET && domain != AF_INET6) {
        return 0;
    }

    if (type != SOCK_STREAM) {
        return 0;
    }

    // 这里可以记录socket创建信息，但需要等待connect调用来获取完整的五元组

    return 0;
}

/**
 * connect系统调用Hook - 跟踪连接建立
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u32 fd = (__u32)ctx->args[0];
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    __u32 addrlen = (__u32)ctx->args[2];
    struct extended_connection_info conn_info = {};
    int ret;

    // 只跟踪IPv4和IPv6连接
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
        return 0;
    }

    // 提取socket信息
    ret = extract_socket_info((struct pt_regs *)ctx, fd, &conn_info);
    if (ret < 0) {
        return 0;
    }

    // 从connect参数中补充目标地址信息
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        conn_info.tuple.dst_ip = bpf_ntohl(addr_in->sin_addr.s_addr);
        conn_info.tuple.dst_port = bpf_ntohs(addr_in->sin_port);
        conn_info.tuple.protocol = IPPROTO_TCP;
        conn_info.tuple.ip_version = 4;
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        conn_info.tuple.dst_ip = bpf_ntohl(addr_in6->sin6_addr.s6_addr32[0]);
        conn_info.tuple.dst_port = bpf_ntohs(addr_in6->sin6_port);
        conn_info.tuple.protocol = IPPROTO_TCP;
        conn_info.tuple.ip_version = 6;
    }

    // 更新统计信息
    update_connection_statistics(&conn_info);

    // 存储连接信息到socket映射
    bpf_map_update_elem(&socket_connections, &fd, &conn_info, BPF_ANY);

    // 存储连接信息到连接ID映射
    bpf_map_update_elem(&connection_id_map, &conn_info.connection_id, &conn_info, BPF_ANY);

    return 0;
}

/**
 * close系统调用Hook - 清理关闭的连接
 */
SEC("tracepoint/syscalls/sys_enter_close")
int trace_sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
    __u32 fd = (__u32)ctx->args[0];
    struct extended_connection_info *conn_info;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 count;

    // 查找连接信息
    conn_info = bpf_map_lookup_elem(&socket_connections, &fd);
    if (!conn_info) {
        return 0;
    }

    // 从socket映射中删除
    bpf_map_delete_elem(&socket_connections, &fd);

    // 从连接ID映射中删除
    bpf_map_delete_elem(&connection_id_map, &conn_info->connection_id);

    // 更新进程连接计数
    __u32 *process_count = bpf_map_lookup_elem(&process_connection_count, &pid);
    if (process_count && *process_count > 0) {
        count = *process_count - 1;
        if (count == 0) {
            bpf_map_delete_elem(&process_connection_count, &pid);
        } else {
            bpf_map_update_elem(&process_connection_count, &pid, &count, BPF_EXIST);
        }
    }

    return 0;
}

/**
 * getsockopt Hook - 检测SSL/TLS连接
 */
SEC("kprobe/__sys_getsockopt")
int kp_sys_getsockopt(struct pt_regs *ctx) {
    __u32 fd = (__u32)PT_REGS_PARM1(ctx);
    __u32 level = (__u32)PT_REGS_PARM2(ctx);
    __u32 optname = (__u32)PT_REGS_PARM3(ctx);
    struct extended_connection_info *conn_info;

    // 只跟踪SSL相关的getsockopt调用
    if (level != SOL_SSL && level != IPPROTO_TCP) {
        return 0;
    }

    // 查找连接信息
    conn_info = bpf_map_lookup_elem(&socket_connections, &fd);
    if (!conn_info) {
        return 0;
    }

    // 更新最后活动时间
    conn_info->last_activity_time = bpf_ktime_get_ns();

    // 如果是SSL相关的选项，可以在这里标记为SSL连接
    if (level == SOL_SSL) {
        conn_info->ssl_version = 1;  // 标记为SSL连接
    }

    return 0;
}

/**
 * 定期清理过期连接的函数
 */
SEC("perf_event")
int cleanup_connections(struct bpf_perf_event_data *ctx) {
    return cleanup_expired_connections();
}

char _license[] SEC("license") = "GPL";