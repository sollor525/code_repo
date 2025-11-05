/**
 * @file ebpf_monitor_simple.c
 * @brief 简化的eBPF监控程序 - 专注于进程发现和LD_PRELOAD注入
 * @author sollor525@hotmail.com
 * @version 1.0.0
 * @date 2023-11-05
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// 最大进程名长度
#define MAX_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// 进程事件结构
struct process_event {
    u32 pid;
    u64 timestamp;
    char comm[MAX_COMM_LEN];
    char libssl_path[MAX_FILENAME_LEN];
};

// Maps定义
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} process_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct process_event));
} monitored_processes SEC(".maps");

// 辅助函数：检查字符串是否包含子串
static __always_inline int str_contains(const char *str, const char *substr, int max_len) {
    int i, j;
    for (i = 0; i < max_len - 1; i++) {
        if (str[i] == '\0') break;
        for (j = 0; substr[j] != '\0'; j++) {
            if (i + j >= max_len || str[i + j] != substr[j]) {
                break;
            }
        }
        if (substr[j] == '\0') {
            return 1;
        }
    }
    return 0;
}

// Hook 1: 监控execve系统调用，发现新进程
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event event = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 获取进程名
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    event.pid = pid;
    event.timestamp = bpf_ktime_get_ns();

    // 尝试获取argv0作为命令
    if (ctx->args[0]) {
        bpf_probe_read_user_str(&event.libssl_path, sizeof(event.libssl_path),
                                   (void *)ctx->args[0]);
    }

    // 发送事件到用户空间
    bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU,
                         &event, sizeof(event));

    return 0;
}

// Hook 2: 监控mmap调用，发现SSL库加载
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 检查是否在监控列表中
    struct process_event *proc_info = bpf_map_lookup_elem(&monitored_processes, &pid);
    if (proc_info) {
        return 0; // 已在监控列表中
    }

    // 获取mmap的文件名
    const char __user *filename = (const char __user *)ctx->args[5];
    char filename_buf[MAX_FILENAME_LEN];
    if (bpf_probe_read_user_str(filename_buf, sizeof(filename_buf), filename) > 0) {
        // 检查是否是SSL库
        if (str_contains(filename_buf, "libssl.so", sizeof(filename_buf)) ||
            str_contains(filename_buf, "libcrypto.so", sizeof(filename_buf))) {

            struct process_event new_proc = {};
            new_proc.pid = pid;
            new_proc.timestamp = bpf_ktime_get_ns();
            bpf_get_current_comm(&new_proc.comm, sizeof(new_proc.comm));
            __builtin_memcpy(new_proc.libssl_path, filename_buf, sizeof(filename_buf));

            // 添加到监控列表
            bpf_map_update_elem(&monitored_processes, &pid, &new_proc, BPF_ANY);

            // 发送发现SSL库加载事件
            bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU,
                                 &new_proc, sizeof(new_proc));
        }
    }

    return 0;
}

// Hook 3: 监控socket连接获取网络信息
SEC("tracepoint/syscalls/sys_enter_socketconnect")
int trace_socketconnect(struct trace_event_raw_sys_enter *ctx)
{
    int sockfd = (int)ctx->args[0];
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 检查是否在监控列表中
    struct process_event *proc_info = bpf_map_lookup_elem(&monitored_processes, &pid);
    if (!proc_info) {
        return 0; // 未监控的进程
    }

    // 只处理IPv4连接
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in sin;
        if (bpf_probe_read_user(&sin, sizeof(sin), addr) == 0) {
            struct process_event event = {};
            event.pid = pid;
            event.timestamp = bpf_ktime_get_ns();
            __builtin_memcpy(event.comm, proc_info->comm, sizeof(proc_info->comm));

            // 将连接信息编码到libssl_path字段中传输
            // 格式: "CONNECT:IP:PORT"
            struct {
                char prefix[8];
                __u32 ip;
                __u16 port;
            } conn_info = {"CONNECT", sin.sin_addr.s_addr, sin.sin_port};

            __builtin_memcpy(&event.libssl_path, &conn_info, sizeof(conn_info));

            bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU,
                                 &event, sizeof(event));
        }
    }

    return 0;
}

// Hook 4: 监控进程退出
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    u32 pid = ctx->pid;

    // 从监控列表中移除
    bpf_map_delete_elem(&monitored_processes, &pid);

    return 0;
}

// 许可证
char _license[] SEC("license") = "GPL";