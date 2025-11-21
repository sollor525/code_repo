#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>

#ifdef HAVE_PCAP
#include <pcap.h>
#endif

#include "web_scan_rust.h"

// 全局变量
static volatile int g_running = 1;

// 信号处理函数
void signal_handler(int sig) {
    printf("\n收到信号 %d，正在退出...\n", sig);
    g_running = 0;
}

// 获取当前时间戳（毫秒）
static long long get_timestamp_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// 打印检测结果
void print_result(const struct web_scan_result_t* result, const char* payload, int payload_len) {
    static long long start_time = 0;
    static int packet_count = 0;
    static int matched_count = 0;

    if (start_time == 0) {
        start_time = get_timestamp_ms();
    }

    packet_count++;

    if (result->is_matched) {
        matched_count++;
        long long current_time = get_timestamp_ms();
        double elapsed_time = (double)(current_time - start_time) / 1000.0;

        printf("\n🚨 [攻击检测] 数据包 #%d\n", packet_count);
        printf("规则ID: %u\n", result->rule_id);
        printf("动作类型: %s\n", result->action == Alert ? "ALERT" : "DROP");
        printf("置信度: %u%%\n", result->confidence);
        printf("运行时间: %.2f 秒\n", elapsed_time);
        printf("检测率: %.2f%% (匹配/总包数)\n", (double)matched_count * 100.0 / packet_count);
        printf("=========================================\n");

        // 打印攻击载荷的前64字节
        printf("攻击载荷 (前64字节): ");
        int print_len = payload_len < 64 ? payload_len : 64;
        for (int i = 0; i < print_len; i++) {
            if (payload[i] >= 32 && payload[i] <= 126) {
                printf("%c", payload[i]);
            } else if (payload[i] == '\r') {
                printf("\\r");
            } else if (payload[i] == '\n') {
                printf("\\n");
            } else if (payload[i] == '\t') {
                printf("\\t");
            } else {
                printf("\\x%02x", (unsigned char)payload[i]);
            }
        }
        printf("\n\n");
    }
}

// 显示统计信息
void show_statistics() {
    struct web_scan_stats_t stats;
    if (web_scan_rust_get_stats(&stats) == 0) {
        printf("\n📊 统计信息:\n");
        printf("========================================\n");
        printf("处理数据包总数: %lu\n", stats.packets_processed);
        printf("匹配数据包数: %lu\n", stats.packets_matched);
        printf("匹配率: %.2f%%\n", stats.packets_processed > 0 ?
               (double)stats.packets_matched * 100.0 / stats.packets_processed : 0.0);
        printf("总处理时间: %.3f ms\n", (double)stats.total_processing_time / 1000.0);
        printf("平均处理时间: %.6f ms/包\n", stats.packets_processed > 0 ?
               (double)stats.avg_processing_time / 1000.0 : 0.0);
        printf("最大处理时间: %.3f ms\n", (double)stats.max_processing_time / 1000.0);
        printf("最小处理时间: %.3f ms\n", (double)stats.min_processing_time / 1000.0);
        printf("已加载规则数: %u\n", stats.rules_loaded);
        printf("活跃规则数: %u\n", stats.rules_active);
        printf("=========================================\n");
    } else {
        printf("无法获取统计信息\n");
    }
}

// 显示规则信息
void show_rules_info() {
    printf("📋 已加载的规则信息:\n");
    printf("========================================\n");
    printf("规则已成功加载并激活\n");
    printf("检测引擎已初始化完成\n");
    printf("========================================\n\n");
}

// 加载规则
int load_rules(const char* rules_path) {
    printf("正在加载规则文件: %s\n", rules_path);

    int result = web_scan_rust_load_rules(rules_path);
    if (result == 0) {
        printf("✅ 规则加载成功\n");
        return 0;
    } else {
        printf("❌ 规则加载失败，错误代码: %d\n", result);

        // 获取详细错误信息
        const char* error_msg = web_scan_rust_get_last_error();
        if (error_msg) {
            printf("错误详情: %s\n", error_msg);
        }
        return -1;
    }
}

// 处理HTTP数据包
int process_packet(const unsigned char* data, int len) {
    if (!data || len <= 0) {
        return -1;
    }

    struct web_scan_result_t result = {0};
    int ret = web_scan_rust_process_payload(data, (uint32_t)len, &result);

    if (ret == 0) {
        print_result(&result, (const char*)data, len);
        return 0;
    } else {
        printf("❌ 数据包处理失败，错误代码: %d\n", ret);
        return -1;
    }
}

#ifdef HAVE_PCAP
// libpcap数据包处理回调函数
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    static uint64_t session_counter = 1;

    // 简化的以太网/IP/TCP解析
    if (pkthdr->len < 54) {  // 以太网头(14) + IP头(20) + TCP头(20)
        return;
    }

    // 跳过以太网头部(14字节)
    const u_char* ip_header = packet + 14;

    // 检查IP协议版本
    if ((ip_header[0] & 0xF0) != 0x40) {  // 不是IPv4
        return;
    }

    // 获取IP头长度
    int ip_header_len = (ip_header[0] & 0x0F) * 4;
    if (pkthdr->len < (size_t)(14 + ip_header_len + 20)) {  // 20是最小TCP头长度
        return;
    }

    // 检查协议类型 (TCP = 6)
    if (ip_header[9] != 6) {
        return;
    }

    // 获取TCP头
    const u_char* tcp_header = packet + 14 + ip_header_len;
    int tcp_header_len = ((tcp_header[12] & 0xF0) >> 4) * 4;

    // 获取目标端口
    int dest_port = (tcp_header[2] << 8) | tcp_header[3];

    // 处理HTTP和DNS端口(80, 8080, 8000, 8003, 53等)
    if (dest_port != 80 && dest_port != 8080 && dest_port != 8000 && dest_port != 8003 && dest_port != 443 && dest_port != 53) {
        return;
    }

    // 计算HTTP载荷起始位置
    int payload_offset = 14 + ip_header_len + tcp_header_len;
    int payload_len = pkthdr->len - payload_offset;

    if (payload_len <= 0) {
        return;
    }

    // 获取HTTP载荷
    const u_char* payload = packet + payload_offset;

    // 检查是否是HTTP请求或DNS流量
    bool should_process = false;

    if (payload_len >= 4 &&
        (strncmp((const char*)payload, "GET ", 4) == 0 ||
         strncmp((const char*)payload, "POST ", 5) == 0 ||
         strncmp((const char*)payload, "PUT ", 4) == 0 ||
         strncmp((const char*)payload, "DELETE ", 7) == 0)) {
        should_process = true;  // HTTP请求
    } else if (dest_port == 53 && payload_len > 0) {
        should_process = true;  // DNS流量
    }

    if (should_process) {
        // 处理载荷
        struct web_scan_result_t result = {0};
        int ret = web_scan_rust_process_payload_with_session(
            session_counter++,
            payload,
            payload_len,
            1,  // is_final = 1
            0,  // reset_on_request_end = 0
            &result
        );

        if (ret == 0) {
            print_result(&result, (const char*)payload, payload_len);
        }
    }
}

// 处理pcap文件（完整libpcap实现）
int process_pcap_file(const char* pcap_file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    printf("正在处理pcap文件: %s\n", pcap_file);

    // 打开pcap文件
    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        printf("❌ 无法打开pcap文件 '%s': %s\n", pcap_file, errbuf);
        return -1;
    }

    // 设置HTTP流量过滤器
    struct bpf_program fp;
    char filter_exp[] = "(tcp port 80) or (tcp port 8080) or (tcp port 8000) or (tcp port 8003) or (tcp port 53)";

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("❌ 无法解析过滤器 '%s': %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        printf("❌ 无法设置过滤器 '%s': %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return -1;
    }

    printf("✅ 成功加载pcap文件，开始分析HTTP流量...\n");
    printf("过滤器: %s\n", filter_exp);
    printf("=========================================\n");

    // 处理数据包 - 使用pcap_loop更可靠
    printf("开始处理数据包...\n");
    int packet_count = 0;

    int result = pcap_loop(handle, -1, packet_handler, (u_char*)&packet_count);

    if (result == -2) {
        printf("用户中断处理\n");
    } else if (result == -1) {
        printf("pcap处理出错: %s\n", pcap_geterr(handle));
    } else {
        printf("pcap处理完成，返回码: %d\n", result);
    }

    printf("\n✅ pcap文件处理完成，共处理 %d 个数据包\n", packet_count);

    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
#else
// 简化版本（没有libpcap支持）
int process_pcap_file(const char* pcap_file) {
    printf("正在处理pcap文件: %s\n", pcap_file);
    printf("⚠️  警告: 程序编译时未启用libpcap支持\n");
    printf("要启用完整的pcap文件处理功能:\n");
    printf("1. 安装libpcap开发库: apt-get install libpcap-dev\n");
    printf("2. 重新编译项目，确保检测到libpcap\n\n");

    return -1;
}
#endif

// 打印帮助信息
void print_help(const char* program_name) {
    printf("HTTP扫描检测器 - 使用Web扫描检测引擎\n\n");
    printf("用法: %s [选项]\n\n", program_name);
    printf("选项:\n");
    printf("  -r, --rules <file>     指定规则文件路径 (默认: ./rules)\n");
    printf("  -p, --pcap <file>     处理pcap文件\n");
    printf("  -h, --help          显示帮助信息\n");
    printf("  -v, --version       显示版本信息\n\n");
    printf("示例:\n");
    printf("  %s -r ./rules/test.rules\n", program_name);
    printf("  %s -p ./capture.pcap\n", program_name);
    printf("  %s -r ./rules/ -p ./http_traffic.pcap\n", program_name);
    printf("\n");
}

// 打印版本信息
void print_version() {
    printf("HTTP扫描检测器 v1.0.0\n");
    printf("基于Web扫描检测引擎 (Rust实现)\n");
    printf("支持PCRE字段、三层匹配架构、实时检测\n");
    printf("\n");
    printf("特性:\n");
    printf("- ✅ PCRE (Perl Compatible Regular Expressions) 支持\n");
    printf("- ✅ 三层匹配架构 (Fast Pattern → Normal Content → Regex Fallback)\n");
    printf("- ✅ Intel Hyperscan 高性能加速 (默认模式)\n");
    printf("- ✅ 完整修饰符支持 (nocase, startswith, endswith等)\n");
    printf("- ✅ HTTP协议感知检测\n");
    printf("- ✅ 实时性能统计\n");
    printf("- ✅ 线程安全并发处理\n");
    printf("\n");
}

// 主函数
int main(int argc, char* argv[]) {
    const char* rules_path = "./rules";
    const char* pcap_file = NULL;

    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--rules") == 0) {
            if (i + 1 < argc) {
                rules_path = argv[++i];
            } else {
                printf("错误: %s 选项需要参数\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pcap") == 0) {
            if (i + 1 < argc) {
                pcap_file = argv[++i];
            } else {
                printf("错误: %s 选项需要参数\n", argv[i]);
                return 1;
            }
        } else {
            printf("错误: 未知选项 %s\n", argv[i]);
            print_help(argv[0]);
            return 1;
        }
    }

    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("🚀 HTTP扫描检测器启动\n");
    printf("版本: 1.0.0\n");
    printf("基于Web扫描检测引擎 (Rust实现)\n");
    printf("========================================\n\n");

    // 初始化引擎
    printf("正在初始化检测引擎...\n");
    if (web_scan_rust_init() != 0) {
        printf("❌ 引擎初始化失败\n");
        return 1;
    }
    printf("✅ 引擎初始化成功\n");

    // 检查Hyperscan状态
    if (web_scan_rust_is_hyperscan_enabled()) {
        printf("✅ Hyperscan加速已启用 (默认模式)\n");
    } else {
        printf("⚠️  Hyperscan加速未启用\n");
    }
    printf("\n");

    // 加载规则
    if (load_rules(rules_path) != 0) {
        return 1;
    }

    show_rules_info();

    // 如果指定了pcap文件，处理它
    if (pcap_file) {
        if (process_pcap_file(pcap_file) != 0) {
            return 1;
        }
    } else {
        printf("💡 使用方法:\n");
        printf("   1. 加载规则: %s -r <规则文件>\n", argv[0]);
        printf("   2. 处理pcap: %s -p <pcap文件>\n", argv[0]);
        printf("   3. 显示帮助: %s -h\n", argv[0]);
        printf("   4. 显示版本: %s -v\n", argv[0]);
        printf("\n");
        printf("📝 检测引擎已就绪，等待数据包处理...\n");
        printf("💡 提示: 使用 Ctrl+C 退出\n\n");

        // 等待用户中断或超时
        printf("按 Ctrl+C 退出程序...\n");
        while (g_running) {
            sleep(1);
        }
    }

    // 显示最终统计
    show_statistics();

    printf("\n👋 HTTP扫描检测器已退出\n");
    return 0;
}