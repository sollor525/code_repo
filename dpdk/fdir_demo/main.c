/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include "fdir_core.h"
#include "flow_manager.h"
#include "packet_processor.h"
#include "pattern_matcher.h"
#include "dpdk_utils.h"
#include "fdir_config.h"

/* 全局变量 */
static volatile bool g_running = true;
static struct fdir_context g_fdir_ctx;
static struct fdir_flow_manager g_flow_mgr[FDIR_MAX_PORTS];
static struct fdir_packet_processor g_proc[FDIR_MAX_PORTS][FDIR_MAX_QUEUES];
static struct fdir_pattern_matcher g_http_matcher[FDIR_MAX_PORTS];
static struct fdir_pattern_matcher g_tls_matcher[FDIR_MAX_PORTS];

/* 配置参数 */
struct fdir_app_config {
    uint16_t port_mask;
    uint16_t nb_rx_queues;
    uint16_t nb_tx_queues;
    bool enable_stats;
    uint32_t stats_interval;
    bool enable_http_matcher;
    bool enable_tls_matcher;
    char config_file[256];
};

/* 默认配置 */
static struct fdir_app_config g_app_config = {
    .port_mask = 0x1,                    /* 默认使用端口0 */
    .nb_rx_queues = FDIR_DEFAULT_RX_QUEUES,
    .nb_tx_queues = FDIR_DEFAULT_TX_QUEUES,
    .enable_stats = true,
    .stats_interval = FDIR_STATS_INTERVAL,
    .enable_http_matcher = true,
    .enable_tls_matcher = true,
    .config_file = {0}
};

/* 内部函数声明 */
static void signal_handler(int signum);
static int parse_args(int argc, char **argv);
static void print_usage(const char *prgname);
static int init_fdir(void);
static int load_flow_rules(void);
static int create_default_flow_rules(void);
static int start_packet_processors(void);
static void stop_packet_processors(void);
static void *stats_thread(void *arg);
static void on_packet_process(struct fdir_packet_processor *proc,
                              struct fdir_packet_ctx *ctx);
static int on_packet_error(struct fdir_packet_processor *proc,
                          int error_code, const char *error_msg);

/**
 * 主函数
 */
int main(int argc, char **argv)
{
    int ret;
    pthread_t stats_tid;

    printf("\nDPDK FDIR Demo - Flow Director\n");
    printf("Copyright (c) 2024\n\n");

    /* 解析命令行参数 */
    ret = parse_args(argc, argv);
    if (ret != 0) {
        return ret;
    }

    /* 设置信号处理 */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* 初始化EAL */
    struct fdir_eal_config eal_cfg = {
        .argc = argc,
        .argv = argv
    };
    ret = fdir_eal_init(&eal_cfg);
    if (ret != FDIR_SUCCESS) {
        printf("Error: Failed to initialize EAL\n");
        return ret;
    }

    /* 初始化FDIR */
    ret = init_fdir();
    if (ret != FDIR_SUCCESS) {
        printf("Error: Failed to initialize FDIR\n");
        goto cleanup_eal;
    }

    /* 加载Flow规则 */
    ret = load_flow_rules();
    if (ret != FDIR_SUCCESS) {
        printf("Error: Failed to load flow rules\n");
        goto cleanup_fdir;
    }

    /* 创建默认Flow规则（如果没有配置文件） */
    if (strlen(g_app_config.config_file) == 0) {
        create_default_flow_rules();
    }

    /* 启动数据包处理器 */
    ret = start_packet_processors();
    if (ret != FDIR_SUCCESS) {
        printf("Error: Failed to start packet processors\n");
        goto cleanup_fdir;
    }

    /* 启动统计线程 */
    if (g_app_config.enable_stats) {
        if (pthread_create(&stats_tid, NULL, stats_thread, NULL) != 0) {
            printf("Warning: Failed to create stats thread\n");
        } else {
            printf("Stats thread started\n");
        }
    }

    printf("\nFDIR Demo is running...\n");
    printf("Press Ctrl+C to stop\n\n");

    /* 主循环 */
    while (g_running) {
        sleep(1);
    }

    /* 停止统计线程 */
    if (g_app_config.enable_stats) {
        pthread_cancel(stats_tid);
        pthread_join(stats_tid, NULL);
    }

    /* 停止数据包处理器 */
    stop_packet_processors();

    /* 清理FDIR */
cleanup_fdir:
    fdir_cleanup(&g_fdir_ctx);

    /* 清理EAL */
cleanup_eal:
    fdir_eal_cleanup();

    printf("\nFDIR Demo stopped\n");
    return 0;
}

/**
 * 信号处理函数
 */
static void signal_handler(int signum)
{
    printf("\nReceived signal %d, stopping...\n", signum);
    g_running = false;
}

/**
 * 解析命令行参数
 */
static int parse_args(int argc, char **argv)
{
    int opt;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];

    static struct option lgopts[] = {
        {"port-mask", required_argument, NULL, 'p'},
        {"nb-queues", required_argument, NULL, 'q'},
        {"stats", no_argument, NULL, 's'},
        {"stats-interval", required_argument, NULL, 'i'},
        {"config", required_argument, NULL, 'c'},
        {"no-http", no_argument, NULL, 0},
        {"no-tls", no_argument, NULL, 1},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, 0, 0}
    };

    /* 修改argv，让EAL只处理它识别的参数 */
    argvopt = malloc(sizeof(char *) * (argc + 1));
    if (!argvopt) {
        return -1;
    }

    argvopt[0] = argv[0];
    int eal_argc = 1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            break;
        }
        argvopt[eal_argc++] = argv[i];
    }
    argvopt[eal_argc] = NULL;

    /* 解析应用层参数 */
    while ((opt = getopt_long(argc, argv, "p:q:si:c:h", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'p': /* port-mask */
            g_app_config.port_mask = strtoul(optarg, NULL, 0);
            break;

        case 'q': /* number of queues */
            g_app_config.nb_rx_queues = strtoul(optarg, NULL, 0);
            g_app_config.nb_tx_queues = g_app_config.nb_rx_queues;
            break;

        case 's': /* enable stats */
            g_app_config.enable_stats = true;
            break;

        case 'i': /* stats interval */
            g_app_config.stats_interval = strtoul(optarg, NULL, 0);
            break;

        case 'c': /* config file */
            strncpy(g_app_config.config_file, optarg,
                   sizeof(g_app_config.config_file) - 1);
            break;

        case 0: /* --no-http */
            g_app_config.enable_http_matcher = false;
            break;

        case 1: /* --no-tls */
            g_app_config.enable_tls_matcher = false;
            break;

        case 'h': /* help */
            print_usage(prgname);
            free(argvopt);
            return 0;

        default:
            print_usage(prgname);
            free(argvopt);
            return -1;
        }
    }

    free(argvopt);
    return 0;
}

/**
 * 打印使用说明
 */
static void print_usage(const char *prgname)
{
    printf("%s [EAL options] -- [application options]\n\n", prgname);
    printf("Application options:\n");
    printf("  -p PORT-MASK        Hexadecimal bitmask of ports to use\n");
    printf("  -q NB-QUEUES        Number of Rx/Tx queues per port\n");
    printf("  -s                  Enable statistics\n");
    printf("  -i INTERVAL         Statistics interval in seconds (default: 1)\n");
    printf("  -c FILE             Configuration file for flow rules\n");
    printf("  --no-http           Disable HTTP pattern matcher\n");
    printf("  --no-tls            Disable TLS pattern matcher\n");
    printf("  -h                  Show this help\n\n");
    printf("Example:\n");
    printf("  %s -c 0xf -n 4 -- -p 0x3 -q 4 -s -i 5\n", prgname);
}

/**
 * 初始化FDIR
 */
static int init_fdir(void)
{
    uint16_t port_id;
    int ret;

    /* 初始化FDIR上下文 */
    ret = fdir_init(&g_fdir_ctx, g_app_config.port_mask);
    if (ret != FDIR_SUCCESS) {
        return ret;
    }

    /* 初始化每个端口的Flow管理器 */
    RTE_ETH_FOREACH_DEV(port_id) {
        if (!(g_app_config.port_mask & (1u << port_id))) {
            continue;
        }

        printf("Initializing flow manager for port %u\n", port_id);
        ret = fdir_flow_manager_init(&g_flow_mgr[port_id], port_id, FDIR_MAX_FLOWS);
        if (ret != FDIR_SUCCESS) {
            printf("Error: Failed to initialize flow manager for port %u\n", port_id);
            return ret;
        }

        /* 初始化HTTP匹配器 */
        if (g_app_config.enable_http_matcher) {
            ret = fdir_pattern_matcher_init(&g_http_matcher[port_id],
                                           FDIR_MATCHER_HTTP, 100);
            if (ret != FDIR_SUCCESS) {
                printf("Error: Failed to initialize HTTP matcher for port %u\n", port_id);
                return ret;
            }
        }

        /* 初始化TLS匹配器 */
        if (g_app_config.enable_tls_matcher) {
            ret = fdir_pattern_matcher_init(&g_tls_matcher[port_id],
                                           FDIR_MATCHER_TLS, 100);
            if (ret != FDIR_SUCCESS) {
                printf("Error: Failed to initialize TLS matcher for port %u\n", port_id);
                return ret;
            }
        }
    }

    return FDIR_SUCCESS;
}

/**
 * 加载Flow规则
 */
static int load_flow_rules(void)
{
    if (strlen(g_app_config.config_file) == 0) {
        return FDIR_SUCCESS; /* 没有配置文件，使用默认规则 */
    }

    printf("Loading flow rules from %s\n", g_app_config.config_file);

    uint16_t port_id;
    RTE_ETH_FOREACH_DEV(port_id) {
        if (!(g_app_config.port_mask & (1u << port_id))) {
            continue;
        }

        /* TODO: 实现配置文件加载逻辑 */
        printf("Port %u: Config file loading not implemented yet\n", port_id);
    }

    return FDIR_SUCCESS;
}

/**
 * 创建默认Flow规则
 */
static int create_default_flow_rules(void)
{
    struct fdir_flow_rule rule;
    uint16_t port_id;

    RTE_ETH_FOREACH_DEV(port_id) {
        if (!(g_app_config.port_mask & (1u << port_id))) {
            continue;
        }

        printf("Creating default flow rules for port %u\n", port_id);

        /* IPv4 TCP规则 - 队列0 */
        memset(&rule, 0, sizeof(rule));
        rule.id = 1000 + port_id * 100;
        snprintf(rule.name, sizeof(rule.name), "ipv4_tcp_port%u", port_id);
        strncpy(rule.description, "IPv4 TCP traffic", sizeof(rule.description) - 1);
        rule.priority = 10;
        rule.port_id = port_id;
        rule.ingress = true;
        rule.egress = false;
        rule.active = true;
        rule.match.src_ip_mask = 0;
        rule.match.dst_ip_mask = 0;
        rule.match.ip_proto = IPPROTO_TCP;
        rule.match.ip_proto_mask = 0xFF;
        rule.action.queue = 0;
        rule.action.drop = false;
        rule.action.mark = 0;
        rule.action.count = true;

        fdir_flow_create(&g_fdir_ctx, &rule);

        /* HTTP规则 - 队列1 */
        memset(&rule, 0, sizeof(rule));
        rule.id = 1100 + port_id * 100;
        snprintf(rule.name, sizeof(rule.name), "http_port%u", port_id);
        strncpy(rule.description, "HTTP traffic", sizeof(rule.description) - 1);
        rule.priority = 20;
        rule.port_id = port_id;
        rule.ingress = true;
        rule.egress = false;
        rule.active = true;
        rule.match.dst_port = HTTP_PORT;
        rule.match.dst_port_mask = 0xFFFF;
        rule.match.ip_proto = IPPROTO_TCP;
        rule.match.ip_proto_mask = 0xFF;
        rule.action.queue = 1;
        rule.action.drop = false;
        rule.action.mark = 1;
        rule.action.count = true;
        rule.match.http_enable = true;

        fdir_flow_create(&g_fdir_ctx, &rule);

        /* HTTPS规则 - 队列2 */
        memset(&rule, 0, sizeof(rule));
        rule.id = 1200 + port_id * 100;
        snprintf(rule.name, sizeof(rule.name), "https_port%u", port_id);
        strncpy(rule.description, "HTTPS/TLS traffic", sizeof(rule.description) - 1);
        rule.priority = 20;
        rule.port_id = port_id;
        rule.ingress = true;
        rule.egress = false;
        rule.active = true;
        rule.match.dst_port = HTTPS_PORT;
        rule.match.dst_port_mask = 0xFFFF;
        rule.match.ip_proto = IPPROTO_TCP;
        rule.match.ip_proto_mask = 0xFF;
        rule.action.queue = 2;
        rule.action.drop = false;
        rule.action.mark = 2;
        rule.action.count = true;
        rule.match.tls_enable = true;

        fdir_flow_create(&g_fdir_ctx, &rule);

        /* UDP DNS规则 - 队列3 */
        memset(&rule, 0, sizeof(rule));
        rule.id = 1300 + port_id * 100;
        snprintf(rule.name, sizeof(rule.name), "dns_port%u", port_id);
        strncpy(rule.description, "DNS traffic", sizeof(rule.description) - 1);
        rule.priority = 30;
        rule.port_id = port_id;
        rule.ingress = true;
        rule.egress = false;
        rule.active = true;
        rule.match.dst_port = DNS_PORT;
        rule.match.dst_port_mask = 0xFFFF;
        rule.match.ip_proto = IPPROTO_UDP;
        rule.match.ip_proto_mask = 0xFF;
        rule.action.queue = 3;
        rule.action.drop = false;
        rule.action.mark = 3;
        rule.action.count = true;

        fdir_flow_create(&g_fdir_ctx, &rule);
    }

    return FDIR_SUCCESS;
}

/**
 * 启动数据包处理器
 */
static int start_packet_processors(void)
{
    uint16_t port_id;
    int ret;

    RTE_ETH_FOREACH_DEV(port_id) {
        if (!(g_app_config.port_mask & (1u << port_id))) {
            continue;
        }

        /* 为每个队列创建处理器 */
        for (uint16_t q = 0; q < g_app_config.nb_rx_queues; q++) {
            struct fdir_process_config proc_cfg = {
                .port_id = port_id,
                .queue_id = q,
                .burst_size = FDIR_DEFAULT_BURST_SIZE,
                .max_burst_size = FDIR_MAX_BATCH_SIZE,
                .mode = FDIR_PROCESS_MODE_POLL,
                .enable_stats = g_app_config.enable_stats,
                .stats_interval = g_app_config.stats_interval,
                .timeout_ms = 100,
                .cpu_affinity = 0xFFFFFFFF, /* 不设置亲和性 */
                .prefetch_offset = 2,
                .enable_dpi = true
            };

            printf("Starting packet processor: port=%u, queue=%u\n",
                   port_id, q);

            ret = fdir_packet_processor_init(&g_proc[port_id][q], &proc_cfg);
            if (ret != FDIR_SUCCESS) {
                printf("Error: Failed to init packet processor\n");
                return ret;
            }

            /* 设置回调函数 */
            fdir_packet_set_callback(&g_proc[port_id][q], on_packet_process);
            fdir_packet_set_error_callback(&g_proc[port_id][q], on_packet_error);

            /* 启动处理器 */
            ret = fdir_packet_processor_start(&g_proc[port_id][q]);
            if (ret != FDIR_SUCCESS) {
                printf("Error: Failed to start packet processor\n");
                return ret;
            }
        }
    }

    return FDIR_SUCCESS;
}

/**
 * 停止数据包处理器
 */
static void stop_packet_processors(void)
{
    uint16_t port_id;

    printf("Stopping packet processors...\n");

    RTE_ETH_FOREACH_DEV(port_id) {
        if (!(g_app_config.port_mask & (1u << port_id))) {
            continue;
        }

        for (uint16_t q = 0; q < g_app_config.nb_rx_queues; q++) {
            fdir_packet_processor_stop(&g_proc[port_id][q]);
            fdir_packet_processor_cleanup(&g_proc[port_id][q]);
        }
    }
}

/**
 * 统计线程
 */
static void *stats_thread(void *arg)
{
    (void)arg;

    while (g_running) {
        /* 打印FDIR统计 */
        fdir_stats_print(&g_fdir_ctx);

        /* 打印处理器统计 */
        uint16_t port_id;
        RTE_ETH_FOREACH_DEV(port_id) {
            if (!(g_app_config.port_mask & (1u << port_id))) {
                continue;
            }

            for (uint16_t q = 0; q < g_app_config.nb_rx_queues; q++) {
                struct fdir_process_stats stats;
                if (fdir_packet_stats_get(&g_proc[port_id][q], &stats) == FDIR_SUCCESS) {
                    printf("\nPort %u Queue %u Stats:\n", port_id, q);
                    fdir_packet_stats_print(&stats);
                }
            }
        }

        /* 打印匹配器统计 */
        RTE_ETH_FOREACH_DEV(port_id) {
            if (!(g_app_config.port_mask & (1u << port_id))) {
                continue;
            }

            if (g_app_config.enable_http_matcher) {
                fdir_pattern_matcher_print_stats(&g_http_matcher[port_id]);
            }

            if (g_app_config.enable_tls_matcher) {
                fdir_pattern_matcher_print_stats(&g_tls_matcher[port_id]);
            }
        }

        sleep(g_app_config.stats_interval);
    }

    return NULL;
}

/**
 * 数据包处理回调
 */
static void on_packet_process(struct fdir_packet_processor *proc,
                              struct fdir_packet_ctx *ctx)
{
    /* HTTP模式匹配 */
    if (g_app_config.enable_http_matcher && fdir_packet_is_tcp(ctx)) {
        struct fdir_http_result http_result;
        if (fdir_pattern_match_http(ctx, &http_result) == FDIR_SUCCESS) {
            printf("HTTP detected: Method=%s, URI=%s, Host=%s\n",
                   http_result.method_str, http_result.uri, http_result.host);
        }
    }

    /* TLS模式匹配 */
    if (g_app_config.enable_tls_matcher && fdir_packet_is_tcp(ctx)) {
        struct fdir_tls_result tls_result;
        if (fdir_pattern_match_tls(ctx, &tls_result) == FDIR_SUCCESS) {
            printf("TLS detected: Version=%s, Record=%s\n",
                   fdir_tls_version_to_string(tls_result.version),
                   fdir_tls_record_type_to_string(tls_result.record_type));
        }
    }
}

/**
 * 错误处理回调
 */
static int on_packet_error(struct fdir_packet_processor *proc,
                          int error_code, const char *error_msg)
{
    (void)error_code; /* 避免未使用参数警告 */
    printf("Packet processing error (Port %u Queue %u): %s\n",
           proc->port_id, proc->queue_id, error_msg);
    return FDIR_SUCCESS;
}