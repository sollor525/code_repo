/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024
 */

#ifndef FDIR_CONFIG_H
#define FDIR_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

/* FDIR最大配置 */
#define FDIR_MAX_FLOWS           1024    /* 最大flow规则数 */
#define FDIR_MAX_QUEUES          16      /* 最大队列数 */
#define FDIR_MAX_NAME_LEN        64      /* 规则名称最大长度 */
#define FDIR_MAX_DESC_LEN        256     /* 规则描述最大长度 */
#define FDIR_MAX_RULES_PER_FILE  1000    /* 每个配置文件最大规则数 */
#define FDIR_MAX_CONFIG_LINE     1024    /* 配置文件行最大长度 */

/* 默认配置 */
#define FDIR_DEFAULT_RX_QUEUES   8       /* 默认接收队列数 */
#define FDIR_DEFAULT_TX_QUEUES   8       /* 默认发送队列数 */
#define FDIR_DEFAULT_BURST_SIZE  32      /* 默认批处理大小 */
#define FDIR_DEFAULT_MBUF_SIZE   2048    /* 默认mbuf大小 */
#define FDIR_DEFAULT_MBUF_CACHE  250     /* 默认mbuf缓存大小 */
#define FDIR_DEFAULT_RING_SIZE   2048    /* 默认ring大小 */

/* 端口配置 */
#define FDIR_MAX_PORTS           4       /* 最大端口数 */
#define FDIR_DEFAULT_PORT        0       /* 默认端口ID */

/* 统计信息 */
#define FDIR_STATS_INTERVAL      1       /* 统计间隔（秒） */
#define FDIR_STATS_HISTORY_SIZE  60      /* 统计历史记录大小 */

/* 调试 */
#define FDIR_DEBUG               0       /* 调试开关 */

/* 常用端口定义 */
#define HTTP_PORT                80      /* HTTP端口 */
#define HTTPS_PORT               443     /* HTTPS端口 */
#define HTTP_ALT_PORT            8080    /* HTTP备用端口 */
#define HTTPS_ALT_PORT           8443    /* HTTPS备用端口 */
#define DNS_PORT                 53      /* DNS端口 */
#define NTP_PORT                 123     /* NTP端口 */

/* 协议类型 - 使用系统定义 */
#ifndef IPPROTO_TCP
#define IPPROTO_TCP              6       /* TCP协议 */
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP              17      /* UDP协议 */
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP             1       /* ICMP协议 */
#endif
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6             41      /* IPv6封装 */
#endif

/* VLAN相关 */
#define VLAN_TCI_MASK            0xFFF   /* VLAN ID掩码 */
#define VLAN_MAX_ID              4094    /* 最大VLAN ID */

/* IPv4地址相关 */
#define IPV4_ADDR_LEN            4       /* IPv4地址长度 */
#define IPV4_ADDR_STR_LEN        16      /* IPv4地址字符串长度 */

/* IPv6地址相关 */
#define IPV6_ADDR_LEN            16      /* IPv6地址长度 */
#define IPV6_ADDR_STR_LEN        46      /* IPv6地址字符串长度 */

/* MAC地址相关 */
#define MAC_ADDR_LEN             6       /* MAC地址长度 */
#define MAC_ADDR_STR_LEN         18      /* MAC地址字符串长度 */

/* 错误码定义 */
#define FDIR_SUCCESS             0       /* 成功 */
#define FDIR_ERROR              -1       /* 一般错误 */
#define FDIR_INVALID_PARAM      -2       /* 无效参数 */
#define FDIR_NO_MEMORY          -3       /* 内存不足 */
#define FDIR_NOT_FOUND          -4       /* 未找到 */
#define FDIR_ALREADY_EXISTS     -5       /* 已存在 */
#define FDIR_PERMISSION_DENIED  -6       /* 权限拒绝 */
#define FDIR_TIMEOUT            -7       /* 超时 */
#define FDIR_NOT_SUPPORTED      -8       /* 不支持 */
#define FDIR_NO_BUFFER          -9       /* 无缓冲区 */

/* 日志级别 */
#define FDIR_LOG_LEVEL_EMERG     0       /* 紧急 */
#define FDIR_LOG_LEVEL_ALERT     1       /* 警报 */
#define FDIR_LOG_LEVEL_CRIT      2       /* 严重 */
#define FDIR_LOG_LEVEL_ERR       3       /* 错误 */
#define FDIR_LOG_LEVEL_WARNING   4       /* 警告 */
#define FDIR_LOG_LEVEL_NOTICE    5       /* 通知 */
#define FDIR_LOG_LEVEL_INFO      6       /* 信息 */
#define FDIR_LOG_LEVEL_DEBUG     7       /* 调试 */

/* 功能开关 */
#define FDIR_ENABLE_IPV6         1       /* 启用IPv6支持 */
#define FDIR_ENABLE_VLAN         1       /* 启用VLAN支持 */
#define FDIR_ENABLE_HTTP         1       /* 启用HTTP识别 */
#define FDIR_ENABLE_TLS          1       /* 启用TLS识别 */
#define FDIR_ENABLE_DPI          1       /* 启用深度包检测 */
#define FDIR_ENABLE_STATS        1       /* 启用统计功能 */
#define FDIR_ENABLE_MONITOR      1       /* 启用监控功能 */

/* 性能调优 */
#define FDIR_PREFETCH_OFFSET     2       /* 预取偏移 */
#define FDIR_BATCH_SIZE          64      /* 批处理大小 */
#define FDIR_MAX_BATCH_SIZE      128     /* 最大批处理大小 */

/* 模式匹配 */
#define HTTP_METHOD_MAX_LEN      8       /* HTTP方法最大长度 */
#define HTTP_HOST_MAX_LEN        256     /* HTTP Host最大长度 */
#define HTTP_URI_MAX_LEN         1024    /* HTTP URI最大长度 */
#define TLS_SNI_MAX_LEN          256     /* TLS SNI最大长度 */

/* 线程相关 */
#define FDIR_MAX_THREADS         16      /* 最大线程数 */
#define FDIR_THREAD_STACK_SIZE   1048576 /* 线程栈大小 */

#endif /* FDIR_CONFIG_H */