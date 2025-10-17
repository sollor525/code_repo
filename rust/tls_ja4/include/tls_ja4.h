/**
 * TLS JA4/JA3 Fingerprint Extractor C API
 *
 * 高性能TLS指纹提取库，支持VPP集成
 *
 * 设计特点：
 * - 线程私有，无需加锁
 * - 零拷贝，高性能
 * - 支持TCP payload直接分析
 * - 兼容VPP多worker线程架构
 */

#ifndef TLS_JA4_H
#define TLS_JA4_H

#ifdef __cplusplus
extern "C" {
#endif

/* 返回状态码定义 */
#define TLS_JA4_SUCCESS                   0   /* 成功，指纹计算完成 */
#define TLS_JA4_NOT_TLS                  -1  /* 非TLS报文 */
#define TLS_JA4_NOT_CLIENT_HELLO         -2  /* TLS报文但不是Client Hello */
#define TLS_JA4_SEGMENT_CACHED           -3  /* TCP分段已缓存，等待更多数据 */
#define TLS_JA4_INVALID_PACKET           -4  /* 无效报文格式 */
#define TLS_JA4_INSUFFICIENT_DATA        -5  /* 数据不足，无法分析 */
#define TLS_JA4_MEMORY_ERROR             -6  /* 内存分配错误 */
#define TLS_JA4_INVALID_PARAMETER        -7  /* 无效参数 */
#define TLS_JA4_CONTEXT_ERROR            -8  /* 上下文初始化错误 */
#define TLS_JA4_CACHE_OVERFLOW           -9  /* TCP缓存溢出，已清理 */
#define TLS_JA4_CACHE_TIMEOUT            -10 /* TCP缓存超时，已清理 */
#define TLS_JA4_IPV6_NOT_SUPPORTED       -11 /* IPv6暂不支持 */
#define TLS_JA4_TCP_REASSEMBLY_FAILED    -12 /* TCP重组失败 */

/* 前向声明 */
typedef struct TlsJa4Context TlsJa4Context;
typedef struct TlsJa4Result TlsJa4Result;
typedef struct TlsJa3Result TlsJa3Result;
typedef struct TlsJa4Fingerprint TlsJa4Fingerprint;

/* 指纹结果结构体 */
struct TlsJa4Fingerprint {
    char fingerprint[64];      /* 指纹，固定长度缓冲区 */
    unsigned int fingerprint_len; /* 指纹实际长度 */
    unsigned short tls_version;   /* TLS版本 */
    unsigned short cipher_count;  /* 密码套件数量 */
    unsigned short extension_count; /* 扩展数量 */
};

/* JA3分析结果结构体 */
struct TlsJa3Result {
    TlsJa4Fingerprint fingerprint; /* JA3指纹数据 */
    unsigned char is_client_hello; /* 是否为Client Hello */
    unsigned char is_complete;     /* 分析是否完成 */
    int status_code;               /* 返回状态码 */
    unsigned long timestamp;       /* 时间戳（毫秒） */
};

/* JA4分析结果结构体 */
struct TlsJa4Result {
    TlsJa4Fingerprint fingerprint; /* JA4指纹数据 */
    unsigned char is_client_hello; /* 是否为Client Hello */
    unsigned char is_complete;     /* 分析是否完成 */
    int status_code;               /* 返回状态码 */
    unsigned long timestamp;       /* 时间戳（毫秒） */
    unsigned char is_match;        /* JA4指纹是否匹配数据库中的条目（1=匹配，0=不匹配） */
};

/* TLS会话信息，用于分段处理 */
struct TlsJa4Session {
    unsigned char src_ip[16];     /* IPv4或IPv6源地址 */
    unsigned char dst_ip[16];     /* IPv4或IPv6目的地址 */
    unsigned short src_port;      /* 源端口 */
    unsigned short dst_port;      /* 目的端口 */
    unsigned char is_client_to_server; /* 数据方向：1=客户端到服务器，0=服务器到客户端 */
    unsigned int sequence;        /* TCP序列号 */
    const unsigned char* payload; /* TCP载荷数据 */
    unsigned int payload_len;     /* 载荷长度 */
};

/* 上下文结构体（线程私有，维护分段缓存） */
struct TlsJa4Context {
    void* _internal; /* 内部状态，用于分段重组和缓存管理 */
};

/**
 * 初始化TLS上下文（线程私有）
 * @return 上下文指针，失败返回NULL
 */
TlsJa4Context* tls_init(void);

/**
 * 检测是否为TLS报文
 * @param tcp_payload TCP载荷数据
 * @param payload_len 载荷长度
 * @return 状态码：TLS_JA4_SUCCESS(是TLS), TLS_JA4_NOT_TLS(非TLS)
 */
int tls_is_tls_packet(
    const unsigned char* tcp_payload,
    unsigned int payload_len
);

/**
 * 检测是否为Client Hello报文
 * @param tcp_payload TCP载荷数据
 * @param payload_len 载荷长度
 * @return 状态码：TLS_JA4_SUCCESS(是Client Hello), TLS_JA4_NOT_CLIENT_HELLO(非Client Hello)
 */
int tls_is_client_hello(
    const unsigned char* tcp_payload,
    unsigned int payload_len
);

/**
 * 计算JA3指纹（仅TCP载荷）
 * @param tls_payload TLS载荷数据（TCP载荷中的TLS部分）
 * @param payload_len 载荷长度
 * @param result JA3结果输出
 * @return 状态码：TLS_JA4_SUCCESS(成功), TLS_JA4_NOT_TLS(非TLS), TLS_JA4_NOT_CLIENT_HELLO(非Client Hello)
 */
int tls_calculate_ja3(
    const unsigned char* tls_payload,
    unsigned int payload_len,
    TlsJa3Result* result
);

/**
 * 计算JA4指纹（仅TCP载荷）
 * @param tls_payload TLS载荷数据（TCP载荷中的TLS部分）
 * @param payload_len 载荷长度
 * @param result JA4结果输出
 * @return 状态码：TLS_JA4_SUCCESS(成功), TLS_JA4_NOT_TLS(非TLS), TLS_JA4_NOT_CLIENT_HELLO(非Client Hello)
 */
int tls_calculate_ja4(
    const unsigned char* tls_payload,
    unsigned int payload_len,
    TlsJa4Result* result
);


/**
 * 清理TLS上下文
 * @param ctx 上下文指针
 */
void tls_cleanup(TlsJa4Context* ctx);

/**
 * 设置TCP缓存限制
 * @param ctx 上下文指针
 * @param max_flows 最大流数量
 * @param max_bytes_per_flow 每个流最大字节数
 * @param timeout_ms 超时时间（毫秒）
 * @return 0表示成功，负数表示错误
 */
int tls_ja4_set_cache_limits(
    TlsJa4Context* ctx,
    unsigned int max_flows,
    unsigned int max_bytes_per_flow,
    unsigned int timeout_ms
);

/**
 * 清理超时的TCP缓存
 * @param ctx 上下文指针
 * @param current_time_ms 当前时间（毫秒）
 * @return 清理的流数量
 */
unsigned int tls_ja4_cleanup_timeout_cache(
    TlsJa4Context* ctx,
    unsigned long current_time_ms
);

/**
 * 获取缓存统计信息
 * @param ctx 上下文指针
 * @param active_flows 活跃流数量（输出）
 * @param total_cached_bytes 总缓存字节数（输出）
 * @return 0表示成功，负数表示错误
 */
int tls_ja4_get_cache_stats(
    TlsJa4Context* ctx,
    unsigned int* active_flows,
    unsigned int* total_cached_bytes
);




#ifdef __cplusplus
}
#endif

#endif /* TLS_JA4_H */
