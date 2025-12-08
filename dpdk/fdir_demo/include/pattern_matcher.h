/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024
 */

#ifndef PATTERN_MATCHER_H
#define PATTERN_MATCHER_H

#include <stdint.h>
#include <stdbool.h>
#include <regex.h>
#include "fdir_config.h"
#include "packet_processor.h"

/* 模式匹配器类型 */
enum fdir_matcher_type {
    FDIR_MATCHER_HTTP = 0,            /* HTTP匹配器 */
    FDIR_MATCHER_TLS,                 /* TLS匹配器 */
    FDIR_MATCHER_REGEX,               /* 正则表达式匹配器 */
    FDIR_MATCHER_FIXED,               /* 固定字符串匹配器 */
    FDIR_MATCHER_WILDCARD,            /* 通配符匹配器 */
    FDIR_MATCHER_CUSTOM,              /* 自定义匹配器 */
    FDIR_MATCHER_MAX
};

/* HTTP方法枚举 */
enum fdir_http_method {
    FDIR_HTTP_METHOD_UNKNOWN = 0,
    FDIR_HTTP_METHOD_GET,
    FDIR_HTTP_METHOD_POST,
    FDIR_HTTP_METHOD_PUT,
    FDIR_HTTP_METHOD_DELETE,
    FDIR_HTTP_METHOD_HEAD,
    FDIR_HTTP_METHOD_OPTIONS,
    FDIR_HTTP_METHOD_PATCH,
    FDIR_HTTP_METHOD_CONNECT,
    FDIR_HTTP_METHOD_TRACE,
    FDIR_HTTP_METHOD_MAX
};

/* HTTP版本枚举 */
enum fdir_http_version {
    FDIR_HTTP_VERSION_UNKNOWN = 0,
    FDIR_HTTP_VERSION_1_0,
    FDIR_HTTP_VERSION_1_1,
    FDIR_HTTP_VERSION_2_0,
    FDIR_HTTP_VERSION_3_0,
    FDIR_HTTP_VERSION_MAX
};

/* TLS版本枚举 */
enum fdir_tls_version {
    FDIR_TLS_VERSION_UNKNOWN = 0,
    FDIR_TLS_VERSION_1_0,
    FDIR_TLS_VERSION_1_1,
    FDIR_TLS_VERSION_1_2,
    FDIR_TLS_VERSION_1_3,
    FDIR_TLS_VERSION_SSL_2_0,
    FDIR_TLS_VERSION_SSL_3_0,
    FDIR_TLS_VERSION_MAX
};

/* TLS记录类型 */
enum fdir_tls_record_type {
    FDIR_TLS_RECORD_CHANGE_CIPHER_SPEC = 20,
    FDIR_TLS_RECORD_ALERT = 21,
    FDIR_TLS_RECORD_HANDSHAKE = 22,
    FDIR_TLS_RECORD_APPLICATION_DATA = 23,
    FDIR_TLS_RECORD_MAX
};

/* TLS握手类型 */
enum fdir_tls_handshake_type {
    FDIR_TLS_HANDSHAKE_HELLO_REQUEST = 0,
    FDIR_TLS_HANDSHAKE_CLIENT_HELLO = 1,
    FDIR_TLS_HANDSHAKE_SERVER_HELLO = 2,
    FDIR_TLS_HANDSHAKE_CERTIFICATE = 11,
    FDIR_TLS_HANDSHAKE_SERVER_KEY_EXCHANGE = 12,
    FDIR_TLS_HANDSHAKE_CERTIFICATE_REQUEST = 13,
    FDIR_TLS_HANDSHAKE_SERVER_HELLO_DONE = 14,
    FDIR_TLS_HANDSHAKE_CERTIFICATE_VERIFY = 15,
    FDIR_TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE = 16,
    FDIR_TLS_HANDSHAKE_FINISHED = 20,
    FDIR_TLS_HANDSHAKE_MAX
};

/* HTTP匹配结果 */
struct fdir_http_result {
    enum fdir_http_method method;     /* HTTP方法 */
    enum fdir_http_version version;   /* HTTP版本 */
    char method_str[16];              /* HTTP方法字符串 */
    char uri[HTTP_URI_MAX_LEN];       /* URI */
    char host[HTTP_HOST_MAX_LEN];     /* Host头部 */
    char user_agent[256];             /* User-Agent */
    char content_type[128];           /* Content-Type */
    uint32_t content_length;          /* Content-Length */
    char referer[256];                /* Referer */
    char cookie[1024];                /* Cookie */
    char authorization[256];          /* Authorization */
    bool is_chunked;                  /* 是否分块传输 */
    bool is_websocket;                /* 是否WebSocket升级 */
    bool has_body;                    /* 是否有消息体 */
    uint16_t status_code;             /* 状态码（响应） */
};

/* TLS匹配结果 */
struct fdir_tls_result {
    enum fdir_tls_version version;    /* TLS版本 */
    enum fdir_tls_record_type record_type; /* 记录类型 */
    enum fdir_tls_handshake_type handshake_type; /* 握手类型 */
    char sni[TLS_SNI_MAX_LEN];        /* 服务器名称指示 */
    char cipher_suite[64];            /* 密码套件 */
    uint8_t session_id[32];           /* 会话ID */
    uint8_t session_id_len;           /* 会话ID长度 */
    uint16_t record_len;              /* 记录长度 */
    uint32_t cert_fingerprint[5];     /* 证书指纹 */
    bool is_resumption;               /* 是否会话恢复 */
    bool is_ocsp;                     /* 是否有OCSP */
    bool is_alpn;                     /* 是否有ALPN */
    char alpn_proto[16];              /* ALPN协议 */
};

/* 正则表达式模式 */
struct fdir_regex_pattern {
    char pattern[256];                /* 正则表达式 */
    char name[64];                    /* 模式名称 */
    bool case_sensitive;              /* 大小写敏感 */
    bool multiline;                   /* 多行模式 */
    bool dotall;                      /* 点匹配所有字符 */
    bool extended;                    /* 扩展模式 */
    regex_t regex;                    /* 编译后的正则表达式 */
    bool compiled;                    /* 是否已编译 */
};

/* 固定字符串模式 */
struct fdir_fixed_pattern {
    char pattern[256];                /* 固定字符串 */
    char name[64];                    /* 模式名称 */
    size_t pattern_len;               /* 模式长度 */
    size_t offset;                    /* 匹配偏移 */
    bool case_sensitive;              /* 大小写敏感 */
    bool exact_match;                 /* 精确匹配 */
};

/* 通配符模式 */
struct fdir_wildcard_pattern {
    char pattern[256];                /* 通配符表达式 */
    char name[64];                    /* 模式名称 */
    bool case_sensitive;              /* 大小写敏感 */
};

/* 模式匹配规则 */
struct fdir_match_rule {
    uint32_t rule_id;                 /* 规则ID */
    enum fdir_matcher_type type;      /* 匹配器类型 */
    char name[64];                    /* 规则名称 */
    char description[256];            /* 规则描述 */
    uint32_t priority;                /* 优先级 */
    bool enabled;                     /* 是否启用 */
    bool invert;                      /* 是否取反 */

    union {
        struct {
            enum fdir_http_method method; /* HTTP方法 */
            enum fdir_http_version version; /* HTTP版本 */
            char uri_pattern[256];         /* URI模式 */
            char host_pattern[256];        /* Host模式 */
            char header_pattern[1024];     /* 头部模式 */
        } http;

        struct {
            enum fdir_tls_version version; /* TLS版本 */
            enum fdir_tls_record_type record_type; /* 记录类型 */
            char sni_pattern[256];          /* SNI模式 */
            char cipher_pattern[256];       /* 密码套件模式 */
        } tls;

        struct fdir_regex_pattern regex;  /* 正则表达式 */
        struct fdir_fixed_pattern fixed;  /* 固定字符串 */
        struct fdir_wildcard_pattern wildcard; /* 通配符 */

        struct {
            int (*match_func)(const uint8_t *data, uint16_t len,
                            void *user_data);
            void *user_data;
        } custom;
    } pattern;

    /* 匹配结果处理 */
    struct {
        uint16_t queue;                 /* 目标队列 */
        uint32_t mark;                  /* 标记值 */
        bool drop;                      /* 丢弃包 */
        bool log;                       /* 记录日志 */
        char log_msg[256];              /* 日志消息 */
    } action;
};

/* 模式匹配器 */
struct fdir_pattern_matcher {
    enum fdir_matcher_type type;      /* 匹配器类型 */
    struct fdir_match_rule *rules;    /* 规则数组 */
    uint32_t rule_count;              /* 规则数量 */
    uint32_t max_rules;               /* 最大规则数 */
    pthread_rwlock_t lock;            /* 读写锁 */
    bool initialized;                 /* 是否已初始化 */

    /* 统计信息 */
    struct {
        uint64_t total_matches;       /* 总匹配次数 */
        uint64_t total_packets;       /* 总处理包数 */
        uint64_t type_matches[FDIR_MATCHER_MAX]; /* 类型匹配次数 */
        uint64_t rule_matches[FDIR_MATCHER_MAX]; /* 规则匹配次数 */
        double avg_match_time;        /* 平均匹配时间（微秒） */
    } stats;
};

/* 函数声明 */

/* 初始化和清理 */
int fdir_pattern_matcher_init(struct fdir_pattern_matcher *matcher,
                             enum fdir_matcher_type type,
                             uint32_t max_rules);
int fdir_pattern_matcher_cleanup(struct fdir_pattern_matcher *matcher);

/* 规则管理 */
int fdir_pattern_matcher_add_rule(struct fdir_pattern_matcher *matcher,
                                 const struct fdir_match_rule *rule);
int fdir_pattern_matcher_del_rule(struct fdir_pattern_matcher *matcher,
                                 uint32_t rule_id);
int fdir_pattern_matcher_update_rule(struct fdir_pattern_matcher *matcher,
                                    const struct fdir_match_rule *rule);
int fdir_pattern_matcher_get_rule(struct fdir_pattern_matcher *matcher,
                                 uint32_t rule_id,
                                 struct fdir_match_rule *rule);
int fdir_pattern_matcher_list_rules(struct fdir_pattern_matcher *matcher,
                                   struct fdir_match_rule *rules,
                                   uint32_t *count);

/* 模式匹配 */
int fdir_pattern_match(struct fdir_pattern_matcher *matcher,
                      struct fdir_packet_ctx *ctx,
                      struct fdir_match_rule **matched_rule);
int fdir_pattern_match_http(struct fdir_packet_ctx *ctx,
                           struct fdir_http_result *result);
int fdir_pattern_match_tls(struct fdir_packet_ctx *ctx,
                          struct fdir_tls_result *result);
int fdir_pattern_match_regex(struct fdir_packet_ctx *ctx,
                            const struct fdir_regex_pattern *pattern,
                            bool *matched);
int fdir_pattern_match_fixed(struct fdir_packet_ctx *ctx,
                            const struct fdir_fixed_pattern *pattern,
                            bool *matched);
int fdir_pattern_match_wildcard(struct fdir_packet_ctx *ctx,
                               const struct fdir_wildcard_pattern *pattern,
                               bool *matched);

/* HTTP解析 */
int fdir_http_parse_request(const uint8_t *data, uint16_t len,
                           struct fdir_http_result *result);
int fdir_http_parse_response(const uint8_t *data, uint16_t len,
                            struct fdir_http_result *result);
int fdir_http_parse_header(const char *header_line, char *name,
                          char *value, size_t value_len);
enum fdir_http_method fdir_http_parse_method(const char *method_str);
enum fdir_http_version fdir_http_parse_version(const char *version_str);
int fdir_http_parse_uri(const char *uri_str, char *path, char *query,
                       char *fragment);

/* TLS解析 */
int fdir_tls_parse_record(const uint8_t *data, uint16_t len,
                         struct fdir_tls_result *result);
int fdir_tls_parse_handshake(const uint8_t *data, uint16_t len,
                            struct fdir_tls_result *result);
int fdir_tls_parse_client_hello(const uint8_t *data, uint16_t len,
                               struct fdir_tls_result *result);
int fdir_tls_parse_server_hello(const uint8_t *data, uint16_t len,
                               struct fdir_tls_result *result);
int fdir_tls_extract_sni(const uint8_t *data, uint16_t len, char *sni);
enum fdir_tls_version fdir_tls_get_version(uint16_t version);

/* 批量匹配 */
int fdir_pattern_match_batch(struct fdir_pattern_matcher *matcher,
                            struct fdir_packet_batch *batch,
                            uint32_t *match_count);

/* 统计结构 */
struct fdir_pattern_matcher_stats {
    uint64_t total_matches;       /* 总匹配次数 */
    uint64_t total_packets;       /* 总处理包数 */
    double avg_match_time;        /* 平均匹配时间（微秒） */
};

/* 统计管理 */
int fdir_pattern_matcher_get_stats(struct fdir_pattern_matcher *matcher,
                                  struct fdir_pattern_matcher_stats *stats);
int fdir_pattern_matcher_reset_stats(struct fdir_pattern_matcher *matcher);
void fdir_pattern_matcher_print_stats(const struct fdir_pattern_matcher *matcher);

/* 工具函数 */
const char *fdir_matcher_type_to_string(enum fdir_matcher_type type);
const char *fdir_http_method_to_string(enum fdir_http_method method);
const char *fdir_http_version_to_string(enum fdir_http_version version);
const char *fdir_tls_version_to_string(enum fdir_tls_version version);
const char *fdir_tls_record_type_to_string(enum fdir_tls_record_type type);
const char *fdir_tls_handshake_type_to_string(enum fdir_tls_handshake_type type);
enum fdir_http_method fdir_string_to_http_method(const char *str);
enum fdir_tls_version fdir_string_to_tls_version(const char *str);

/* 模式编译 */
int fdir_regex_compile(struct fdir_regex_pattern *pattern);
void fdir_regex_free(struct fdir_regex_pattern *pattern);
int fdir_wildcard_compile(const char *pattern, char *regex);
bool fdir_wildcard_match(const char *pattern, const char *str,
                        bool case_sensitive);

/* 调试函数 */
#if FDIR_DEBUG
void fdir_http_print_result(const struct fdir_http_result *result);
void fdir_tls_print_result(const struct fdir_tls_result *result);
void fdir_pattern_print_rule(const struct fdir_match_rule *rule);
#endif

#endif /* PATTERN_MATCHER_H */