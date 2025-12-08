/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <regex.h>
#include "pattern_matcher.h"
#include "dpdk_utils.h"

/**
 * 初始化模式匹配器
 */
int fdir_pattern_matcher_init(struct fdir_pattern_matcher *matcher,
                             enum fdir_matcher_type type,
                             uint32_t max_rules)
{
    if (!matcher || max_rules == 0) {
        return FDIR_INVALID_PARAM;
    }

    memset(matcher, 0, sizeof(*matcher));
    matcher->type = type;
    matcher->max_rules = max_rules;

    /* 分配规则数组 */
    matcher->rules = (struct fdir_match_rule *)rte_zmalloc(
        "pattern_rules", max_rules * sizeof(struct fdir_match_rule), 0);
    if (!matcher->rules) {
        return FDIR_NO_MEMORY;
    }

    /* 初始化读写锁 */
    if (pthread_rwlock_init(&matcher->lock, NULL) != 0) {
        rte_free(matcher->rules);
        return FDIR_ERROR;
    }

    matcher->initialized = true;

    printf("Pattern matcher initialized: type=%s, max_rules=%u\n",
           fdir_matcher_type_to_string(type), max_rules);

    return FDIR_SUCCESS;
}

/**
 * 清理模式匹配器
 */
int fdir_pattern_matcher_cleanup(struct fdir_pattern_matcher *matcher)
{
    if (!matcher || !matcher->initialized) {
        return FDIR_INVALID_PARAM;
    }

    /* 清理正则表达式 */
    for (uint32_t i = 0; i < matcher->rule_count; i++) {
        if (matcher->rules[i].type == FDIR_MATCHER_REGEX &&
            matcher->rules[i].pattern.regex.compiled) {
            regfree(&matcher->rules[i].pattern.regex.regex);
        }
    }

    /* 销毁读写锁 */
    pthread_rwlock_destroy(&matcher->lock);

    /* 释放内存 */
    rte_free(matcher->rules);

    memset(matcher, 0, sizeof(*matcher));

    return FDIR_SUCCESS;
}

/**
 * 添加规则
 */
int fdir_pattern_matcher_add_rule(struct fdir_pattern_matcher *matcher,
                                 const struct fdir_match_rule *rule)
{
    if (!matcher || !rule || !matcher->initialized) {
        return FDIR_INVALID_PARAM;
    }

    if (matcher->rule_count >= matcher->max_rules) {
        return FDIR_NO_MEMORY;
    }

    pthread_rwlock_wrlock(&matcher->lock);

    /* 复制规则 */
    rte_memcpy(&matcher->rules[matcher->rule_count], rule, sizeof(*rule));

    /* 编译正则表达式 */
    if (rule->type == FDIR_MATCHER_REGEX) {
        int ret = regcomp(&matcher->rules[matcher->rule_count].pattern.regex.regex,
                         rule->pattern.regex.pattern,
                         REG_EXTENDED | (rule->pattern.regex.case_sensitive ? 0 : REG_ICASE));
        if (ret != 0) {
            pthread_rwlock_unlock(&matcher->lock);
            char error_msg[256];
            regerror(ret, &rule->pattern.regex.regex, error_msg, sizeof(error_msg));
            printf("Error: Failed to compile regex: %s\n", error_msg);
            return FDIR_ERROR;
        }
        matcher->rules[matcher->rule_count].pattern.regex.compiled = true;
    }

    matcher->rule_count++;

    pthread_rwlock_unlock(&matcher->lock);

    printf("Pattern rule added: ID=%u, Type=%s\n",
           rule->rule_id, fdir_matcher_type_to_string(rule->type));

    return FDIR_SUCCESS;
}

/**
 * 匹配模式
 */
int fdir_pattern_match(struct fdir_pattern_matcher *matcher,
                      struct fdir_packet_ctx *ctx,
                      struct fdir_match_rule **matched_rule)
{
    if (!matcher || !ctx || !matcher->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_rdlock(&matcher->lock);

    /* 检查是否有规则 */
    if (matcher->rule_count == 0) {
        pthread_rwlock_unlock(&matcher->lock);
        return FDIR_NOT_FOUND;
    }

    /* 更新统计 */
    matcher->stats.total_packets++;

    /* 匹配规则 */
    for (uint32_t i = 0; i < matcher->rule_count; i++) {
        if (!matcher->rules[i].enabled) {
            continue;
        }

        bool matched = false;
        uint64_t start_time = fdir_get_tsc_cycles();

        switch (matcher->rules[i].type) {
        case FDIR_MATCHER_HTTP:
            matched = fdir_pattern_match_http(ctx, NULL) == FDIR_SUCCESS;
            break;

        case FDIR_MATCHER_TLS:
            matched = fdir_pattern_match_tls(ctx, NULL) == FDIR_SUCCESS;
            break;

        case FDIR_MATCHER_FIXED:
            matched = fdir_pattern_match_fixed(ctx, &matcher->rules[i].pattern.fixed,
                                              &matched) == FDIR_SUCCESS;
            break;

        case FDIR_MATCHER_WILDCARD:
            matched = fdir_pattern_match_wildcard(ctx, &matcher->rules[i].pattern.wildcard,
                                                 &matched) == FDIR_SUCCESS;
            break;

        default:
            break;
        }

        /* 更新匹配时间统计 */
        double match_time = fdir_cycles_to_usec(fdir_get_tsc_cycles() - start_time);
        matcher->stats.avg_match_time = (matcher->stats.avg_match_time * (matcher->stats.total_matches) +
                                        match_time) / (matcher->stats.total_matches + 1);

        if (matched) {
            matcher->stats.total_matches++;
            if (matcher->rules[i].type < FDIR_MATCHER_MAX) {
                matcher->stats.type_matches[matcher->rules[i].type]++;
            }

            if (matched_rule) {
                *matched_rule = &matcher->rules[i];
            }

            pthread_rwlock_unlock(&matcher->lock);
            return FDIR_SUCCESS;
        }
    }

    pthread_rwlock_unlock(&matcher->lock);

    return FDIR_NOT_FOUND;
}

/**
 * 匹配HTTP
 */
int fdir_pattern_match_http(struct fdir_packet_ctx *ctx,
                           struct fdir_http_result *result)
{
    if (!ctx || !ctx->app_data || ctx->app_data_len < 4) {
        return FDIR_NOT_FOUND;
    }

    /* 简单检测HTTP方法 */
    const char *data = (const char *)ctx->app_data;

    if (strncmp(data, "GET ", 4) == 0 ||
        strncmp(data, "POST", 4) == 0 ||
        strncmp(data, "PUT ", 4) == 0 ||
        strncmp(data, "HEAD", 4) == 0 ||
        strncmp(data, "DELE", 4) == 0 ||
        strncmp(data, "OPTI", 4) == 0 ||
        strncmp(data, "PATC", 4) == 0 ||
        strncmp(data, "CONN", 4) == 0 ||
        strncmp(data, "TRAC", 4) == 0) {

        if (result) {
            memset(result, 0, sizeof(*result));

            /* 解析HTTP方法 */
            if (strncmp(data, "GET ", 4) == 0) {
                result->method = FDIR_HTTP_METHOD_GET;
                strncpy(result->method_str, "GET", sizeof(result->method_str) - 1);
            } else if (strncmp(data, "POST", 4) == 0) {
                result->method = FDIR_HTTP_METHOD_POST;
                strncpy(result->method_str, "POST", sizeof(result->method_str) - 1);
            } else if (strncmp(data, "PUT ", 4) == 0) {
                result->method = FDIR_HTTP_METHOD_PUT;
                strncpy(result->method_str, "PUT", sizeof(result->method_str) - 1);
            } else if (strncmp(data, "HEAD", 4) == 0) {
                result->method = FDIR_HTTP_METHOD_HEAD;
                strncpy(result->method_str, "HEAD", sizeof(result->method_str) - 1);
            } else {
                result->method = FDIR_HTTP_METHOD_UNKNOWN;
                strncpy(result->method_str, "UNKNOWN", sizeof(result->method_str) - 1);
            }

            /* 简单解析URI */
            const char *uri_start = strchr(data, ' ');
            if (uri_start) {
                uri_start++;
                const char *uri_end = strchr(uri_start, ' ');
                if (uri_end) {
                    size_t uri_len = uri_end - uri_start;
                    if (uri_len < sizeof(result->uri)) {
                        strncpy(result->uri, uri_start, uri_len);
                        result->uri[uri_len] = '\0';
                    }
                }
            }

            /* 简单解析Host */
            const char *host_str = strcasestr(data, "Host:");
            if (host_str) {
                host_str += 5;
                while (*host_str == ' ') host_str++;
                const char *host_end = strchr(host_str, '\r');
                if (!host_end) host_end = strchr(host_str, '\n');
                if (host_end) {
                    size_t host_len = host_end - host_str;
                    if (host_len < sizeof(result->host)) {
                        strncpy(result->host, host_str, host_len);
                        result->host[host_len] = '\0';
                    }
                }
            }
        }

        return FDIR_SUCCESS;
    }

    return FDIR_NOT_FOUND;
}

/**
 * 匹配TLS
 */
int fdir_pattern_match_tls(struct fdir_packet_ctx *ctx,
                          struct fdir_tls_result *result)
{
    if (!ctx || !ctx->app_data || ctx->app_data_len < 3) {
        return FDIR_NOT_FOUND;
    }

    const uint8_t *data = ctx->app_data;

    /* TLS记录层格式：
     * 0x16: Handshake类型
     * 0x03: 版本号高字节
     * 0xXX: 版本号低字节 (0x00-0x03)
     */
    if (data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x03) {
        if (result) {
            memset(result, 0, sizeof(*result));

            /* 解析版本 */
            switch (data[2]) {
            case 0x00:
                result->version = FDIR_TLS_VERSION_SSL_3_0;
                break;
            case 0x01:
                result->version = FDIR_TLS_VERSION_1_0;
                break;
            case 0x02:
                result->version = FDIR_TLS_VERSION_1_1;
                break;
            case 0x03:
                result->version = FDIR_TLS_VERSION_1_2;
                break;
            default:
                result->version = FDIR_TLS_VERSION_UNKNOWN;
                break;
            }

            /* 解析记录类型 */
            result->record_type = FDIR_TLS_RECORD_HANDSHAKE;

            /* 简单解析握手类型 */
            if (ctx->app_data_len >= 6 && data[5] == 0x01) {
                result->handshake_type = FDIR_TLS_HANDSHAKE_CLIENT_HELLO;
            } else if (ctx->app_data_len >= 6 && data[5] == 0x02) {
                result->handshake_type = FDIR_TLS_HANDSHAKE_SERVER_HELLO;
            }

            /* 简单解析记录长度 */
            if (ctx->app_data_len >= 5) {
                result->record_len = (data[3] << 8) | data[4];
            }

            /* TODO: 解析SNI等扩展 */
        }

        return FDIR_SUCCESS;
    }

    return FDIR_NOT_FOUND;
}

/**
 * 匹配固定字符串
 */
int fdir_pattern_match_fixed(struct fdir_packet_ctx *ctx,
                            const struct fdir_fixed_pattern *pattern,
                            bool *matched)
{
    if (!ctx || !pattern || !matched || !ctx->app_data) {
        return FDIR_INVALID_PARAM;
    }

    *matched = false;

    if (ctx->app_data_len < pattern->offset + pattern->pattern_len) {
        return FDIR_SUCCESS; /* 数据太短，不匹配 */
    }

    const char *data = (const char *)ctx->app_data + pattern->offset;

    if (pattern->case_sensitive) {
        if (strncmp(data, pattern->pattern, pattern->pattern_len) == 0) {
            *matched = true;
        }
    } else {
        if (strncasecmp(data, pattern->pattern, pattern->pattern_len) == 0) {
            *matched = true;
        }
    }

    return FDIR_SUCCESS;
}

/**
 * 匹配通配符
 */
int fdir_pattern_match_wildcard(struct fdir_packet_ctx *ctx,
                               const struct fdir_wildcard_pattern *pattern,
                               bool *matched)
{
    if (!ctx || !pattern || !matched || !ctx->app_data) {
        return FDIR_INVALID_PARAM;
    }

    *matched = false;

    /* 简单的通配符匹配实现
     * 支持 * 和 ? 通配符
     */
    const char *data = (const char *)ctx->app_data;
    const char *pattern_str = pattern->pattern;
    const char *data_ptr = data;
    const char *pattern_ptr = pattern_str;

    while (*pattern_ptr && *data_ptr) {
        if (*pattern_ptr == '*') {
            /* 跳过所有 * */
            while (*pattern_ptr == '*') {
                pattern_ptr++;
            }

            /* 如果模式结束，匹配所有剩余数据 */
            if (*pattern_ptr == '\0') {
                *matched = true;
                return FDIR_SUCCESS;
            }

            /* 查找下一个匹配字符 */
            while (*data_ptr && *data_ptr != *pattern_ptr) {
                data_ptr++;
            }
        } else if (*pattern_ptr == '?') {
            /* 匹配任意单个字符 */
            data_ptr++;
            pattern_ptr++;
        } else {
            /* 精确匹配 */
            if (pattern->case_sensitive) {
                if (*data_ptr != *pattern_ptr) {
                    break;
                }
            } else {
                if (tolower(*data_ptr) != tolower(*pattern_ptr)) {
                    break;
                }
            }
            data_ptr++;
            pattern_ptr++;
        }
    }

    /* 如果都到达末尾，匹配成功 */
    if (*pattern_ptr == '\0' && *data_ptr == '\0') {
        *matched = true;
    }

    return FDIR_SUCCESS;
}

/**
 * 获取统计信息
 */
int fdir_pattern_matcher_get_stats(struct fdir_pattern_matcher *matcher,
                                  struct fdir_pattern_matcher_stats *stats)
{
    if (!matcher || !stats || !matcher->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_rdlock(&matcher->lock);

    stats->total_matches = matcher->stats.total_matches;
    stats->total_packets = matcher->stats.total_packets;
    stats->avg_match_time = matcher->stats.avg_match_time;

    pthread_rwlock_unlock(&matcher->lock);

    return FDIR_SUCCESS;
}

/**
 * 重置统计信息
 */
int fdir_pattern_matcher_reset_stats(struct fdir_pattern_matcher *matcher)
{
    if (!matcher || !matcher->initialized) {
        return FDIR_INVALID_PARAM;
    }

    pthread_rwlock_wrlock(&matcher->lock);

    memset(&matcher->stats, 0, sizeof(matcher->stats));

    pthread_rwlock_unlock(&matcher->lock);

    return FDIR_SUCCESS;
}

/**
 * 打印统计信息
 */
void fdir_pattern_matcher_print_stats(const struct fdir_pattern_matcher *matcher)
{
    if (!matcher) {
        return;
    }

    printf("\n=== Pattern Matcher Stats ===\n");
    printf("Type: %s\n", fdir_matcher_type_to_string(matcher->type));
    printf("Total Rules: %u\n", matcher->rule_count);
    printf("Total Matches: %lu\n", matcher->stats.total_matches);
    printf("Total Packets: %lu\n", matcher->stats.total_packets);
    printf("Avg Match Time: %.2f us\n", matcher->stats.avg_match_time);

    printf("\nType Matches:\n");
    printf("  HTTP: %lu\n", matcher->stats.type_matches[FDIR_MATCHER_HTTP]);
    printf("  TLS: %lu\n", matcher->stats.type_matches[FDIR_MATCHER_TLS]);
    printf("  Regex: %lu\n", matcher->stats.type_matches[FDIR_MATCHER_REGEX]);
    printf("  Fixed: %lu\n", matcher->stats.type_matches[FDIR_MATCHER_FIXED]);
    printf("  Wildcard: %lu\n", matcher->stats.type_matches[FDIR_MATCHER_WILDCARD]);
    printf("==============================\n\n");
}

/* 工具函数 */

/**
 * 匹配器类型转字符串
 */
const char *fdir_matcher_type_to_string(enum fdir_matcher_type type)
{
    switch (type) {
    case FDIR_MATCHER_HTTP:
        return "HTTP";
    case FDIR_MATCHER_TLS:
        return "TLS";
    case FDIR_MATCHER_REGEX:
        return "Regex";
    case FDIR_MATCHER_FIXED:
        return "Fixed";
    case FDIR_MATCHER_WILDCARD:
        return "Wildcard";
    case FDIR_MATCHER_CUSTOM:
        return "Custom";
    default:
        return "Unknown";
    }
}

/**
 * HTTP方法转字符串
 */
const char *fdir_http_method_to_string(enum fdir_http_method method)
{
    switch (method) {
    case FDIR_HTTP_METHOD_GET:
        return "GET";
    case FDIR_HTTP_METHOD_POST:
        return "POST";
    case FDIR_HTTP_METHOD_PUT:
        return "PUT";
    case FDIR_HTTP_METHOD_DELETE:
        return "DELETE";
    case FDIR_HTTP_METHOD_HEAD:
        return "HEAD";
    case FDIR_HTTP_METHOD_OPTIONS:
        return "OPTIONS";
    case FDIR_HTTP_METHOD_PATCH:
        return "PATCH";
    case FDIR_HTTP_METHOD_CONNECT:
        return "CONNECT";
    case FDIR_HTTP_METHOD_TRACE:
        return "TRACE";
    default:
        return "Unknown";
    }
}

/**
 * HTTP版本转字符串
 */
const char *fdir_http_version_to_string(enum fdir_http_version version)
{
    switch (version) {
    case FDIR_HTTP_VERSION_1_0:
        return "HTTP/1.0";
    case FDIR_HTTP_VERSION_1_1:
        return "HTTP/1.1";
    case FDIR_HTTP_VERSION_2_0:
        return "HTTP/2.0";
    case FDIR_HTTP_VERSION_3_0:
        return "HTTP/3.0";
    default:
        return "Unknown";
    }
}

/**
 * TLS版本转字符串
 */
const char *fdir_tls_version_to_string(enum fdir_tls_version version)
{
    switch (version) {
    case FDIR_TLS_VERSION_1_0:
        return "TLS 1.0";
    case FDIR_TLS_VERSION_1_1:
        return "TLS 1.1";
    case FDIR_TLS_VERSION_1_2:
        return "TLS 1.2";
    case FDIR_TLS_VERSION_1_3:
        return "TLS 1.3";
    case FDIR_TLS_VERSION_SSL_3_0:
        return "SSL 3.0";
    default:
        return "Unknown";
    }
}

/**
 * TLS记录类型转字符串
 */
const char *fdir_tls_record_type_to_string(enum fdir_tls_record_type type)
{
    switch (type) {
    case FDIR_TLS_RECORD_CHANGE_CIPHER_SPEC:
        return "Change Cipher Spec";
    case FDIR_TLS_RECORD_ALERT:
        return "Alert";
    case FDIR_TLS_RECORD_HANDSHAKE:
        return "Handshake";
    case FDIR_TLS_RECORD_APPLICATION_DATA:
        return "Application Data";
    default:
        return "Unknown";
    }
}

/**
 * TLS握手类型转字符串
 */
const char *fdir_tls_handshake_type_to_string(enum fdir_tls_handshake_type type)
{
    switch (type) {
    case FDIR_TLS_HANDSHAKE_HELLO_REQUEST:
        return "Hello Request";
    case FDIR_TLS_HANDSHAKE_CLIENT_HELLO:
        return "Client Hello";
    case FDIR_TLS_HANDSHAKE_SERVER_HELLO:
        return "Server Hello";
    case FDIR_TLS_HANDSHAKE_CERTIFICATE:
        return "Certificate";
    case FDIR_TLS_HANDSHAKE_SERVER_KEY_EXCHANGE:
        return "Server Key Exchange";
    case FDIR_TLS_HANDSHAKE_CERTIFICATE_REQUEST:
        return "Certificate Request";
    case FDIR_TLS_HANDSHAKE_SERVER_HELLO_DONE:
        return "Server Hello Done";
    case FDIR_TLS_HANDSHAKE_CERTIFICATE_VERIFY:
        return "Certificate Verify";
    case FDIR_TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE:
        return "Client Key Exchange";
    case FDIR_TLS_HANDSHAKE_FINISHED:
        return "Finished";
    default:
        return "Unknown";
    }
}

#if FDIR_DEBUG
/**
 * 调试：打印HTTP结果
 */
void fdir_http_print_result(const struct fdir_http_result *result)
{
    if (!result) {
        printf("HTTP result is NULL\n");
        return;
    }

    printf("\n=== HTTP Result ===\n");
    printf("Method: %s\n", fdir_http_method_to_string(result->method));
    printf("Version: %s\n", fdir_http_version_to_string(result->version));
    printf("Method Str: %s\n", result->method_str);
    printf("URI: %s\n", result->uri);
    printf("Host: %s\n", result->host);
    printf("User-Agent: %s\n", result->user_agent);
    printf("Content-Type: %s\n", result->content_type);
    printf("Content-Length: %u\n", result->content_length);
    printf("Status Code: %u\n", result->status_code);
    printf("==================\n\n");
}

/**
 * 调试：打印TLS结果
 */
void fdir_tls_print_result(const struct fdir_tls_result *result)
{
    if (!result) {
        printf("TLS result is NULL\n");
        return;
    }

    printf("\n=== TLS Result ===\n");
    printf("Version: %s\n", fdir_tls_version_to_string(result->version));
    printf("Record Type: %s\n", fdir_tls_record_type_to_string(result->record_type));
    printf("Handshake Type: %s\n", fdir_tls_handshake_type_to_string(result->handshake_type));
    printf("SNI: %s\n", result->sni);
    printf("Cipher Suite: %s\n", result->cipher_suite);
    printf("Record Len: %u\n", result->record_len);
    printf("Is Resumption: %s\n", result->is_resumption ? "Yes" : "No");
    printf("==================\n\n");
}

/**
 * 调试：打印匹配规则
 */
void fdir_pattern_print_rule(const struct fdir_match_rule *rule)
{
    if (!rule) {
        printf("Match rule is NULL\n");
        return;
    }

    printf("\n=== Match Rule ===\n");
    printf("Rule ID: %u\n", rule->rule_id);
    printf("Name: %s\n", rule->name);
    printf("Type: %s\n", fdir_matcher_type_to_string(rule->type));
    printf("Priority: %u\n", rule->priority);
    printf("Enabled: %s\n", rule->enabled ? "Yes" : "No");
    printf("Invert: %s\n", rule->invert ? "Yes" : "No");

    printf("\nPattern:\n");
    switch (rule->type) {
    case FDIR_MATCHER_FIXED:
        printf("  Pattern: %s\n", rule->pattern.fixed.pattern);
        printf("  Offset: %zu\n", rule->pattern.fixed.offset);
        printf("  Case Sensitive: %s\n", rule->pattern.fixed.case_sensitive ? "Yes" : "No");
        break;
    case FDIR_MATCHER_WILDCARD:
        printf("  Pattern: %s\n", rule->pattern.wildcard.pattern);
        printf("  Case Sensitive: %s\n", rule->pattern.wildcard.case_sensitive ? "Yes" : "No");
        break;
    default:
        printf("  (Not implemented)\n");
        break;
    }

    printf("\nAction:\n");
    printf("  Queue: %u\n", rule->action.queue);
    printf("  Mark: %u\n", rule->action.mark);
    printf("  Drop: %s\n", rule->action.drop ? "Yes" : "No");
    printf("  Log: %s\n", rule->action.log ? "Yes" : "No");
    printf("==================\n\n");
}
#endif /* FDIR_DEBUG */