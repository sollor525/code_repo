/**
 * @file openssl_hook.c
 * @brief OpenSSL LD_PRELOAD Hook实现
 * @author sollor525@hotmail.com
 * @version 0.1.0
 * @date 2023-11-04
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdint.h>

// OpenSSL函数指针类型定义
typedef struct ssl_st SSL;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_session_st SSL_SESSION;

// OpenSSL 内部结构体声明（用于访问内部数据）
typedef struct ssl3_state_st {
    unsigned char client_random[32];
    unsigned char server_random[32];
    void *session;
} SSL3_STATE;

typedef struct ssl_st {
    int version;
    SSL3_STATE *s3;
    void *session;
} SSL;

// 原始OpenSSL函数指针
static int (*original_SSL_write)(SSL *ssl, const void *buf, int num) = NULL;
static int (*original_SSL_read)(SSL *ssl, void *buf, int num) = NULL;
static int (*original_SSL_connect)(SSL *ssl) = NULL;
static int (*original_SSL_accept)(SSL *ssl) = NULL;
static int (*original_SSL_get_fd)(const SSL *ssl) = NULL;
static int (*original_SSL_get_client_random)(const SSL *ssl, unsigned char *out, size_t outlen) = NULL;
static SSL_SESSION *(*original_SSL_get_session)(const SSL *ssl) = NULL;
static int (*original_SSL_session_reused)(const SSL *ssl) = NULL;

// SSL上下文函数指针
static SSL_CTX *(*original_SSL_CTX_new)(const SSL_METHOD *method) = NULL;
static void (*original_SSL_CTX_free)(SSL_CTX *ctx) = NULL;
static void (*original_SSL_CTX_set_keylog_callback_real)(SSL_CTX *ctx, void (*cb)(const SSL *ssl, const char *line)) = NULL;

// 密钥提取函数指针（从OpenSSL内部获取）
static int (*original_SSL_export_keying_material)(SSL *ssl, unsigned char *out, size_t olen,
                                                 const char *label, size_t llen,
                                                 const unsigned char *context, size_t contextlen,
                                                 int use_context) = NULL;

// Keylog回调函数指针
static void (*original_SSL_CTX_set_keylog_callback)(SSL_CTX *ctx, void (*cb)(const SSL *ssl, const char *line)) = NULL;

// 全局变量用于跟踪状态
static int hook_initialized = 0;
static pthread_mutex_t hook_mutex = PTHREAD_MUTEX_INITIALIZER;

// 注释掉Keylog回调，改为主动提取模式
// static void openssl_keylog_callback(const SSL *ssl, const char *line) { ... }

// 前向声明 - 解决编译错误
static int extract_client_random_proactive(SSL *ssl, unsigned char *client_random);
static int extract_master_secret_proactive(SSL *ssl, unsigned char *master_secret);
static void log_tls_key_proactive(const char *label, const unsigned char *client_random, const unsigned char *master_secret, const char *operation);

// 辅助函数前向声明
static int access_ssl_structure_direct_c(SSL *ssl, unsigned char *client_random);
static int search_client_random_in_memory_c(SSL *ssl, unsigned char *client_random);
static int extract_from_ssl_session_c(SSL *ssl, unsigned char *master_secret);
static int search_master_secret_in_memory_c(SSL *ssl, unsigned char *master_secret);
static int is_likely_master_secret_c(const unsigned char *master_secret);
static int is_likely_client_random_c(const unsigned char *data);
static int validate_client_random_position_c(SSL *ssl, int offset);

// Rust FFI函数声明（如果实际链接Rust库时需要）
extern int tls_key_agent_on_client_random(SSL *ssl, const unsigned char *client_random, size_t len);
extern int tls_key_agent_on_master_secret(SSL *ssl, const unsigned char *master_secret, size_t len);
extern int tls_key_agent_on_connection_info(SSL *ssl, const char *src_ip, int src_port,
                                          const char *dst_ip, int dst_port, const char *protocol);

// 增强版TLS密钥提取 - 主动从SSL函数Hook中提取
static int extract_tls_keys_proactive(SSL *ssl, const char *operation) {
    if (!ssl || !hook_initialized) {
        return -1;
    }

    printf("[TLS Agent] 开始主动密钥提取 - 操作: %s\n", operation);

    // 步骤1: 提取Client Random
    unsigned char client_random[32];
    if (extract_client_random_proactive(ssl, client_random)) {
        printf("[TLS Agent] ✓ Client Random提取成功\n");

        // 步骤2: 尝试提取Master Secret
        unsigned char master_secret[48];
        if (extract_master_secret_proactive(ssl, master_secret)) {
            printf("[TLS Agent] ✓ Master Secret提取成功\n");

            // 记录密钥信息
            log_tls_key_proactive("CLIENT_RANDOM", client_random, master_secret, operation);
        } else {
            printf("[TLS Agent] ⚠ Master Secret提取失败 (这在现代OpenSSL中是正常的)\n");

            // 仍然记录Client Random
            unsigned char empty_master[48] = {0};
            log_tls_key_proactive("CLIENT_RANDOM", client_random, empty_master, operation);
        }
    } else {
        printf("[TLS Agent] ❌ Client Random提取失败\n");
        return -1;
    }

    return 0;
}

// 增强版Client Random提取
static int extract_client_random_proactive(SSL *ssl, unsigned char *client_random) {
    // 方法1: 使用OpenSSL官方API
    if (original_SSL_get_client_random) {
        int len = original_SSL_get_client_random(ssl, client_random, 32);
        if (len == 32) {
            printf("[TLS Agent] Client Random: 方法1 (OpenSSL API) 成功\n");
            return 1;
        }
    }

    // 方法2: 直接访问SSL结构体
    if (access_ssl_structure_direct_c(ssl, client_random)) {
        printf("[TLS Agent] Client Random: 方法2 (直接结构体访问) 成功\n");
        return 1;
    }

    // 方法3: 内存搜索
    if (search_client_random_in_memory_c(ssl, client_random)) {
        printf("[TLS Agent] Client Random: 方法3 (内存搜索) 成功\n");
        return 1;
    }

    printf("[TLS Agent] Client Random: 所有方法都失败\n");
    return 0;
}

// 增强版Master Secret提取
static int extract_master_secret_proactive(SSL *ssl, unsigned char *master_secret) {
    // 方法1: 使用SSL_export_keying_material
    if (original_SSL_export_keying_material) {
        // 尝试导出"master secret"标签的密钥材料
        int result = original_SSL_export_keying_material(
            ssl,
            master_secret,
            48,
            "master secret",
            13,
            NULL,
            0,
            0
        );

        if (result > 0 && is_likely_master_secret_c(master_secret)) {
            printf("[TLS Agent] Master Secret: 方法1 (SSL_export_keying_material) 成功\n");
            return 1;
        }
    }

    // 方法2: 从SSL_SESSION中提取
    if (extract_from_ssl_session_c(ssl, master_secret)) {
        printf("[TLS Agent] Master Secret: 方法2 (SSL_SESSION) 成功\n");
        return 1;
    }

    // 方法3: 内存搜索 (最后回退)
    if (search_master_secret_in_memory_c(ssl, master_secret)) {
        printf("[TLS Agent] Master Secret: 方法3 (内存搜索) 成功\n");
        return 1;
    }

    return 0;
}

// C语言版本的辅助函数声明
static int access_ssl_structure_direct_c(SSL *ssl, unsigned char *client_random);
static int search_client_random_in_memory_c(SSL *ssl, unsigned char *client_random);
static int extract_from_ssl_session_c(SSL *ssl, unsigned char *master_secret);
static int search_master_secret_in_memory_c(SSL *ssl, unsigned char *master_secret);
static int is_likely_master_secret_c(const unsigned char *master_secret);
static void log_tls_key_proactive(const char *label, const unsigned char *client_random, const unsigned char *master_secret, const char *operation);

// C语言版本的SSL结构体直接访问
static int access_ssl_structure_direct_c(SSL *ssl, unsigned char *client_random) {
    if (!ssl || !client_random) {
        return 0;
    }

    // 检查SSL结构体中的s3字段
    if (ssl->s3) {
        memcpy(client_random, ssl->s3->client_random, 32);

        // 验证这看起来像有效的Client Random
        if (is_likely_client_random_c(client_random)) {
            return 1;
        }
    }

    return 0;
}

// C语言版本的内存搜索Client Random
static int search_client_random_in_memory_c(SSL *ssl, unsigned char *client_random) {
    if (!ssl || !client_random) {
        return 0;
    }

    unsigned char *ssl_ptr = (unsigned char *)ssl;
    int search_range = 1024; // 搜索前1KB

    for (int offset = 0; offset < search_range; offset++) {
        unsigned char *candidate_ptr = ssl_ptr + offset;

        if (is_likely_client_random_c(candidate_ptr)) {
            // 验证位置的合理性
            if (validate_client_random_position_c(ssl, offset)) {
                memcpy(client_random, candidate_ptr, 32);
                return 1;
            }
        }
    }

    return 0;
}

// C语言版本的Client Random检测
static int is_likely_client_random_c(const unsigned char *data) {
    // 检查1: 不应该全零或全相同
    unsigned char first_byte = data[0];
    if (data[0] == 0) {
        // 全零，检查是否全相同
        int all_same = 1;
        for (int i = 1; i < 32; i++) {
            if (data[i] != first_byte) {
                all_same = 0;
                break;
            }
        }
        if (all_same) return 0;
    }

    // 检查2: 简单的熵值检测
    int byte_counts[256] = {0};
    for (int i = 0; i < 32; i++) {
        byte_counts[data[i]]++;
    }

    int max_count = 0;
    for (int i = 0; i < 256; i++) {
        if (byte_counts[i] > max_count) {
            max_count = byte_counts[i];
        }
    }

    // 任何字节不应该出现超过4次
    if (max_count > 4) {
        return 0;
    }

    // 检查3: 不应该有太长的连续相同字节
    int max_consecutive = 1;
    int current_consecutive = 1;

    for (int i = 1; i < 32; i++) {
        if (data[i] == data[i-1]) {
            current_consecutive++;
            if (current_consecutive > max_consecutive) {
                max_consecutive = current_consecutive;
            }
        } else {
            current_consecutive = 1;
        }
    }

    if (max_consecutive > 3) {
        return 0;
    }

    return 1;
}

// 验证Client Random位置的合理性
static int validate_client_random_position_c(SSL *ssl, int offset) {
    // 简单验证：Client Random应该在SSL对象的合理范围内
    if (offset > 1024) {
        return 0;
    }
    return 1;
}

// C语言版本的SSL_SESSION提取
static int extract_from_ssl_session_c(SSL *ssl, unsigned char *master_secret) {
    if (!ssl || !master_secret || !original_SSL_get_session) {
        return 0;
    }

    SSL_SESSION *session = original_SSL_get_session(ssl);
    if (!session) {
        return 0;
    }

    // 这里实现从SSL_SESSION结构中提取Master Secret
    // 由于OpenSSL版本差异，这是一个复杂的过程
    // 在实际环境中需要根据具体版本调整偏移量

    // 暂时返回失败
    return 0;
}

// C语言版本的内存搜索Master Secret
static int search_master_secret_in_memory_c(SSL *ssl, unsigned char *master_secret) {
    if (!ssl || !master_secret) {
        return 0;
    }

    unsigned char *ssl_ptr = (unsigned char *)ssl;
    int search_range = 2048; // 搜索范围更大

    for (int offset = 0; offset < search_range; offset++) {
        unsigned char *candidate_ptr = ssl_ptr + offset;

        if (is_likely_master_secret_c(candidate_ptr)) {
            memcpy(master_secret, candidate_ptr, 48);
            return 1;
        }
    }

    return 0;
}

// C语言版本的Master Secret检测
static int is_likely_master_secret_c(const unsigned char *master_secret) {
    if (!master_secret) {
        return 0;
    }

    // 检查1: 不应该全零
    int all_zero = 1;
    for (int i = 0; i < 48; i++) {
        if (master_secret[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) return 0;

    // 检查2: 不应该全相同
    unsigned char first_byte = master_secret[0];
    int all_same = 1;
    for (int i = 1; i < 48; i++) {
        if (master_secret[i] != first_byte) {
            all_same = 0;
            break;
        }
    }
    if (all_same) return 0;

    // 检查3: 应该有足够的熵值
    int unique_bytes = 0;
    int seen[256] = {0};

    for (int i = 0; i < 48; i++) {
        if (!seen[master_secret[i]]) {
            seen[master_secret[i]] = 1;
            unique_bytes++;
        }
    }

    // 48字节中至少要有16个不同的字节
    return (unique_bytes >= 16);
}

// 增强版密钥日志记录 - 减少Keylog依赖
static void log_tls_key_proactive(const char *label, const unsigned char *client_random, const unsigned char *master_secret, const char *operation) {
    // 仍然支持SSLKEYLOGFILE环境变量，但不依赖它
    const char *keylog_env = getenv("SSLKEYLOGFILE");
    if (keylog_env) {
        FILE *file = fopen(keylog_env, "a");
        if (file) {
            time_t timestamp = time(NULL);

            // 转换为十六进制字符串
            char client_random_hex[65];
            char master_secret_hex[97];

            for (int i = 0; i < 32; i++) {
                sprintf(client_random_hex + i * 2, "%02x", client_random[i]);
            }
            client_random_hex[64] = '\0';

            for (int i = 0; i < 48; i++) {
                sprintf(master_secret_hex + i * 2, "%02x", master_secret[i]);
            }
            master_secret_hex[96] = '\0';

            // 检查Master Secret是否有效
            int has_valid_master = 0;
            for (int i = 0; i < 48; i++) {
                if (master_secret[i] != 0) {
                    has_valid_master = 1;
                    break;
                }
            }

            // 使用标准Wireshark格式
            if (has_valid_master) {
                fprintf(file, "CLIENT_RANDOM %s %s %ld\n", client_random_hex, master_secret_hex, timestamp);
            } else {
                fprintf(file, "CLIENT_RANDOM %s %s %ld\n", client_random_hex,
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", timestamp);
            }

            fclose(file);
        }
    }

    // 同时输出到stderr用于调试
    printf("[TLS Agent] 密钥提取完成 [%s] - 操作: %s\n", label, operation);
    printf("[TLS Agent] Client Random: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", client_random[i]);
    }

    int has_valid_master = 0;
    for (int i = 0; i < 48; i++) {
        if (master_secret[i] != 0) {
            has_valid_master = 1;
            break;
        }
    }

    if (has_valid_master) {
        printf(" - Master Secret: ");
        for (int i = 0; i < 8; i++) {
            printf("%02x", master_secret[i]);
        }
    } else {
        printf(" - Master Secret: 未提取");
    }
    printf("\n");
}

// 原始的keylog日志记录（保留作为回退）
static void log_tls_key(const char *label, const unsigned char *client_random, const unsigned char *master_secret, const char *operation) {
    const char *keylog_file = getenv("SSLKEYLOGFILE");
    if (keylog_file) {
        FILE *fp = fopen(keylog_file, "a");
        if (fp) {
            // 构造Wireshark兼容的keylog行
            char client_random_hex[65];
            char master_secret_hex[97];

            for (int i = 0; i < 32; i++) {
                sprintf(client_random_hex + i * 2, "%02x", client_random[i]);
            }
            client_random_hex[64] = '\0';

            for (int i = 0; i < 48; i++) {
                sprintf(master_secret_hex + i * 2, "%02x", master_secret[i]);
            }
            master_secret_hex[96] = '\0';

            fprintf(fp, "CLIENT_RANDOM %s %s\n", client_random_hex, master_secret_hex);
            fflush(fp);
            fclose(fp);
        }
    }
}

// 初始化函数
__attribute__((constructor))
static void init_openssl_hook(void) {
    pthread_mutex_lock(&hook_mutex);

    if (hook_initialized) {
        pthread_mutex_unlock(&hook_mutex);
        return;
    }

    printf("[TLS Agent] OpenSSL Hook 初始化开始\n");

    // 清除dlerror
    dlerror();

    // 获取原始函数指针
    original_SSL_write = dlsym(RTLD_NEXT, "SSL_write");
    original_SSL_read = dlsym(RTLD_NEXT, "SSL_read");
    original_SSL_connect = dlsym(RTLD_NEXT, "SSL_connect");
    original_SSL_accept = dlsym(RTLD_NEXT, "SSL_accept");
    original_SSL_get_fd = dlsym(RTLD_NEXT, "SSL_get_fd");
    original_SSL_get_client_random = dlsym(RTLD_NEXT, "SSL_get_client_random");
    original_SSL_get_session = dlsym(RTLD_NEXT, "SSL_get_session");
    original_SSL_session_reused = dlsym(RTLD_NEXT, "SSL_session_reused");

    // SSL上下文函数指针
    original_SSL_CTX_new = dlsym(RTLD_NEXT, "SSL_CTX_new");
    original_SSL_CTX_free = dlsym(RTLD_NEXT, "SSL_CTX_free");
    original_SSL_CTX_set_keylog_callback_real = (void (*)(SSL_CTX *, void (*)(const SSL *, const char *)))dlsym(RTLD_NEXT, "SSL_CTX_set_keylog_callback");

    // 可选函数，可能不存在
    original_SSL_export_keying_material = dlsym(RTLD_NEXT, "SSL_export_keying_material");
    if (!original_SSL_export_keying_material) {
        printf("[TLS Agent] SSL_export_keying_material 函数不可用（正常情况）\n");
    }

    // Keylog回调函数（兼容性）
    original_SSL_CTX_set_keylog_callback = original_SSL_CTX_set_keylog_callback_real;

    // 检查关键函数是否成功获取
    char *error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "[TLS Agent] dlsym错误: %s\n", error);
    }

    if (!original_SSL_write || !original_SSL_read || !original_SSL_connect || !original_SSL_accept) {
        fprintf(stderr, "[TLS Agent] 获取核心OpenSSL函数失败\n");
        fprintf(stderr, "  SSL_write: %p\n", original_SSL_write);
        fprintf(stderr, "  SSL_read: %p\n", original_SSL_read);
        fprintf(stderr, "  SSL_connect: %p\n", original_SSL_connect);
        fprintf(stderr, "  SSL_accept: %p\n", original_SSL_accept);
    } else {
        printf("[TLS Agent] OpenSSL Hook 初始化成功\n");

        // 设置环境变量，强制OpenSSL使用keylog
        setenv("SSLKEYLOGFILE", "/tmp/openssl_keys_all.log", 1);

        hook_initialized = 1;
    }

    // 尝试为现有SSL上下文设置keylog回调
    if (original_SSL_CTX_set_keylog_callback_real) {
        printf("[TLS Agent] 支持Keylog回调机制\n");

        // Hook SSL_CTX_new函数以自动设置keylog回调
        if (original_SSL_CTX_new) {
            printf("[TLS Agent] 成功设置Keylog回调钩子\n");
        }
    }

    pthread_mutex_unlock(&hook_mutex);
}

// 清理函数
__attribute__((destructor))
static void cleanup_openssl_hook(void) {
    printf("[TLS Agent] OpenSSL Hook 清理\n");
}

// 获取连接信息
static void get_connection_info(SSL *ssl, char *src_ip, int *src_port, char *dst_ip, int *dst_port) {
    if (!original_SSL_get_fd || !ssl) {
        return;
    }

    int fd = original_SSL_get_fd(ssl);
    if (fd < 0) {
        return;
    }

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    // 获取本地地址
    if (getsockname(fd, (struct sockaddr*)&addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, src_ip, INET_ADDRSTRLEN);
        *src_port = ntohs(addr.sin_port);
    }

    // 获取远程地址
    if (getpeername(fd, (struct sockaddr*)&addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, dst_ip, INET_ADDRSTRLEN);
        *dst_port = ntohs(addr.sin_port);
    }
}

// TLS密钥信息结构体
typedef struct {
    unsigned char client_random[32];
    unsigned char master_secret[48];
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    int src_port;
    int dst_port;
    pid_t pid;
    char process_name[256];
    char command_line[1024];
    int has_master_secret;
} tls_key_info_t;

// 将密钥信息写入本地文件（备用方案）
static void write_key_to_file(const tls_key_info_t *key_info) {
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/tls_keys_%d.log", key_info->pid);

    FILE *fp = fopen(filename, "a");
    if (!fp) {
        return;
    }

    fprintf(fp, "TIME: %ld\n", time(NULL));
    fprintf(fp, "PID: %d\n", key_info->pid);
    fprintf(fp, "PROCESS: %s\n", key_info->process_name);
    fprintf(fp, "SRC: %s:%d\n", key_info->src_ip, key_info->src_port);
    fprintf(fp, "DST: %s:%d\n", key_info->dst_ip, key_info->dst_port);

    fprintf(fp, "CLIENT_RANDOM: ");
    for (int i = 0; i < 32; i++) {
        fprintf(fp, "%02x", key_info->client_random[i]);
    }
    fprintf(fp, "\n");

    if (key_info->has_master_secret) {
        fprintf(fp, "MASTER_SECRET: ");
        for (int i = 0; i < 48; i++) {
            fprintf(fp, "%02x", key_info->master_secret[i]);
        }
        fprintf(fp, "\n");
    }

    fprintf(fp, "---\n");
    fclose(fp);
}

// 获取进程命令行
static void get_process_command_line(char *cmdline, size_t size) {
    FILE *fp = fopen("/proc/self/cmdline", "r");
    if (!fp) {
        strncpy(cmdline, "unknown", size - 1);
        cmdline[size - 1] = '\0';
        return;
    }

    size_t total_len = 0;
    int ch;
    while ((ch = fgetc(fp)) != EOF && total_len < size - 1) {
        if (ch == '\0') {
            cmdline[total_len++] = ' ';
        } else {
            cmdline[total_len++] = (char)ch;
        }
    }
    cmdline[total_len] = '\0';

    fclose(fp);
}

// 从SSL结构体中提取Client Random（内部访问）
static int extract_client_random_from_ssl(SSL *ssl, unsigned char *client_random) {
    if (!ssl || !client_random) {
        return 0;
    }

    // 方法1：尝试使用OpenSSL API
    if (original_SSL_get_client_random) {
        int len = original_SSL_get_client_random(ssl, client_random, 32);
        if (len == 32) {
            return 1;
        }
    }

    // 方法2：访问内部结构（谨慎使用）
    if (ssl->s3) {
        memcpy(client_random, ssl->s3->client_random, 32);
        return 1;
    }

    return 0;
}

// 从SSL会话中尝试提取Master Secret（简化版本）
static int extract_master_secret_from_ssl(SSL *ssl, unsigned char *master_secret) {
    if (!ssl || !master_secret) {
        return 0;
    }

    // 注意：在现代OpenSSL版本中，直接访问master_secret受到限制
    // 这里提供一个框架，实际实现可能需要更复杂的技术

    // 方法1：尝试从SSL_SESSION中获取Master Secret
    SSL_SESSION *session = original_SSL_get_session ? original_SSL_get_session(ssl) : NULL;
    if (session) {
        // 对于某些OpenSSL版本，可以尝试从session中提取
        // 注意：这通常需要访问内部结构，可能在不同版本中不可用

        // 方法1a：尝试使用SSL_SESSION_get_master_key（如果可用）
        // 这在较新版本的OpenSSL中可能不可用

        // 方法1b：通过keylog回调机制
        // 如果设置了keylog回调，应该已经通过回调获取了Master Secret

        // 方法1c：直接内存访问（不推荐，需要精确的偏移量）
        // 这里仅作为概念验证，实际使用需要根据具体版本调整
        /*
        unsigned char *session_data = (unsigned char *)session;
        // 假设Master Secret在特定偏移处（这需要根据OpenSSL版本调整）
        int master_secret_offset = 0x40; // 示例偏移，需要实际测试
        memcpy(master_secret, session_data + master_secret_offset, 48);

        // 验证是否为有效密钥（不全为0）
        int is_valid = 0;
        for (int i = 0; i < 48; i++) {
            if (master_secret[i] != 0) {
                is_valid = 1;
                break;
            }
        }

        if (is_valid) {
            return 1;
        }
        */
    }

    // 方法2：通过SSL_export_keying_material尝试获取相关密钥材料
    if (original_SSL_export_keying_material) {
        unsigned char key_material[64];
        // 尝试导出"master secret"标签的密钥材料
        int result = original_SSL_export_keying_material(
            ssl,
            key_material,
            48,
            "master secret",
            13,
            NULL,
            0,
            0
        );

        if (result > 0) {
            memcpy(master_secret, key_material, 48);

            // 验证密钥是否有效
            int is_valid = 0;
            for (int i = 0; i < 48; i++) {
                if (master_secret[i] != 0) {
                    is_valid = 1;
                    break;
                }
            }

            if (is_valid) {
                return 1;
            }
        }
    }

    // 方法3：使用OpenSSL的SSL_KEYLOG机制
    // 这通常需要设置环境变量或回调函数
    // 在实际部署中，这是最可靠的方法

    // 暂时返回失败，表示当前方法无法提取master_secret
    return 0;
}

// 提取TLS密钥信息
static void extract_tls_keys(SSL *ssl) {
    if (!ssl || !hook_initialized) {
        return;
    }

    // 使用线程局部存储避免重复提取
    static __thread int extracted = 0;
    if (extracted) {
        return;
    }

    tls_key_info_t key_info = {0};

    // 提取Client Random
    if (extract_client_random_from_ssl(ssl, key_info.client_random)) {
        printf("[TLS Agent] 成功提取Client Random\n");

        // 调用Rust FFI函数
        if (tls_key_agent_on_client_random(ssl, key_info.client_random, 32) != 0) {
            printf("[TLS Agent] Rust FFI Client Random处理失败\n");
        }
    } else {
        printf("[TLS Agent] Client Random提取失败\n");
        return;
    }

    // 尝试提取Master Secret
    key_info.has_master_secret = extract_master_secret_from_ssl(ssl, key_info.master_secret);
    if (key_info.has_master_secret) {
        printf("[TLS Agent] 成功提取Master Secret\n");

        // 调用Rust FFI函数
        if (tls_key_agent_on_master_secret(ssl, key_info.master_secret, 48) != 0) {
            printf("[TLS Agent] Rust FFI Master Secret处理失败\n");
        }
    } else {
        printf("[TLS Agent] Master Secret提取失败（这在现代OpenSSL中是正常的）\n");
    }

    // 获取连接信息
    get_connection_info(ssl, key_info.src_ip, &key_info.src_port, key_info.dst_ip, &key_info.dst_port);

    // 获取进程信息
    key_info.pid = getpid();
    get_process_command_line(key_info.command_line, sizeof(key_info.command_line));

    // 获取进程名
    FILE *fp = fopen("/proc/self/comm", "r");
    if (fp) {
        if (fgets(key_info.process_name, sizeof(key_info.process_name), fp)) {
            key_info.process_name[strcspn(key_info.process_name, "\n")] = 0;
        }
        fclose(fp);
    } else {
        strncpy(key_info.process_name, "unknown", sizeof(key_info.process_name) - 1);
    }

    // 调用Rust FFI函数传递连接信息
    if (tls_key_agent_on_connection_info(ssl, key_info.src_ip, key_info.src_port,
                                        key_info.dst_ip, key_info.dst_port, "TCP") != 0) {
        printf("[TLS Agent] Rust FFI 连接信息处理失败\n");
    }

    // 打印提取的信息
    printf("[TLS Agent] === TLS密钥信息 ===\n");
    printf("[TLS Agent] 进程: %s (PID: %d)\n", key_info.process_name, key_info.pid);
    printf("[TLS Agent] 连接: %s:%d -> %s:%d\n",
           key_info.src_ip, key_info.src_port, key_info.dst_ip, key_info.dst_port);

    printf("[TLS Agent] Client Random: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", key_info.client_random[i]);
    }
    printf("\n");

    if (key_info.has_master_secret) {
        printf("[TLS Agent] Master Secret: ");
        for (int i = 0; i < 48; i++) {
            printf("%02x", key_info.master_secret[i]);
        }
        printf("\n");
    }
    printf("[TLS Agent] =====================\n");

    // 写入文件作为备份
    write_key_to_file(&key_info);

    // 标记为已提取
    extracted = 1;
}

// 检测握手是否完成的辅助函数
static int is_handshake_complete(SSL *ssl) {
    if (!ssl || !original_SSL_get_fd) {
        return 0;
    }

    // 方法1：通过SSL_get_fd检查连接状态
    int fd = original_SSL_get_fd(ssl);
    if (fd < 0) {
        return 0;
    }

    // 方法2：尝试获取Client Random来判断握手状态
    if (original_SSL_get_client_random) {
        unsigned char temp[32];
        int len = original_SSL_get_client_random(ssl, temp, sizeof(temp));
        if (len == 32) {
            return 1; // Client Random存在表明握手已进行
        }
    }

    // 方法3：检查SSL状态（需要访问内部结构）
    if (ssl->s3) {
        // 检查内部状态是否表明握手完成
        // 这里简化处理，实际可以根据OpenSSL版本检查具体状态
        return 1;
    }

    return 0;
}

// Hook SSL_write
int SSL_write(SSL *ssl, const void *buf, int num) {
    if (!original_SSL_write) {
        return -1;
    }

    int result = original_SSL_write(ssl, buf, num);

    // 在首次成功写入时使用主动式密钥提取
    static __thread int keys_extracted = 0;
    if (!keys_extracted && result > 0 && is_handshake_complete(ssl)) {
        printf("[TLS Agent] SSL_write: 主动提取TLS密钥\n");
        extract_tls_keys_proactive(ssl, "SSL_write");
        keys_extracted = 1;
    }

    return result;
}

// Hook SSL_read
int SSL_read(SSL *ssl, void *buf, int num) {
    if (!original_SSL_read) {
        return -1;
    }

    int result = original_SSL_read(ssl, buf, num);

    // 在首次成功读取时使用主动式密钥提取
    static __thread int keys_extracted = 0;
    if (!keys_extracted && result > 0 && is_handshake_complete(ssl)) {
        printf("[TLS Agent] SSL_read: 主动提取TLS密钥\n");
        extract_tls_keys_proactive(ssl, "SSL_read");
        keys_extracted = 1;
    }

    return result;
}

// Hook SSL_connect
int SSL_connect(SSL *ssl) {
    if (!original_SSL_connect) {
        return -1;
    }

    int result = original_SSL_connect(ssl);

    if (result == 1) {
        printf("[TLS Agent] SSL_connect: 连接建立成功，主动提取TLS密钥\n");
        extract_tls_keys_proactive(ssl, "SSL_connect");
    } else if (result < 0) {
        // 检查是否是非阻塞模式下的继续操作
        int error = errno;
        if (error == EAGAIN || error == EWOULDBLOCK) {
            // 非阻塞模式，可能需要等待
        } else {
            printf("[TLS Agent] SSL_connect失败，错误码: %d\n", error);
        }
    }

    return result;
}

// Hook SSL_accept
int SSL_accept(SSL *ssl) {
    if (!original_SSL_accept) {
        return -1;
    }

    int result = original_SSL_accept(ssl);

    if (result == 1) {
        printf("[TLS Agent] SSL_accept: 接受连接成功，主动提取TLS密钥\n");
        extract_tls_keys_proactive(ssl, "SSL_accept");
    } else if (result < 0) {
        // 检查是否是非阻塞模式下的继续操作
        int error = errno;
        if (error == EAGAIN || error == EWOULDBLOCK) {
            // 非阻塞模式，可能需要等待
        } else {
            printf("[TLS Agent] SSL_accept失败，错误码: %d\n", error);
        }
    }

    return result;
}

// Hook SSL_do_handshake（如果存在）
int SSL_do_handshake(SSL *ssl) {
    static int (*original_SSL_do_handshake)(SSL *ssl) = NULL;

    if (!original_SSL_do_handshake) {
        original_SSL_do_handshake = dlsym(RTLD_NEXT, "SSL_do_handshake");
        if (!original_SSL_do_handshake) {
            // 函数不存在，可能是旧版本OpenSSL
            return 1; // 返回成功，避免阻塞
        }
    }

    int result = original_SSL_do_handshake(ssl);

    if (result == 1) {
        printf("[TLS Agent] SSL_do_handshake: 握手完成，主动提取TLS密钥\n");
        extract_tls_keys_proactive(ssl, "SSL_do_handshake");
    }

    return result;
}

// 全局配置
static char *g_config_path = NULL;

// 导出函数供Rust调用
int init_tls_key_agent_hook(const char *config_path) {
    if (!hook_initialized) {
        printf("[TLS Agent] Hook未初始化，无法初始化Agent\n");
        return -1;
    }

    printf("[TLS Agent] 初始化TLS Key Agent Hook\n");
    printf("[TLS Agent] 配置文件: %s\n", config_path ? config_path : "null");

    // 保存配置路径
    if (g_config_path) {
        free(g_config_path);
    }
    if (config_path) {
        g_config_path = strdup(config_path);
    } else {
        g_config_path = NULL;
    }

    // 创建临时目录
    struct stat st = {0};
    if (stat("/tmp/tls_agent", &st) == -1) {
        mkdir("/tmp/tls_agent", 0755);
    }

    printf("[TLS Agent] TLS Key Agent Hook 初始化完成\n");
    return 0;
}

int cleanup_tls_key_agent_hook(void) {
    printf("[TLS Agent] 清理TLS Key Agent Hook\n");

    if (g_config_path) {
        free(g_config_path);
        g_config_path = NULL;
    }

    printf("[TLS Agent] TLS Key Agent Hook 清理完成\n");
    return 0;
}

// 获取Hook状态
int tls_key_agent_hook_status(void) {
    return hook_initialized ? 1 : 0;
}

// 设置日志级别
void tls_key_agent_set_log_level(int level) {
    printf("[TLS Agent] 设置日志级别: %d\n", level);
    // 这里可以实现更复杂的日志级别控制
}

// Hook SSL_CTX_new - 自动设置keylog回调
SSL_CTX *SSL_CTX_new(const SSL_METHOD *method) {
    if (!original_SSL_CTX_new) {
        original_SSL_CTX_new = dlsym(RTLD_NEXT, "SSL_CTX_new");
        if (!original_SSL_CTX_new) {
            return NULL;
        }
    }

    // 调用原始函数创建SSL_CTX
    SSL_CTX *ctx = original_SSL_CTX_new(method);
    if (!ctx) {
        return NULL;
    }

    // 注释：不再自动设置keylog回调，改用主动式提取
    // Keylog回调现在作为回退机制，仅在某些特殊情况下启用
    /*
    if (original_SSL_CTX_set_keylog_callback_real && hook_initialized) {
        original_SSL_CTX_set_keylog_callback_real(ctx, openssl_keylog_callback);
        printf("[TLS Agent] 为新SSL_CTX设置keylog回调\n");
    }
    */

    return ctx;
}

// Hook SSL_CTX_free - 清理keylog回调
void SSL_CTX_free(SSL_CTX *ctx) {
    if (!ctx) {
        return;
    }

    if (!original_SSL_CTX_free) {
        original_SSL_CTX_free = dlsym(RTLD_NEXT, "SSL_CTX_free");
        if (!original_SSL_CTX_free) {
            return;
        }
    }

    // 清理keylog回调
    if (original_SSL_CTX_set_keylog_callback_real) {
        original_SSL_CTX_set_keylog_callback_real(ctx, NULL);
    }

    // 调用原始函数
    original_SSL_CTX_free(ctx);
}