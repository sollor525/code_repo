/**
 * @file test_hook_simple.c
 * @brief 简单的Hook测试程序，使用LD_PRELOAD加载我们的Hook库
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    printf("=== TLS密钥提取Hook测试程序 ===\n");

    // 设置环境变量，指定keylog文件路径
    setenv("SSLKEYLOGFILE", "/tmp/tls_test_keys.log", 1);
    printf("设置SSLKEYLOGFILE=/tmp/tls_test_keys.log\n");

    // 初始化OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    printf("OpenSSL库初始化完成\n");

    // 创建SSL上下文
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "创建SSL上下文失败\n");
        return 1;
    }

    printf("SSL上下文创建成功\n");

    // 创建SSL对象（不进行实际网络连接，仅测试Hook机制）
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "创建SSL对象失败\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("SSL对象创建成功\n");

    // 由于没有实际连接，SSL_connect会失败，但这足够测试Hook初始化
    printf("测试SSL_connect（预期失败，因为没有连接）...\n");
    int result = SSL_connect(ssl);
    printf("SSL_connect返回: %d\n", result);

    if (result <= 0) {
        printf("SSL_connect失败是预期的，因为没有建立网络连接\n");
        ERR_print_errors_fp(stderr);
    }

    // 测试SSL_write（同样会失败，但可以测试Hook）
    printf("测试SSL_write...\n");
    const char *test_data = "TEST DATA";
    result = SSL_write(ssl, test_data, strlen(test_data));
    printf("SSL_write返回: %d\n", result);

    // 清理资源
    printf("清理资源...\n");
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    printf("测试完成！\n");
    printf("请检查以下文件：\n");
    printf("1. /tmp/tls_test_keys.log - 密钥日志文件\n");
    printf("2. 查看控制台输出，确认Hook库是否正确加载\n");

    // 检查密钥文件是否存在
    if (access("/tmp/tls_test_keys.log", F_OK) == 0) {
        printf("✓ 密钥日志文件已创建\n");
    } else {
        printf("⚠ 密钥日志文件未创建\n");
    }

    return 0;
}