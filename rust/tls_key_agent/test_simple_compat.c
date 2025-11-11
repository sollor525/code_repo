#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    printf("=== 简单OpenSSL兼容性测试 ===\n");

    // 设置密钥日志文件
    setenv("SSLKEYLOGFILE", "/tmp/simple_compat_test.log", 1);

    // 初始化OpenSSL
    SSL_library_init();
    printf("OpenSSL库初始化完成\n");

    // 创建SSL上下文
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        printf("✗ 创建SSL上下文失败\n");
        return 1;
    }
    printf("✓ SSL上下文创建成功\n");

    // 创建SSL对象
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        printf("✗ 创建SSL对象失败\n");
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("✓ SSL对象创建成功\n");

    // 简单测试
    printf("测试SSL_connect...\n");
    int result = SSL_connect(ssl);
    printf("SSL_connect结果: %d\n", result);

    printf("测试SSL_write...\n");
    result = SSL_write(ssl, "test", 4);
    printf("SSL_write结果: %d\n", result);

    // 清理
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    printf("测试完成！\n");
    return 0;
}