/**
 * @file test_proactive_extraction.c
 * @brief 测试主动式TLS密钥提取功能
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// 声明我们的Hook函数
extern int tls_key_agent_hook_status(void);
extern void tls_key_agent_set_log_level(int level);

int main() {
    printf("=== 主动式TLS密钥提取测试程序 ===\n");

    // 检查Hook状态
    int hook_status = tls_key_agent_hook_status();
    printf("Hook状态: %s\n", hook_status ? "已初始化" : "未初始化");

    // 设置日志级别
    tls_key_agent_set_log_level(1); // 详细日志

    // 初始化OpenSSL
    SSL_library_init();
    SSL_load_error_strings();

    // 创建SSL上下文
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "创建SSL上下文失败\n");
        return 1;
    }

    printf("SSL上下文创建成功\n");

    // 创建socket连接（简单的HTTP请求测试）
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("创建socket失败");
        SSL_CTX_free(ctx);
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);

    // 尝试连接到一个常见的HTTPS网站（实际测试时可以使用本地测试服务器）
    if (inet_pton(AF_INET, "93.184.216.34", &addr.sin_addr) <= 0) { // example.com
        printf("无法解析目标地址，使用本地测试\n");
        close(sock);
        SSL_CTX_free(ctx);

        // 创建本地测试
        printf("执行本地SSL测试（无需网络连接）...\n");

        // 创建SSL对象（不进行实际连接，只测试Hook机制）
        SSL *ssl = SSL_new(ctx);
        if (ssl) {
            printf("SSL对象创建成功\n");

            // 测试SSL_write Hook（即使没有实际连接）
            printf("测试SSL_write Hook...\n");
            const char *test_data = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
            int result = SSL_write(ssl, test_data, strlen(test_data));
            printf("SSL_write返回: %d (预期为-1，因为没有连接)\n", result);

            // 测试SSL_read Hook
            printf("测试SSL_read Hook...\n");
            char buffer[1024];
            result = SSL_read(ssl, buffer, sizeof(buffer));
            printf("SSL_read返回: %d (预期为-1，因为没有连接)\n", result);

            SSL_free(ssl);
        }

        SSL_CTX_free(ctx);
        printf("本地测试完成\n");
        return 0;
    }

    printf("尝试连接到example.com:443...\n");
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("连接失败");
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("TCP连接成功，创建SSL连接...\n");

    // 创建SSL连接
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    printf("执行SSL握手...\n");
    int ret = SSL_connect(ssl);
    if (ret == 1) {
        printf("SSL握手成功！\n");

        // 发送HTTP请求
        const char *request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        printf("发送HTTP请求...\n");
        ret = SSL_write(ssl, request, strlen(request));
        printf("SSL_write返回: %d\n", ret);

        if (ret > 0) {
            // 读取响应
            char response[4096];
            printf("读取HTTP响应...\n");
            ret = SSL_read(ssl, response, sizeof(response) - 1);
            printf("SSL_read返回: %d\n", ret);

            if (ret > 0) {
                response[ret] = '\0';
                printf("接收到 %d 字节响应\n", ret);
                printf("响应开头: %.100s%s\n", response, ret > 100 ? "..." : "");
            }
        }

    } else {
        printf("SSL握手失败\n");
        ERR_print_errors_fp(stderr);
    }

    printf("清理资源...\n");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    printf("测试完成！\n");
    printf("请检查 /tmp/openssl_keys_all.log 文件以查看提取的密钥信息\n");

    return 0;
}