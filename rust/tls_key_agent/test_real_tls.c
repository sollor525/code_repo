/**
 * @file test_real_tls.c
 * @brief 真实TLS连接测试 - 连接到实际的HTTPS网站
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

int create_socket(const char* host, int port) {
    struct sockaddr_in dest_addr;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("无法创建socket");
        return -1;
    }

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);

    // 使用example.com的IP地址
    if (inet_pton(AF_INET, "93.184.216.34", &dest_addr.sin_addr) <= 0) {
        printf("无法解析主机地址\n");
        close(sock);
        return -1;
    }

    printf("连接到 %s:%d...\n", host, port);
    if (connect(sock, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("连接失败");
        close(sock);
        return -1;
    }

    printf("TCP连接成功！\n");
    return sock;
}

int main() {
    printf("=== 真实TLS连接测试 ===\n");

    // 设置密钥日志文件
    setenv("SSLKEYLOGFILE", "/tmp/real_tls_test.log", 1);

    // 初始化OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    printf("OpenSSL初始化完成\n");

    // 创建TCP连接
    int sock = create_socket("example.com", 443);
    if (sock < 0) {
        printf("TCP连接失败，进行离线测试\n");

        // 离线测试
        const SSL_METHOD *method = TLS_client_method();
        SSL_CTX *ctx = SSL_CTX_new(method);
        if (!ctx) {
            printf("创建SSL上下文失败\n");
            return 1;
        }

        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            printf("创建SSL对象失败\n");
            SSL_CTX_free(ctx);
            return 1;
        }

        printf("执行离线SSL测试...\n");

        // 测试SSL函数（不会成功，但测试Hook）
        SSL_connect(ssl);
        SSL_write(ssl, "test", 4);
        SSL_read(ssl, NULL, 0);

        SSL_free(ssl);
        SSL_CTX_free(ctx);

        printf("离线测试完成\n");
        return 0;
    }

    // 创建SSL上下文
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        printf("创建SSL上下文失败\n");
        close(sock);
        return 1;
    }

    // 创建SSL连接
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    printf("开始SSL握手...\n");
    int ret = SSL_connect(ssl);
    if (ret != 1) {
        printf("SSL握手失败\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return 1;
    }

    printf("✓ SSL握手成功！\n");

    // 发送HTTP请求
    const char *request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    printf("发送HTTP请求...\n");
    ret = SSL_write(ssl, request, strlen(request));
    if (ret > 0) {
        printf("✓ 发送了 %d 字节数据\n", ret);

        // 读取响应
        char response[1024];
        printf("读取HTTP响应...\n");
        ret = SSL_read(ssl, response, sizeof(response) - 1);
        if (ret > 0) {
            response[ret] = '\0';
            printf("✓ 接收到 %d 字节响应\n", ret);
            printf("响应开头: %.100s%s\n", response, ret > 100 ? "..." : "");
        }
    }

    // 清理连接
    printf("关闭连接...\n");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);

    printf("真实TLS测试完成！\n");
    printf("请检查密钥日志文件：\n");
    printf("  - /tmp/real_tls_test.log\n");
    printf("  - /tmp/openssl_keys_all.log\n");

    return 0;
}