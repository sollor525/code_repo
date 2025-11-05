#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int ret;

    // 初始化OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    printf("OpenSSL初始化完成\n");

    // 创建SSL上下文
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        printf("创建SSL上下文失败\n");
        return 1;
    }

    printf("SSL上下文创建成功\n");

    // 创建SSL对象
    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("创建SSL对象失败\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("SSL对象创建成功\n");

    // 设置SSL文件描述符
    SSL_set_fd(ssl, 1); // stdout

    // 尝试连接（这会失败，但会触发我们的Hook）
    ret = SSL_connect(ssl);
    printf("SSL连接结果: %d\n", ret);

    // 尝试获取Client Random
    unsigned char client_random[32];
    int cr_len = SSL_get_client_random(ssl, client_random, sizeof(client_random));
    printf("Client Random长度: %d\n", cr_len);

    if (cr_len > 0) {
        printf("Client Random: ");
        for (int i = 0; i < cr_len; i++) {
            printf("%02x", client_random[i]);
        }
        printf("\n");
    }

    // 清理
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    EVP_cleanup();

    printf("测试完成\n");
    return 0;
}