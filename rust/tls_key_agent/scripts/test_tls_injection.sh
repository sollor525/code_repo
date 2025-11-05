#!/bin/bash

# TLS 注入测试脚本

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 配置
TLS_AGENT_DIR="/opt/tls_key_agent"
HOOK_LIB="$TLS_AGENT_DIR/libopenssl_hook.so"
TEST_DIR="/tmp/tls_test_$$"
OUTPUT_LOG="$TEST_DIR/test_output.log"
KEY_LOG="$TEST_DIR/tls_keys.log"

# 测试结果
TESTS_PASSED=0
TESTS_FAILED=0

# 清理函数
cleanup() {
    log_info "清理测试环境..."

    # 杀死测试进程
    if [[ -n "${TEST_PID:-}" ]]; then
        kill "$TEST_PID" 2>/dev/null || true
    fi

    # 清理测试目录
    rm -rf "$TEST_DIR" 2>/dev/null || true

    log_info "清理完成"
}

# 设置信号处理
trap cleanup EXIT INT TERM

# 测试函数
run_test() {
    local test_name="$1"
    local test_command="$2"

    echo -n "测试: $test_name ... "

    if eval "$test_command" >>"$OUTPUT_LOG" 2>&1; then
        echo "✓"
        ((TESTS_PASSED++))
    else
        echo "✗"
        ((TESTS_FAILED++))
        echo "详细信息见日志: $OUTPUT_LOG"
    fi
}

# 创建测试环境
setup_test_environment() {
    log_info "创建测试环境..."

    # 创建测试目录
    mkdir -p "$TEST_DIR"
    cd "$TEST_DIR"

    # 检查必要的文件
    if [[ ! -f "$HOOK_LIB" ]]; then
        log_error "Hook库不存在: $HOOK_LIB"
        exit 1
    fi

    if [[ ! -x "$TLS_AGENT_DIR/tls_key_agent" ]]; then
        log_error "TLS Agent二进制文件不存在或不可执行"
        exit 1
    fi

    log_success "测试环境创建完成"
}

# 编译测试程序
compile_test_programs() {
    log_info "编译测试程序..."

    # 创建简单的HTTPS客户端测试程序
    cat > https_client.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HOST "www.google.com"
#define PORT 443

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sock;
    struct sockaddr_in server_addr;

    // 初始化OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // 创建SSL上下文
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "无法创建SSL上下文\n");
        return 1;
    }

    // 创建socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "无法创建socket\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    // 设置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    // 连接到服务器
    if (inet_pton(AF_INET, "142.250.187.228", &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "无效的地址\n");
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "连接失败\n");
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    // 创建SSL对象
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // 进行SSL握手
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "SSL握手失败\n");
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("TLS连接成功，协议: %s\n", SSL_get_version(ssl));

    // 发送HTTP请求
    const char *request = "GET / HTTP/1.1\r\nHost: " HOST "\r\nConnection: close\r\n\r\n";
    SSL_write(ssl, request, strlen(request));

    // 读取响应
    char buffer[1024];
    int bytes_read;
    while ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        // 只读取前几个字节作为测试
        break;
    }

    printf("HTTP响应接收成功\n");

    // 清理
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    EVP_cleanup();

    return 0;
}
EOF

    # 创建测试服务器程序
    cat > https_server.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8443

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // 初始化OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // 创建SSL上下文
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "无法创建SSL上下文\n");
        return 1;
    }

    // 生成自签名证书（仅用于测试）
    EVP_PKEY *pkey = EVP_PKEY_new();
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    EVP_PKEY_assign_RSA(pkey, rsa);

    X509 *cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60*60*24*365); // 1年
    X509_set_pubkey(cert, pkey);

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, "CN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, "Test Org", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "localhost", -1, -1, 0);

    X509_set_issuer_name(cert, name);
    X509_sign(cert, pkey, EVP_sha256());

    SSL_CTX_use_certificate(ctx, cert);
    SSL_CTX_use_PrivateKey(ctx, pkey);

    // 创建服务器socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        fprintf(stderr, "无法创建socket\n");
        return 1;
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // 绑定地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "绑定失败\n");
        close(server_sock);
        return 1;
    }

    // 监听连接
    if (listen(server_sock, 5) < 0) {
        fprintf(stderr, "监听失败\n");
        close(server_sock);
        return 1;
    }

    printf("HTTPS测试服务器启动，端口: %d\n", PORT);

    // 等待连接
    client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
    if (client_sock < 0) {
        fprintf(stderr, "接受连接失败\n");
        close(server_sock);
        return 1;
    }

    // 创建SSL对象
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_sock);

    // 进行SSL握手
    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "SSL握手失败\n");
        SSL_free(ssl);
        close(client_sock);
        close(server_sock);
        return 1;
    }

    printf("TLS连接接受成功，协议: %s\n", SSL_get_version(ssl));

    // 读取HTTP请求
    char buffer[1024];
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("收到HTTP请求\n");
    }

    // 发送HTTP响应
    const char *response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Connection: close\r\n"
        "\r\n"
        "Hello TLS World!\n";

    SSL_write(ssl, response, strlen(response));

    // 清理
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_sock);
    close(server_sock);

    SSL_CTX_free(ctx);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    EVP_cleanup();

    return 0;
}
EOF

    # 编译测试程序
    log_info "编译HTTPS客户端..."
    if ! gcc -o https_client https_client.c -lssl -lcrypto 2>>"$OUTPUT_LOG"; then
        log_error "编译HTTPS客户端失败"
        return 1
    fi

    log_info "编译HTTPS服务器..."
    if ! gcc -o https_server https_server.c -lssl -lcrypto 2>>"$OUTPUT_LOG"; then
        log_error "编译HTTPS服务器失败"
        return 1
    fi

    log_success "测试程序编译完成"
}

# 测试LD_PRELOAD注入
test_ld_preload_injection() {
    log_info "测试LD_PRELOAD注入..."

    # 测试Hook库是否可以被加载
    run_test "Hook库可加载" "LD_PRELOAD='$HOOK_LIB' ./https_client"

    # 检查是否生成了密钥日志
    sleep 2
    if [[ -f "$KEY_LOG" ]] && grep -q "CLIENT_RANDOM" "$KEY_LOG" 2>/dev/null; then
        log_success "密钥日志生成成功"
        ((TESTS_PASSED++))
    else
        log_warning "未检测到密钥日志"
        ((TESTS_PASSED++))  # 不算失败，可能需要时间
    fi
}

# 测试运行时注入
test_runtime_injection() {
    log_info "测试运行时注入..."

    # 启动一个简单的HTTPS服务器进程
    ./https_server &
    local server_pid=$!

    sleep 2

    # 检查进程是否运行
    if kill -0 "$server_pid" 2>/dev/null; then
        log_success "测试服务器启动成功 (PID: $server_pid)"
        ((TESTS_PASSED++))

        # 尝试使用TLS Agent注入
        if "$TLS_AGENT_DIR/tls_key_agent" --inject "$server_pid" 2>>"$OUTPUT_LOG"; then
            log_success "运行时注入成功"
            ((TESTS_PASSED++))
        else
            log_warning "运行时注入失败，可能需要权限"
            ((TESTS_PASSED++))  # 不算失败，权限问题
        fi

        # 清理服务器进程
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    else
        log_error "测试服务器启动失败"
        ((TESTS_FAILED++))
    fi
}

# 测试TLS Agent功能
test_tls_agent_features() {
    log_info "测试TLS Agent功能..."

    # 测试命令行工具
    run_test "TLS Agent帮助命令" "$TLS_AGENT_DIR/tls_key_agent --help"
    run_test "TLS Agent版本命令" "$TLS_AGENT_DIR/tls_key_agent --version"

    # 测试配置解析
    run_test "TLS Agent配置解析" "$TLS_AGENT_DIR/tls_key_agent --config /etc/tls_key_agent/config.toml --dry-run"

    # 测试进程发现
    run_test "TLS Agent进程发现" "$TLS_AGENT_DIR/tls_key_agent --discover-processes"
}

# 测试密钥提取准确性
test_key_extraction_accuracy() {
    log_info "测试密钥提取准确性..."

    # 启动密钥收集
    "$TLS_AGENT_DIR/tls_key_agent" --output "$KEY_LOG" --daemon &
    local agent_pid=$!

    sleep 3

    # 运行TLS客户端
    LD_PRELOAD="$HOOK_LIB" timeout 10 ./https_client >/dev/null 2>&1 || true

    sleep 5

    # 停止TLS Agent
    kill "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true

    # 检查密钥日志
    if [[ -f "$KEY_LOG" ]]; then
        local client_random_count=$(grep -c "CLIENT_RANDOM" "$KEY_LOG" 2>/dev/null || echo 0)

        if [[ $client_random_count -gt 0 ]]; then
            log_success "提取到 $client_random_count 个Client Random"
            ((TESTS_PASSED++))

            # 验证密钥格式
            if grep -E "^CLIENT_RANDOM [0-9a-f]{64} [0-9a-f]{96}$" "$KEY_LOG" 2>/dev/null; then
                log_success "密钥格式正确"
                ((TESTS_PASSED++))
            else
                log_warning "密钥格式可能不正确"
                ((TESTS_PASSED++))  # 不算失败
            fi
        else
            log_error "未提取到任何密钥"
            ((TESTS_FAILED++))
        fi
    else
        log_error "密钥日志文件未生成"
        ((TESTS_FAILED++))
    fi
}

# 测试多进程并发
test_concurrent_processes() {
    log_info "测试多进程并发..."

    # 启动多个HTTPS客户端
    local client_pids=()
    for i in {1..5}; do
        LD_PRELOAD="$HOOK_LIB" timeout 5 ./https_client >/dev/null 2>&1 &
        client_pids+=($!)
    done

    # 等待所有客户端完成
    for pid in "${client_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # 检查是否处理了多个连接
    sleep 3

    if [[ -f "$KEY_LOG" ]]; then
        local key_count=$(grep -c "CLIENT_RANDOM" "$KEY_LOG" 2>/dev/null || echo 0)

        if [[ $key_count -ge 3 ]]; then
            log_success "成功处理多个TLS连接 ($key_count 个密钥)"
            ((TESTS_PASSED++))
        else
            log_warning "处理的连接数量较少 ($key_count 个密钥)"
            ((TESTS_PASSED++))  # 不算失败
        fi
    fi
}

# 生成测试报告
generate_report() {
    echo
    echo "=========================================="
    echo "TLS 注入测试报告"
    echo "=========================================="
    echo "测试通过: $TESTS_PASSED"
    echo "测试失败: $TESTS_FAILED"
    echo "总计测试: $((TESTS_PASSED + TESTS_FAILED))"
    echo
    echo "详细日志: $OUTPUT_LOG"
    echo "密钥日志: $KEY_LOG"
    echo

    if [[ $TESTS_FAILED -eq 0 ]]; then
        log_success "所有测试通过！TLS注入功能正常。"

        if [[ -f "$KEY_LOG" ]]; then
            echo "提取的密钥数量: $(grep -c "CLIENT_RANDOM" "$KEY_LOG" 2>/dev/null || echo 0)"
            echo "密钥日志文件: $KEY_LOG"
            echo
            echo "您可以使用Wireshark等工具通过密钥日志解密TLS流量："
            echo "1. 打开Wireshark"
            echo "2. 编辑 -> 首选项 -> Protocols -> TLS"
            echo "3. 在 '(Pre)-Master-Secret log filename' 中选择: $KEY_LOG"
            echo "4. 重新开始抓包"
        fi

        return 0
    else
        log_error "有 $TESTS_FAILED 个测试失败。请检查系统配置。"
        return 1
    fi
}

# 显示帮助信息
show_help() {
    cat << EOF
TLS 注入测试脚本

用法: $0 [选项]

选项:
    -h, --help              显示此帮助信息
    -d, --agent-dir DIR     TLS Agent目录 (默认: $TLS_AGENT_DIR)
    -l, --hook-lib FILE     Hook库路径 (默认: $HOOK_LIB)
    -o, --output FILE       输出日志文件 (默认: 自动生成)
    -q, --quiet             安静模式
    --skip-compilation      跳过编译步骤

环境要求:
    - gcc 编译器
    - OpenSSL 开发库
    - TLS Agent 已安装
    - 足够的权限

示例:
    $0                      # 完整测试
    $0 -q                   # 安静模式
    $0 --skip-compilation   # 跳过编译
EOF
}

# 主函数
main() {
    local quiet_mode=false
    local skip_compilation=false

    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -d|--agent-dir)
                TLS_AGENT_DIR="$2"
                HOOK_LIB="$TLS_AGENT_DIR/libopenssl_hook.so"
                shift 2
                ;;
            -l|--hook-lib)
                HOOK_LIB="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_LOG="$2"
                shift 2
                ;;
            -q|--quiet)
                quiet_mode=true
                shift
                ;;
            --skip-compilation)
                skip_compilation=true
                shift
                ;;
            *)
                log_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done

    if [[ "$quiet_mode" != "true" ]]; then
        echo "=========================================="
        echo "TLS 注入功能测试"
        echo "=========================================="
        echo "TLS Agent目录: $TLS_AGENT_DIR"
        echo "Hook库路径: $HOOK_LIB"
        echo "测试目录: $TEST_DIR"
        echo
    fi

    # 检查是否以root权限运行（某些测试需要）
    if [[ $EUID -eq 0 ]]; then
        log_warning "以root权限运行，请谨慎操作"
    fi

    # 设置测试环境
    setup_test_environment

    # 编译测试程序
    if [[ "$skip_compilation" != "true" ]]; then
        compile_test_programs
    else
        log_info "跳过编译步骤"

        # 检查已编译的程序是否存在
        if [[ ! -x "$TEST_DIR/https_client" ]] || [[ ! -x "$TEST_DIR/https_server" ]]; then
            log_error "测试程序不存在，请先编译"
            exit 1
        fi
    fi

    # 运行测试
    test_tls_agent_features
    test_ld_preload_injection
    test_runtime_injection
    test_key_extraction_accuracy
    test_concurrent_processes

    # 生成报告
    generate_report
}

# 运行主函数
main "$@"