/*
 * Web Scan Rust - 规则测试程序
 *
 * 此程序用于测试和支持的规则格式，验证规则解析和匹配功能
 * 编译方法参考 build_and_test.sh 中的C集成示例
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "web_scan_rust.h"

void test_basic_rules() {
    printf("=== 测试基础规则 ===\n");

    // 测试1: 简单URI匹配
    const char* payload1 = "GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n";
    WebScanResult result1;
    memset(&result1, 0, sizeof(result1));

    int ret1 = web_scan_rust_process_payload(
        (const uint8_t*)payload1,
        strlen(payload1),
        &result1
    );

    printf("测试1 - 简单URI匹配: %s (规则ID: %u)\n",
           result1.is_matched ? "✅ 匹配" : "❌ 未匹配", result1.rule_id);

    // 测试2: HTTP方法匹配
    const char* payload2 = "POST /api/login HTTP/1.1\r\nHost: example.com\r\n\r\n";
    WebScanResult result2;
    memset(&result2, 0, sizeof(result2));

    int ret2 = web_scan_rust_process_payload(
        (const uint8_t*)payload2,
        strlen(payload2),
        &result2
    );

    printf("测试2 - HTTP方法匹配: %s (规则ID: %u)\n",
           result2.is_matched ? "✅ 匹配" : "❌ 未匹配", result2.rule_id);
}

void test_request_body_rules() {
    printf("\n=== 测试请求体规则 ===\n");

    // 测试3: 请求体匹配
    const char* payload3 = "POST /login HTTP/1.1\r\nHost: example.com\r\n"
                          "Content-Length: 25\r\n\r\n"
                          "username=admin&password=123";
    WebScanResult result3;
    memset(&result3, 0, sizeof(result3));

    int ret3 = web_scan_rust_process_payload(
        (const uint8_t*)payload3,
        strlen(payload3),
        &result3
    );

    printf("测试3 - 请求体匹配: %s (规则ID: %u)\n",
           result3.is_matched ? "✅ 匹配" : "❌ 未匹配", result3.rule_id);

    // 测试4: SQL注入检测
    const char* payload4 = "POST /search HTTP/1.1\r\nHost: example.com\r\n"
                          "Content-Length: 45\r\n\r\n"
                          "query=test' UNION SELECT * FROM users--";
    WebScanResult result4;
    memset(&result4, 0, sizeof(result4));

    int ret4 = web_scan_rust_process_payload(
        (const uint8_t*)payload4,
        strlen(payload4),
        &result4
    );

    printf("测试4 - SQL注入检测: %s (规则ID: %u)\n",
           result4.is_matched ? "✅ 匹配" : "❌ 未匹配", result4.rule_id);
}

void test_segmented_packets() {
    printf("\n=== 测试分段数据包 ===\n");

    uint64_t session_id = 10001;

    // 第一个分段：HTTP头部
    const char* segment1 = "POST /api/upload HTTP/1.1\r\n"
                          "Host: example.com\r\n"
                          "Content-Type: multipart/form-data\r\n"
                          "Content-Length: 100\r\n\r\n";

    WebScanResult result1;
    memset(&result1, 0, sizeof(result1));

    int ret1 = web_scan_rust_process_payload_with_session(
        session_id,
        (const uint8_t*)segment1,
        strlen(segment1),
        0,  // is_final = 0
        0,  // reset_on_request_end = 0
        &result1
    );

    printf("分段1 - HTTP头部: %s\n", ret1 == 0 ? "✅ 处理成功" : "❌ 处理失败");

    // 第二个分段：文件数据
    const char* segment2 = "------WebKitFormBoundary\r\n"
                          "Content-Disposition: form-data; name=\"file\"; filename=\"test.php\"\r\n\r\n"
                          "<?php echo 'malicious'; ?>\r\n"
                          "------WebKitFormBoundary--\r\n";

    WebScanResult result2;
    memset(&result2, 0, sizeof(result2));

    int ret2 = web_scan_rust_process_payload_with_session(
        session_id,
        (const uint8_t*)segment2,
        strlen(segment2),
        1,  // is_final = 1
        0,  // reset_on_request_end = 0
        &result2
    );

    printf("分段2 - 文件上传检测: %s (规则ID: %u)\n",
           result2.is_matched ? "✅ 匹配" : "❌ 未匹配", result2.rule_id);

    // 关闭会话
    web_scan_rust_close_session(session_id);
}

void test_fast_patterns() {
    printf("\n=== 测试Fast Pattern优化 ===\n");

    // 测试Fast Pattern在header中的规则
    const char* payload_fast = "GET /admin/login.php HTTP/1.1\r\n"
                              "Host: example.com\r\n"
                              "User-Agent: curl/7.68.0\r\n"
                              "Cookie: sessionid=abc123\r\n\r\n"
                              "username=admin&password=secret";

    WebScanResult result_fast;
    memset(&result_fast, 0, sizeof(result_fast));

    int ret_fast = web_scan_rust_process_payload(
        (const uint8_t*)payload_fast,
        strlen(payload_fast),
        &result_fast
    );

    printf("Fast Pattern测试: %s (规则ID: %u)\n",
           result_fast.is_matched ? "✅ 匹配" : "❌ 未匹配", result_fast.rule_id);
}

void print_statistics() {
    printf("\n=== 统计信息 ===\n");

    WebScanStats stats;
    int ret = web_scan_rust_get_stats(&stats);

    if (ret == 0) {
        printf("总数据包数: %lu\n", stats.packets_processed);
        printf("匹配数据包数: %lu\n", stats.packets_matched);
        printf("HTTP数据包数: %lu\n", stats.http_packets);
        printf("HTTPS数据包数: %lu\n", stats.https_packets);
        printf("HTTP/2数据包数: %lu\n", stats.http2_packets);
        printf("总处理时间: %lu 微秒\n", stats.total_processing_time_us);
    } else {
        printf("❌ 获取统计信息失败\n");
    }
}

int main() {
    printf("Web Scan Rust - 规则测试程序\n");
    printf("版本: v0.1.0\n");
    printf("测试规则文件: examples/supported_rules.rules\n\n");

    // 初始化引擎
    printf("正在初始化引擎...\n");
    if (web_scan_rust_init_with_hyperscan() != 0) {
        printf("❌ 引擎初始化失败: %s\n", web_scan_rust_get_last_error());
        return 1;
    }

    // 启用引擎
    web_scan_rust_set_enabled(1);
    web_scan_rust_reset_stats();

    // 加载规则文件
    printf("正在加载规则文件...\n");
    const char* rules_file = "examples/supported_rules.rules";

    // 检查规则文件是否存在
    if (access(rules_file, R_OK) != 0) {
        printf("❌ 规则文件不存在: %s\n", rules_file);
        printf("请确保规则文件存在并可读\n");
        web_scan_rust_cleanup();
        return 1;
    }

    // 将字符串转换为C字符串
    char rules_path[256];
    snprintf(rules_path, sizeof(rules_path), "%s", rules_file);

    int load_result = web_scan_rust_load_rules(rules_path);
    if (load_result != 0) {
        printf("❌ 规则加载失败: %s\n", web_scan_rust_get_last_error());
        web_scan_rust_cleanup();
        return 1;
    }

    printf("✅ 规则加载成功\n");

    // 检查Hyperscan状态
    if (web_scan_rust_is_hyperscan_enabled()) {
        printf("✅ Hyperscan加速已启用\n");
    } else {
        printf("⚠️  Hyperscan加速未启用\n");
    }

    // 运行测试
    test_basic_rules();
    test_request_body_rules();
    test_segmented_packets();
    test_fast_patterns();

    // 显示统计信息
    print_statistics();

    // 清理
    printf("\n正在清理引擎...\n");
    web_scan_rust_cleanup();

    printf("\n✅ 测试完成\n");
    printf("\n支持的规则特性:\n");
    printf("✅ HTTP协议检测和解析\n");
    printf("✅ 基础content匹配\n");
    printf("✅ HTTP位置修饰符 (method, uri, cookie, header, body)\n");
    printf("✅ 内容修饰符 (startswith, endswith, depth, offset, within, distance)\n");
    printf("✅ 多content模式规则\n");
    printf("✅ Fast Pattern优化\n");
    printf("✅ 分段数据包处理\n");
    printf("✅ 元数据和分类\n");

    printf("\n不支持的特性:\n");
    printf("❌ 正则表达式 (pcre)\n");
    printf("❌ Flow选项\n");
    printf("❌ 字节码检测\n");
    printf("❌ IP列表和端口范围\n");
    printf("❌ 文件检测和提取\n");

    return 0;
}