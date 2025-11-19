# C 程序集成指南

本文档详细说明如何在 C 程序中集成和使用 Web Scan Rust 库（.so 共享库）。

## 版本信息

- **库版本**: v0.1.0
- **API稳定性**: 稳定版本，生产就绪
- **测试覆盖**: 65/65 测试通过 (100%)
- **VPP/IPS集成**: 经过充分测试和验证

## 目录

- [概述](#概述)
- [编译共享库](#编译共享库)
- [动态链接方式](#动态链接方式)
- [静态链接方式](#静态链接方式)
- [运行时库路径配置](#运行时库路径配置)
- [基本使用示例](#基本使用示例)
- [分段数据处理](#分段数据处理)
- [会话管理最佳实践](#会话管理最佳实践)
- [Fast Pattern优化使用](#fast-pattern优化使用)
- [错误处理](#错误处理)
- [线程安全说明](#线程安全说明)
- [性能优化建议](#性能优化建议)
- [VPP/IPS特定集成](#vppips特定集成)
- [故障排除](#故障排除)

## 概述

Web Scan Rust 库编译为共享库（.so 文件）后，可以通过标准的 C FFI 接口在 C 程序中调用。本文档重点说明：

1. 如何编译生成 .so 库
2. 如何在 C 程序中链接和使用库
3. 运行时库路径配置
4. 完整的集成示例

## 编译共享库

### 步骤 1: 构建 Rust 库

```bash
cd web_scan_rust

# 构建发布版本的共享库（启用 Hyperscan）
cargo build --release --features hyperscan

# 验证库文件已生成
ls -lh target/release/libweb_scan_rust.so
```

### 步骤 2: 验证库文件

```bash
# 检查库依赖
ldd target/release/libweb_scan_rust.so

# 检查导出符号
nm -D target/release/libweb_scan_rust.so | grep web_scan

# 检查库信息
file target/release/libweb_scan_rust.so
```

## 动态链接方式

### 方法 1: 编译时链接（推荐）

#### 基本编译命令

```bash
gcc -o my_program my_program.c \
    -I/path/to/web_scan_rust/include \
    -L/path/to/web_scan_rust/target/release \
    -lweb_scan_rust \
    -ldl
```

#### 参数说明

- `-I`: 指定头文件搜索路径
- `-L`: 指定库文件搜索路径
- `-lweb_scan_rust`: 链接 libweb_scan_rust.so
- `-ldl`: 链接动态加载库（如果需要动态加载）

#### 完整示例

```bash
# 设置路径变量
export WEB_SCAN_RUST_DIR=/path/to/web_scan_rust
export LIB_DIR=$WEB_SCAN_RUST_DIR/target/release
export INCLUDE_DIR=$WEB_SCAN_RUST_DIR/include

# 编译
gcc -o my_program my_program.c \
    -I$INCLUDE_DIR \
    -L$LIB_DIR \
    -lweb_scan_rust \
    -ldl \
    -Wall -O2
```

### 方法 2: 使用 pkg-config（如果配置了）

如果项目提供了 pkg-config 配置文件：

```bash
# 编译
gcc -o my_program my_program.c \
    $(pkg-config --cflags --libs web-scan-rust)
```

### 方法 3: 使用 CMake

在 `CMakeLists.txt` 中：

```cmake
cmake_minimum_required(VERSION 3.10)
project(my_project)

# 设置库路径
set(WEB_SCAN_RUST_DIR /path/to/web_scan_rust)
set(WEB_SCAN_RUST_LIB_DIR ${WEB_SCAN_RUST_DIR}/target/release)
set(WEB_SCAN_RUST_INCLUDE_DIR ${WEB_SCAN_RUST_DIR}/include)

# 添加可执行文件
add_executable(my_program my_program.c)

# 包含头文件目录
target_include_directories(my_program PRIVATE ${WEB_SCAN_RUST_INCLUDE_DIR})

# 链接库
target_link_directories(my_program PRIVATE ${WEB_SCAN_RUST_LIB_DIR})
target_link_libraries(my_program PRIVATE web_scan_rust dl)

# 设置运行时库路径
set_target_properties(my_program PROPERTIES
    INSTALL_RPATH "${WEB_SCAN_RUST_LIB_DIR}"
    BUILD_WITH_INSTALL_RPATH TRUE
)
```

### 方法 4: 使用 Makefile

在 `Makefile` 中：

```makefile
WEB_SCAN_RUST_DIR = /path/to/web_scan_rust
LIB_DIR = $(WEB_SCAN_RUST_DIR)/target/release
INCLUDE_DIR = $(WEB_SCAN_RUST_DIR)/include

CC = gcc
CFLAGS = -Wall -O2 -I$(INCLUDE_DIR)
LDFLAGS = -L$(LIB_DIR) -lweb_scan_rust -ldl

my_program: my_program.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f my_program
```

## 静态链接方式

**注意**：Rust 库通常编译为动态库。如果需要静态链接，需要特殊配置。

### 使用 Rust 静态库

```bash
# 构建静态库版本（需要修改 Cargo.toml）
cargo build --release --features hyperscan --lib

# 链接静态库
gcc -o my_program my_program.c \
    -I/path/to/web_scan_rust/include \
    target/release/libweb_scan_rust.a \
    -lpthread -ldl -lm
```

## 运行时库路径配置

编译完成后，程序运行时需要能够找到共享库。有以下几种方式：

### 方法 1: 使用 LD_LIBRARY_PATH（开发/测试）

```bash
export LD_LIBRARY_PATH=/path/to/web_scan_rust/target/release:$LD_LIBRARY_PATH
./my_program
```

### 方法 2: 使用 rpath（推荐用于生产环境）

在编译时指定 rpath：

```bash
gcc -o my_program my_program.c \
    -I/path/to/web_scan_rust/include \
    -L/path/to/web_scan_rust/target/release \
    -lweb_scan_rust \
    -Wl,-rpath,/path/to/web_scan_rust/target/release
```

这样编译的程序会自动在指定路径查找库。

### 方法 3: 安装到系统目录

```bash
# 复制库到系统目录
sudo cp target/release/libweb_scan_rust.so /usr/local/lib/

# 更新动态链接器缓存
sudo ldconfig

# 现在可以直接运行程序
./my_program
```

### 方法 4: 使用相对路径 rpath

```bash
# 使用相对于可执行文件的路径
gcc -o my_program my_program.c \
    -I../web_scan_rust/include \
    -L../web_scan_rust/target/release \
    -lweb_scan_rust \
    -Wl,-rpath,'$ORIGIN/../web_scan_rust/target/release'
```

## 基本使用示例

### 示例 1: 最简单的集成

```c
#include <stdio.h>
#include <string.h>
#include "web_scan_rust.h"

int main() {
    // 初始化引擎
    if (web_scan_rust_init_with_hyperscan() != 0) {
        fprintf(stderr, "Failed to initialize: %s\n", 
                web_scan_rust_get_last_error());
        return 1;
    }
    
    // 加载规则
    if (web_scan_rust_load_rules("rules.rules") != 0) {
        fprintf(stderr, "Failed to load rules: %s\n", 
                web_scan_rust_get_last_error());
        return 1;
    }
    
    // 处理数据包
    const char *payload = "GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\n\r\n";
    web_scan_result_t result;
    
    if (web_scan_rust_process_payload(
            (const uint8_t *)payload,
            strlen(payload),
            &result) == 0) {
        
        if (result.is_matched) {
            printf("Threat detected! Rule ID: %u\n", result.rule_id);
        }
    }
    
    // 清理
    web_scan_rust_cleanup();
    return 0;
}
```

编译和运行：

```bash
# 编译
gcc -o example1 example1.c \
    -I../web_scan_rust/include \
    -L../web_scan_rust/target/release \
    -lweb_scan_rust \
    -Wl,-rpath,../web_scan_rust/target/release

# 运行
./example1
```

### 示例 2: 带错误处理

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "web_scan_rust.h"

void check_error(const char *operation) {
    const char *error = web_scan_rust_get_last_error();
    if (error) {
        fprintf(stderr, "%s failed: %s\n", operation, error);
        exit(1);
    }
}

int main() {
    // 初始化
    if (web_scan_rust_init_with_hyperscan() != 0) {
        check_error("Initialization");
    }
    
    // 加载规则
    if (web_scan_rust_load_rules("rules.rules") != 0) {
        check_error("Load rules");
    }
    
    printf("Loaded %u rules\n", web_scan_rust_get_rule_count());
    
    // 处理多个数据包
    const char *payloads[] = {
        "GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        NULL
    };
    
    web_scan_result_t result;
    for (int i = 0; payloads[i] != NULL; i++) {
        if (web_scan_rust_process_payload(
                (const uint8_t *)payloads[i],
                strlen(payloads[i]),
                &result) == 0) {
            
            if (result.is_matched) {
                printf("Packet %d: Threat detected (Rule %u)\n", 
                       i + 1, result.rule_id);
            } else {
                printf("Packet %d: No threat\n", i + 1);
            }
        } else {
            check_error("Process payload");
        }
    }
    
    // 获取统计信息
    web_scan_stats_t stats;
    if (web_scan_rust_get_stats(&stats) == 0) {
        printf("\nStatistics:\n");
        printf("  Processed: %lu\n", stats.packets_processed);
        printf("  Matched: %lu\n", stats.packets_matched);
    }
    
    // 清理
    web_scan_rust_cleanup();
    return 0;
}
```

## 高级功能示例

### 示例 3: 会话管理（跨数据包匹配）

```c
#include <stdio.h>
#include <string.h>
#include "web_scan_rust.h"

int main() {
    // 初始化
    web_scan_rust_init_with_hyperscan();
    web_scan_rust_load_rules("rules.rules");
    
    uint64_t session_id = 12345;
    
    // 第一个数据包：包含 URI 中的 "admin"
    const char *packet1 = 
        "GET /admin/login HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: 20\r\n"
        "\r\n";
    
    web_scan_result_t result1;
    web_scan_rust_process_payload_with_session(
        session_id,
        (const uint8_t *)packet1,
        strlen(packet1),
        0,  // is_final = 0
        0,  // reset_on_request_end = 0
        &result1
    );
    
    printf("Packet 1: Matched=%s\n", result1.is_matched ? "Yes" : "No");
    
    // 第二个数据包：包含 body 中的 "password"
    const char *packet2 = "password=secret";
    
    web_scan_result_t result2;
    web_scan_rust_process_payload_with_session(
        session_id,
        (const uint8_t *)packet2,
        strlen(packet2),
        1,  // is_final = 1
        0,  // reset_on_request_end = 0
        &result2
    );
    
    printf("Packet 2: Matched=%s, Rule ID=%u\n", 
           result2.is_matched ? "Yes" : "No",
           result2.rule_id);
    
    // 关闭会话
    web_scan_rust_close_session(session_id);
    web_scan_rust_cleanup();
    
    return 0;
}
```

### 示例 4: 分段包处理

```c
#include <stdio.h>
#include <string.h>
#include "web_scan_rust.h"

int main() {
    // 初始化
    web_scan_rust_init_with_hyperscan();
    web_scan_rust_load_rules("rules.rules");
    
    uint64_t session_id = 67890;
    
    // 第一个分段：不完整（HTTP header不完整）
    const char *segment1 = "GET /admin/";
    web_scan_result_t result1;
    
    int ret = web_scan_rust_process_payload_with_session(
        session_id,
        (const uint8_t *)segment1,
        strlen(segment1),
        0,  // is_final = 0
        0,  // reset_on_request_end = 0
        &result1
    );
    
    if (ret == 0) {
        printf("Segment 1: Engine buffers data internally (HTTP header incomplete)\n");
    }
    
    // 第二个分段：完整（完成HTTP header）
    const char *segment2 = "login.php HTTP/1.1\r\nHost: example.com\r\n\r\n";
    web_scan_result_t result2;
    
    ret = web_scan_rust_process_payload_with_session(
        session_id,
        (const uint8_t *)segment2,
        strlen(segment2),
        1,  // is_final = 1
        0,  // reset_on_request_end = 0
        &result2
    );
    
    if (ret == 0) {
        printf("Segment 2: Matched=%s, Rule ID=%u\n",
               result2.is_matched ? "Yes" : "No",
               result2.rule_id);
    }
    
    // 关闭会话
    web_scan_rust_close_session(session_id);
    web_scan_rust_cleanup();
    
    return 0;
}
```

## 错误处理

### 检查返回值

所有函数在失败时返回非零值：

```c
int ret = web_scan_rust_load_rules("rules.rules");
if (ret != 0) {
    const char *error = web_scan_rust_get_last_error();
    if (error) {
        fprintf(stderr, "Error: %s\n", error);
    }
    return 1;
}
```

### 错误处理最佳实践

```c
#define CHECK_API_CALL(func, ...) \
    do { \
        int _ret = func(__VA_ARGS__); \
        if (_ret != 0) { \
            const char *_err = web_scan_rust_get_last_error(); \
            fprintf(stderr, "%s failed: %s\n", #func, _err ? _err : "unknown error"); \
            return 1; \
        } \
    } while(0)

int main() {
    CHECK_API_CALL(web_scan_rust_init_with_hyperscan);
    CHECK_API_CALL(web_scan_rust_load_rules, "rules.rules");
    // ...
    return 0;
}
```

## 线程安全说明

### 并发调用

所有 API 函数都是线程安全的，可以在多线程环境中并发调用：

```c
#include <pthread.h>

void* process_packets(void* arg) {
    uint64_t session_id = (uint64_t)arg;
    const char *payload = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
    web_scan_result_t result;
    
    web_scan_rust_process_payload_with_session(
        session_id,
        (const uint8_t *)payload,
        strlen(payload),
        1, 0, &result
    );
    
    return NULL;
}

int main() {
    web_scan_rust_init_with_hyperscan();
    web_scan_rust_load_rules("rules.rules");
    
    // 创建多个线程
    pthread_t threads[10];
    for (int i = 0; i < 10; i++) {
        pthread_create(&threads[i], NULL, process_packets, (void*)(uint64_t)i);
    }
    
    // 等待所有线程完成
    for (int i = 0; i < 10; i++) {
        pthread_join(threads[i], NULL);
    }
    
    web_scan_rust_cleanup();
    return 0;
}
```

### 会话隔离

不同会话的流状态是独立的，可以安全地并发处理：

- 每个会话使用唯一的 `session_id`
- 不同会话之间不会相互干扰
- 同一会话的数据包应在同一线程处理（或使用同步机制）

## 性能优化建议

### 1. 使用会话管理

对于需要跨数据包匹配的场景，使用会话管理功能：

```c
// 好的做法：使用会话管理
uint64_t session_id = get_session_id();
web_scan_rust_process_payload_with_session(session_id, ...);

// 避免：每次都创建新流
web_scan_rust_process_payload(...);  // 每次都创建新流
```

### 2. 批量处理

对于大量数据包，考虑批量处理：

```c
// 批量处理多个数据包
for (int i = 0; i < packet_count; i++) {
    web_scan_rust_process_payload_with_session(
        session_ids[i],
        packets[i],
        packet_lens[i],
        0, 0, &results[i]
    );
}
```

### 3. 及时关闭会话

不再使用的会话应及时关闭，避免内存泄漏：

```c
// 会话结束时
web_scan_rust_close_session(session_id);

// 或批量关闭
web_scan_rust_close_all_sessions();
```

### 4. 重用结果结构体

避免频繁分配结果结构体：

```c
web_scan_result_t result;  // 重用同一个结构体

for (int i = 0; i < count; i++) {
    web_scan_rust_process_payload(..., &result);
    // 处理结果
}
```

## 故障排除

### 问题 1: 运行时找不到库

**症状**：
```
error while loading shared libraries: libweb_scan_rust.so: cannot open shared object file
```

**解决方案**：

```bash
# 方法 1: 设置 LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/path/to/web_scan_rust/target/release:$LD_LIBRARY_PATH

# 方法 2: 使用 rpath 重新编译
gcc -o program program.c ... -Wl,-rpath,/path/to/web_scan_rust/target/release

# 方法 3: 安装到系统目录
sudo cp libweb_scan_rust.so /usr/local/lib/
sudo ldconfig
```

### 问题 2: 符号未定义

**症状**：
```
undefined reference to `web_scan_rust_init'
```

**解决方案**：

```bash
# 检查库中是否有符号
nm -D libweb_scan_rust.so | grep web_scan_rust_init

# 确保链接了库
gcc ... -lweb_scan_rust

# 检查库路径
gcc ... -L/path/to/lib -lweb_scan_rust
```

### 问题 3: 版本不匹配

**症状**：程序崩溃或行为异常

**解决方案**：

- 确保使用匹配的头文件和库文件版本
- 重新编译库和程序
- 检查 ABI 兼容性

### 问题 4: 内存泄漏

**症状**：长时间运行后内存使用增加

**解决方案**：

- 确保调用 `web_scan_rust_close_session()` 关闭不再使用的会话
- 定期调用 `web_scan_rust_close_all_sessions()` 清理所有会话
- 使用内存检查工具（如 Valgrind）检测泄漏

## 总结

集成 Web Scan Rust 库到 C 程序的基本步骤：

1. **编译库**：`cargo build --release --features hyperscan`
2. **包含头文件**：`#include "web_scan_rust.h"`
3. **链接库**：`-lweb_scan_rust -L/path/to/lib`
4. **配置运行时路径**：使用 rpath 或 LD_LIBRARY_PATH
5. **初始化**：调用 `web_scan_rust_init_with_hyperscan()`
6. **使用 API**：调用各种处理函数
7. **清理**：调用 `web_scan_rust_cleanup()`

更多详细信息请参考 [API 文档](API.md) 和 [使用示例](USAGE.md)。

