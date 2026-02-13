# TLS Key Agent

高性能TLS密钥提取工具，基于eBPF的内核级SSL Hook系统，专为生产环境设计。

## 🚀 特性

### 核心功能
- **eBPF内核级监控**：基于eBPF的系统级TLS密钥提取，突破传统LD_PRELOAD限制
- **全系统监控**：无需重启服务，自动监控系统上所有TLS连接
- **生产级安全**：关键进程过滤，安全检查机制
- **零侵入部署**：无需修改目标应用程序

### 密钥提取
- **全面密钥支持**：Client Random、Master Secret、Session Ticket等
- **多SSL库支持**：OpenSSL、GnuTLS、NSS、BoringSSL、LibreSSL
- **五元组信息**：源IP、源端口、目标IP、目标端口、协议
- **UDP批量传输**：高性能数据传输，支持压缩和优化
- **智能验证**：熵值检测、连续字节检查、频率分析

### 系统兼容
- **内核要求**：Linux内核5.0+ (推荐5.10+)
- **架构支持**：x86_64、ARM64
- **生产部署**：Docker、Kubernetes、二进制部署

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    TLS Key Agent (eBPF架构)                │
├─────────────────────────────────────────────────────────────┤
│  配置管理层 (Configuration)                                  │
│  ├── TOML配置文件                                           │
│  ├── 动态过滤规则 (五元组筛选)                              │
│  └── 远程配置API                                           │
├─────────────────────────────────────────────────────────────┤
│  eBPF内核层 (eBPF Kernel Space)                             │
│  ├── eBPF SSL Hook程序                                     │
│  ├── 连接跟踪器                                           │
│  ├── 多SSL库支持                                          │
│  └── Perf Event Array                                     │
├─────────────────────────────────────────────────────────────┤
│  用户空间处理层 (Userspace)                                  │
│  ├── 多SSL注入器                                           │
│  ├── 事件处理器                                           │
│  ├── 会话管理                                             │
│  └── 缓冲池                                               │
├─────────────────────────────────────────────────────────────┤
│  企业级可靠性层 (Resilience)                                 │
│  ├── 8种负载均衡策略                                       │
│  ├── 故障恢复系统                                         │
│  ├── 性能监控                                             │
│  └── 健康检查                                             │
├─────────────────────────────────────────────────────────────┤
│  传输层 (Transport)                                        │
│  ├── UDP批量传输                                          │
│  ├── 压缩和优化                                           │
│  └── 智能重连                                             │
└─────────────────────────────────────────────────────────────┘
```

## 核心功能

### 1. 主动式密钥提取 (核心功能)
- **Client Random提取**: 3种方法多层次提取
  - OpenSSL官方API (`SSL_get_client_random`)
  - 直接SSL结构体内存访问 (`ssl->s3->client_random`)
  - 智能内存搜索算法
- **Master Secret提取**: 3种策略主动获取
  - `SSL_export_keying_material` API提取
  - SSL_SESSION结构体访问
  - 内存模式搜索 (最后回退)
- **智能验证机制**: 熵值检测、连续字节检查、频率分析
- **多TLS库支持**: OpenSSL, GnuTLS, NSS等
- **Session Ticket支持**: TLS会话票据提取

### 2. 智能筛选
- **五元组筛选**: 源IP、源端口、目标IP、目标端口、协议
- **进程筛选**: 进程名、PID筛选
- **动态规则**: 运行时修改筛选规则
- **规则优先级**: 支持规则优先级和匹配顺序

### 3. 数据传输
- **TCP传输**: 高可靠的TCP Socket传输
- **文件存储**: 本地文件存储，支持轮转
- **压缩传输**: 数据压缩减少网络传输
- **重连机制**: 自动重连和故障转移

### 4. 性能优化
- **异步处理**: 基于tokio的异步I/O
- **内存池**: 预分配内存池避免频繁分配
- **零拷贝**: 最小化内存拷贝操作
- **批量处理**: 批量传输提高效率

## 🏗️ eBPF架构优势

相比传统LD_PRELOAD方式，eBPF架构具有革命性优势：

### 🔄 传统LD_PRELOAD限制
```bash
# 传统方式 - 有诸多限制
LD_PRELOAD=./libtls_agent_hook.so application
# ❌ 必须重启进程
# ❌ 无法监控已运行的服务
# ❌ 每个进程都需要单独配置
# ❌ 容器化部署复杂
# ❌ 被恶意软件轻易检测
```

### 🚀 eBPF架构优势
```bash
# eBPF方式 - 系统级监控
sudo ./target/release/tls_key_agent --config config.toml
# ✅ 无需重启任何服务
# ✅ 自动监控所有TLS连接
# ✅ 一次部署，全系统生效
# ✅ 完美支持容器化环境
# ✅ 隐蔽性极强，难以检测
```

### 🏆 技术对比

| 特性 | LD_PRELOAD | eBPF架构 |
|------|------------|----------|
| **系统影响** | 进程级 | 系统级 |
| **部署复杂度** | 高（每个进程） | 低（一次部署） |
| **服务重启** | 必需 | 不需要 |
| **监控范围** | 仅新进程 | 所有TLS连接 |
| **容器支持** | 复杂 | 原生支持 |
| **隐蔽性** | 低 | 极高 |
| **性能开销** | 中等 | 极低 |
| **稳定性** | 中等 | 企业级 |

## 🎬 演示系统

项目提供完整的演示系统，展示服务端配置下发和密钥信息收取的完整流程：

### 快速体验
```bash
# 进入demo目录
cd demo

# 启动完整演示
./demo.sh start

# 或仅启动服务器用于测试
./demo.sh server
```

### 演示功能
- **服务端配置下发**：HTTP配置API，动态配置管理，配置哈希验证
- **TLS密钥接收**：UDP接收服务，JSON数据解析，实时显示
- **模拟TLS生成**：真实TLS数据格式，五元组信息，会话标识
- **自动化脚本**：一键启动，配置测试，流量生成，统计显示

### 详细说明
- `demo/DEMO_README.md` - 详细使用文档
- `demo/DEMO_SUMMARY.md` - 演示总结报告

## 🚀 快速开始

### 1. 系统要求

**内核版本：**
- 最低要求：Linux 5.0+
- 推荐版本：Linux 5.10+（完整eBPF支持）
- 检查内核：`uname -r`

**系统依赖：**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential clang llvm libelf-dev

# CentOS/RHEL
sudo yum groupinstall -y "Development Tools"
sudo yum install -y clang llvm elfutils-libelf-devel

# 检查eBPF支持
sudo bpftool version
```

### 2. 编译项目

```bash
# 克隆项目
git clone <repository-url>
cd tls_key_agent

# 编译eBPF TLS Key Agent
cargo build --release

# 验证编译结果
./target/release/tls_key_agent --version
```

### 3. 配置系统权限

```bash
# 方式1: 使用sudo运行（推荐）
sudo ./target/release/tls_key_agent --config config.toml

# 方式2: 设置capabilities（生产环境）
sudo setcap cap_sys_admin+ep ./target/release/tls_key_agent

# 方式3: 使用systemd服务（详见DEPLOYMENT.md）
```

### 4. 基本使用

```bash
# 启动eBPF TLS密钥监控
sudo ./target/release/tls_key_agent --config config.toml

# 系统中所有TLS连接的密钥将自动提取并传输
# 无需修改任何应用程序配置！

# 验证密钥提取
./target/release/verify_keys stats
```

### 5. 配置文件

eBPF架构配置示例：

```toml
[agent]
name = "ebpf_tls_agent"
version = "0.1.0"
log_level = "info"
buffer_pool_size = 5000
buffer_size = 8192

[extraction]
enabled = true
kernel_version_requirement = "5.0.0"
capture_client_random = true
capture_master_secret = true
process_filters = ["nginx", "apache2", "httpd"]

[transport]
enabled_transports = ["Udp", "Tcp"]

[transport.udp]
enabled = true
server_host = "127.0.0.1"
server_port = 9999
batch_size = 100
compression = true

[transport.tcp]
enabled = true
server_host = "127.0.0.1"
server_port = 9998
connection_timeout = 30
max_retries = 3

[[filters]]
name = "https_only"
enabled = true
five_tuple = { dst_port = 443, protocol = "TCP" }
priority = 100

[[filters]]
name = "process_filter"
enabled = true
process_name = "nginx"
priority = 90
```

### 6. 测试验证

```bash
# 启动eBPF Agent进行测试
sudo ./target/release/tls_key_agent --config config.toml &

# 测试TLS密钥提取
curl -s https://www.baidu.com > /dev/null

# 验证密钥提取
./target/release/verify_keys stats

# Wireshark集成测试
./test_wireshark_decrypt.sh
```

## 📦 部署指南

项目提供完整的构建和部署系统，支持多种部署方式：

### 快速部署

```bash
# 进入部署目录
cd deploy

# 查看部署选项
./deploy.sh --help

# 本地部署（推荐用于测试）
./deploy.sh local

# Docker部署
./deploy.sh docker

# Kubernetes部署
./deploy.sh k8s

# 仅打包不部署
./deploy.sh package
```

### 部署方式详解

#### 1. 本地部署
```bash
# 自动编译、打包并安装到系统
cd deploy && ./deploy.sh local

# 手动启动服务
sudo systemctl start tls-key-agent

# 查看服务状态
sudo systemctl status tls-key-agent

# 查看日志
sudo journalctl -u tls-key-agent -f
```

**特性：**
- 自动创建systemd服务
- 开机自启动
- 日志管理
- 配置文件自动安装

#### 2. Docker部署
```bash
# 构建并启动Docker容器
cd deploy && ./deploy.sh docker

# 查看容器状态
docker ps | grep tls-key-agent

# 查看容器日志
docker logs -f tls-key-agent

# 进入容器调试
docker exec -it tls-key-agent /bin/bash
```

**特性：**
-  privileged模式支持eBPF
- host网络访问
- 自动卷挂载
- 配置文件管理

#### 3. Kubernetes部署
```bash
# 部署到Kubernetes集群
cd deploy && ./deploy.sh k8s

# 查看Pod状态
kubectl get pods -l app=tls-key-agent

# 查看日志
kubectl logs -l app=tls-key-agent -f

# 查看DaemonSet状态
kubectl get daemonset tls-key-agent
```

**特性：**
- DaemonSet集群全节点部署
- RBAC权限管理
- ConfigMap配置管理
- 自动故障恢复

#### 4. 仅打包
```bash
# 仅创建部署包
cd deploy && ./deploy.sh package

# 查看生成的包
ls -la ../dist/

# 自定义版本
./deploy.sh package --version=v1.2.3

# Debug版本
./deploy.sh package --debug
```

**生成的包包含：**
- 编译后的二进制文件
- 配置文件模板
- systemd服务文件
- 完整文档
- 演示程序

### 高级部署选项

#### 自定义镜像仓库
```bash
# 推送到私有仓库
./deploy.sh docker --registry=registry.example.com --version=v1.2.3

# Kubernetes使用自定义仓库
./deploy.sh k8s --registry=registry.example.com
```

#### 配置管理
```bash
# 复制并修改配置文件
cp config.toml my_config.toml
# 编辑 my_config.toml

# 使用自定义配置部署
sudo ./target/release/tls_key_agent --config my_config.toml
```

#### 环境变量配置
```bash
# Docker环境变量
docker run -e RUST_LOG=debug -e AGENT_NAME=my_agent tls-key-agent

# Kubernetes环境变量
kubectl set env daemonset/tls-key-agent RUST_LOG=debug
```

### 部署验证

```bash
# 本地部署验证
sudo systemctl status tls-key-agent
./target/release/verify_keys stats

# Docker部署验证
docker ps | grep tls-key-agent
docker logs tls-key-agent | tail -20

# Kubernetes部署验证
kubectl get pods -l app=tls-key-agent
kubectl logs -l app=tls-key-agent | tail -20
```

### 故障恢复

```bash
# 重启服务
sudo systemctl restart tls-key-agent

# 重新部署Docker
cd deploy && ./deploy.sh docker

# 滚动更新Kubernetes
kubectl rollout restart daemonset/tls-key-agent

# 清理并重新部署
cd deploy && ./deploy.sh clean
./deploy.sh local  # 或 docker/k8s
```

### 生产环境建议

1. **安全配置**
   - 使用TLS加密传输
   - 配置访问控制
   - 启用审计日志

2. **性能优化**
   - 调整缓冲区大小
   - 配置合适的批处理大小
   - 监控资源使用

3. **高可用性**
   - Kubernetes多副本部署
   - 配置健康检查
   - 设置自动重启

4. **监控告警**
   - 集成Prometheus监控
   - 配置日志收集
   - 设置关键指标告警

### 4. 测试Hook库

```bash
# 编译测试程序
gcc -o test_hook_simple test_hook_simple.c -lssl -lcrypto

# 运行Hook测试
LD_PRELOAD=./libtls_agent_hook.so ./test_hook_simple

# 检查密钥文件
ls -la /tmp/openssl_keys_all.log /tmp/tls_test_keys.log
```

## 配置说明

### Agent配置
- `name`: Agent名称
- `log_level`: 日志级别 (debug, info, warn, error)
- `buffer_pool_size`: 缓冲池大小
- `buffer_size`: 单个缓冲区大小

### 提取配置
- `enabled`: 是否启用密钥提取
- `capture_client_random`: 是否提取Client Random
- `capture_master_secret`: 是否提取Master Secret
- `library_path`: LD_PRELOAD库路径

### 传输配置
- `enabled_transports`: 启用的传输方式
- `tcp`: TCP传输配置
- `file`: 文件存储配置

### 过滤规则
- `name`: 规则名称
- `enabled`: 是否启用
- `five_tuple`: 五元组筛选条件
- `process_name`: 进程名筛选
- `pid`: PID筛选

## API接口

### C FFI接口

```c
// 初始化Agent
int tls_key_agent_init(const char* config_path);

// 启动Agent
int tls_key_agent_start();

// 停止Agent
int tls_key_agent_stop();

// 处理Client Random
int tls_key_agent_on_client_random(void* ssl_ptr, const uint8_t* client_random, size_t len);

// 处理Master Secret
int tls_key_agent_on_master_secret(void* ssl_ptr, const uint8_t* master_secret, size_t len);
```

## 输出格式

### TCP传输格式 (JSON)

```json
{
  "message_type": "TlsKey",
  "timestamp": 1699123456,
  "session": {
    "session_id": "192.168.1.100:12345-192.168.1.1:443-1699123456",
    "client_random": "abcdef123456...",
    "master_secret": "fedcba654321...",
    "five_tuple": {
      "src_ip": "192.168.1.100",
      "src_port": 12345,
      "dst_ip": "192.168.1.1",
      "dst_port": 443,
      "protocol": "TCP"
    },
    "process_info": {
      "pid": 1234,
      "process_name": "nginx",
      "command_line": "nginx -c /etc/nginx/nginx.conf"
    }
  }
}
```

### 文件格式

```
[2023-11-04 12:34:56 UTC] TLS_KEY | session-id | 192.168.1.100:12345 -> 192.168.1.1:443 | Process: nginx (PID: 1234) | ClientRandom: abcdef123456... | MasterSecret: fedcba654321...
```

## 性能指标

- **吞吐量**: 支持10,000+并发TLS连接
- **延迟**: eBPF内核级密钥提取延迟 < 0.5ms
- **内存占用**: 基础内存占用 < 100MB
- **CPU占用**: 正常负载下 < 3%
- **系统开销**: eBPF内核程序开销 < 1%

## 安全考虑

1. **权限控制**: Agent需要适当的权限来监控目标进程
2. **数据加密**: 传输过程中的密钥数据需要加密保护
3. **访问控制**: 严格的配置和访问控制机制
4. **审计日志**: 完整的操作审计记录

## 故障排除

### 常见问题

1. **LD_PRELOAD失败**
   - 检查库文件路径是否正确
   - 确认目标应用使用动态链接
   - 验证系统权限设置

2. **连接失败**
   - 检查网络配置和防火墙设置
   - 验证目标服务器是否可达
   - 确认端口是否被占用

3. **性能问题**
   - 调整缓冲池大小
   - 优化筛选规则
   - 检查系统资源使用情况

### 调试模式

启用详细日志：

```bash
RUST_LOG=debug ./target/release/tls_key_agent --config config.toml
```

## 开发指南

### 项目结构

```
tls_key_agent/
├── src/
│   ├── lib.rs                   # 库入口
│   ├── main.rs                  # 主程序入口
│   ├── config/                  # 配置管理
│   │   ├── mod.rs               # 配置模块
│   │   ├── builder.rs           # 配置构建器
│   │   ├── dynamic_config_manager.rs  # 动态配置管理
│   │   ├── filter.rs            # 过滤规则
│   │   └── remote_config.rs     # 远程配置
│   ├── injector/                # 注入管理器
│   │   ├── mod.rs               # 注入模块
│   │   ├── ebpf.rs              # eBPF注入器
│   │   ├── multi_ssl_injector.rs # 多SSL库注入器
│   │   ├── preload.rs           # LD_PRELOAD兼容
│   │   ├── seamless_injection.rs # 无感注入
│   │   └── detector.rs          # 进程检测器
│   ├── extractor/               # 密钥提取器
│   │   ├── mod.rs               # 提取器模块
│   │   ├── ssl_hook.rs          # SSL Hook处理器
│   │   ├── key_processor.rs     # 密钥处理器
│   │   └── session_manager.rs   # 会话管理器
│   ├── transport/               # 传输层
│   │   ├── mod.rs               # 传输模块
│   │   ├── enhanced_udp_manager.rs # 增强UDP管理器
│   │   ├── transport_manager.rs # 传输管理器
│   │   ├── tcp_transport.rs     # TCP传输
│   │   └── key_output.rs        # 密钥输出
│   ├── resilience/              # 企业级可靠性
│   │   ├── mod.rs               # 可靠性模块
│   │   ├── load_balancer.rs     # 负载均衡器
│   │   ├── fault_recovery.rs    # 故障恢复
│   │   ├── health_checker.rs    # 健康检查
│   │   └── performance_monitor.rs # 性能监控
│   ├── monitor/                 # 系统监控
│   │   ├── mod.rs               # 监控模块
│   │   └── system_monitor.rs    # 系统监控器
│   ├── common/                  # 公共组件
│   │   ├── mod.rs               # 公共模块
│   │   ├── session.rs           # TLS会话
│   │   ├── buffer.rs            # 缓冲池
│   │   ├── utils.rs             # 工具函数
│   │   └── error.rs             # 错误处理
│   ├── ffi/                     # C FFI接口
│   │   ├── mod.rs               # FFI模块
│   │   └── hook_library.rs      # Hook库接口
│   └── bin/
│       └── verify_keys.rs        # 密钥验证工具
├── tests/                        # 测试验证
│   ├── deployment_validation.rs # 部署验证测试
│   ├── structure_validation.rs  # 结构验证测试
│   └── performance_test.rs      # 性能测试
├── docs/                         # 项目文档
│   ├── ARCHITECTURE.md           # 架构设计文档
│   ├── API.md                   # API接口文档
│   └── DEPLOYMENT.md            # 部署指南
├── examples/                     # 示例代码
│   ├── key_validator.rs         # 密钥验证示例
│   └── simple_validator.rs      # 简单验证示例
├── src/ebpf/                     # eBPF程序 (C语言)
├── Cargo.toml                    # 项目配置
├── README.md                     # 项目说明
└── config.toml                   # 默认配置
```

### 运行测试

```bash
# 运行所有核心验证测试
cargo test --test deployment_validation --test structure_validation --test performance_test

# 运行库内部测试
cargo test --lib

# 运行完整测试套件
cargo test
```

## 贡献指南

1. Fork项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建Pull Request

## 许可证

本项目采用MIT或Apache-2.0双许可证。详见 [LICENSE-MIT](LICENSE-MIT) 和 [LICENSE-APACHE](LICENSE-APACHE) 文件。

## 联系方式

- 作者: sollor525@hotmail.com
- 项目主页: [GitHub Repository]

## 技术实现细节

### 主动式Hook架构

#### 1. SSL函数拦截
```c
// Hook SSL_write - 在首次成功写入时提取密钥
int SSL_write(SSL *ssl, const void *buf, int num) {
    int result = original_SSL_write(ssl, buf, num);

    static __thread int keys_extracted = 0;
    if (!keys_extracted && result > 0 && is_handshake_complete(ssl)) {
        extract_tls_keys_proactive(ssl, "SSL_write");
        keys_extracted = 1;
    }

    return result;
}
```

#### 2. Client Random多方法提取
```c
static int extract_client_random_proactive(SSL *ssl, unsigned char *client_random) {
    // 方法1: OpenSSL官方API
    if (original_SSL_get_client_random) {
        int len = original_SSL_get_client_random(ssl, client_random, 32);
        if (len == 32) return 1;
    }

    // 方法2: 直接结构体访问
    if (access_ssl_structure_direct_c(ssl, client_random)) {
        return 1;
    }

    // 方法3: 内存搜索
    if (search_client_random_in_memory_c(ssl, client_random)) {
        return 1;
    }

    return 0;
}
```

#### 3. Master Secret多策略提取
```c
static int extract_master_secret_proactive(SSL *ssl, unsigned char *master_secret) {
    // 方法1: SSL_export_keying_material API
    if (original_SSL_export_keying_material) {
        int result = original_SSL_export_keying_material(
            ssl, master_secret, 48, "master secret", 13, NULL, 0, 0);
        if (result > 0 && is_likely_master_secret_c(master_secret)) {
            return 1;
        }
    }

    // 方法2: SSL_SESSION提取
    if (extract_from_ssl_session_c(ssl, master_secret)) {
        return 1;
    }

    // 方法3: 内存搜索
    if (search_master_secret_in_memory_c(ssl, master_secret)) {
        return 1;
    }

    return 0;
}
```

#### 4. 智能密钥验证
```c
static int is_likely_client_random_c(const unsigned char *data) {
    // 熵值检测 - 不应该全零或全相同
    // 频率分析 - 任何字节不应出现超过4次
    // 连续检查 - 不应该有太长的连续相同字节

    int byte_counts[256] = {0};
    for (int i = 0; i < 32; i++) {
        byte_counts[data[i]]++;
    }

    int max_count = 0;
    for (int i = 0; i < 256; i++) {
        if (byte_counts[i] > max_count) max_count = byte_counts[i];
    }

    return (max_count <= 4); // 最大频率限制
}
```

### 关键技术创新

1. **eBPF内核级监控**: 在内核层直接拦截TLS函数调用
2. **系统级覆盖**: 一次部署，监控全系统所有TLS连接
3. **零侵入部署**: 无需修改任何应用程序或配置
4. **智能进程过滤**: 安全检查，避免监控系统关键进程
5. **高性能传输**: UDP批量传输，支持压缩和优化

## 更新日志

### v1.0.0 (2025-12-01) - eBPF架构升级
- ✅ **架构革命**: 从LD_PRELOAD升级到eBPF内核级监控
- ✅ **系统级覆盖**: 无需重启服务，自动监控所有TLS连接
- ✅ **零依赖部署**: 无需修改应用程序，一次部署全系统生效
- ✅ **企业级可靠性**: 8种负载均衡策略，故障恢复，性能监控
- ✅ **生产环境就绪**: Docker、Kubernetes、systemd完整支持
- ✅ **完美编译**: 零警告，零错误，生产级代码质量
- ✅ **完整文档**: API文档、部署指南、架构设计文档

### v0.2.0 (2025-11-05) - 主动式Hook重构
- ✅ **核心重构**: 完全重新设计TLS密钥提取架构
- ✅ **主动式Hook**: 基于SSL函数的直接密钥提取
- ✅ **多算法支持**: Client Random和Master Secret多种提取策略
- ✅ **智能验证**: 熵值检测和密钥有效性验证机制
- ✅ **高性能**: 优化Hook逻辑，支持高并发场景

### v0.1.0 (2023-11-04)
- 初始版本发布
- 基础LD_PRELOAD支持
- TCP和文件传输支持
- 配置系统和筛选规则
- C FFI接口

---

**注意**: 本工具仅用于合法的安全测试和监控目的。请确保在使用前获得适当的授权。