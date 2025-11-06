# TLS Key Agent 文档中心

欢迎使用TLS Key Agent文档！这里包含了项目的完整文档集合，帮助您快速上手和深入使用。

## 📚 文档目录

### 🚀 快速开始
- **[项目主README](../README.md)** - 项目概述、主动式Hook功能介绍
- **[主动式Hook技术索引](PROACTIVE_HOOK_INDEX.md)** - 主动式Hook完整文档索引
- **[主动式Hook技术文档](../PROACTIVE_HOOK_DESIGN.md)** - 核心Hook架构设计
- **[快速使用指南](../USAGE_GUIDE.md)** - 完整的使用和部署指南
- **[使用指南](USAGE.md)** - 详细的使用说明和配置示例

### 🏗️ 技术文档
- **[主动式Hook技术文档](../PROACTIVE_HOOK_DESIGN.md)** - 核心Hook架构与实现细节
- **[主动式Hook技术索引](PROACTIVE_HOOK_INDEX.md)** - 完整技术文档索引
- **[API文档](API.md)** - 完整的API接口说明和示例
- **[eBPF注入指南](EBPF_INJECT_GUIDE.md)** - eBPF模式的使用说明
- **[实时捕获分析](LIVE_CAPTURE_ANALYSIS.md)** - 实时密钥捕获与分析方法
- **[快速eBPF指南](QUICK_EBPF_GUIDE.md)** - eBPF快速入门指南
- **[测试文档](../TESTING.md)** - 测试策略、用例和验证方法

### 🚀 部署运维
- **[部署文档](DEPLOYMENT.md)** - 各种环境的部署方案
- **[项目总结](../PROJECT_SUMMARY.md)** - 项目完成情况和技术亮点

## 📋 文档导航

### 按角色查看

#### 🔧 开发者
1. 首先阅读 [项目主README](../README.md) 了解项目
2. 查看 [主动式Hook技术索引](PROACTIVE_HOOK_INDEX.md) 获取完整技术概览
3. 查看 [主动式Hook技术文档](../PROACTIVE_HOOK_DESIGN.md) 理解核心架构
4. 使用 [API文档](API.md) 进行开发集成
5. 参考 [快速使用指南](../USAGE_GUIDE.md) 进行测试
6. 使用 [测试文档](../TESTING.md) 验证功能
7. 参考 [eBPF注入指南](EBPF_INJECT_GUIDE.md) 了解高级用法

#### 🚀 运维工程师
1. 从 [快速使用指南](../USAGE_GUIDE.md) 开始部署
2. 参考 [项目主README](../README.md) 了解主动式Hook功能
3. 查看 [部署文档](DEPLOYMENT.md) 选择部署方案
4. 参考 [API文档](API.md) 进行监控集成
5. 使用 [eBPF注入指南](EBPF_INJECT_GUIDE.md) 了解高级用法

#### 👨‍💼 管理者
1. 阅读 [项目主README](../README.md) 了解项目价值和主动式Hook创新
2. 查看 [主动式Hook技术索引](PROACTIVE_HOOK_INDEX.md) 了解技术概览
3. 查看 [主动式Hook技术文档](../PROACTIVE_HOOK_DESIGN.md) 了解技术优势
4. 查看 [项目总结](../PROJECT_SUMMARY.md) 了解完成情况
5. 浏览 [部署文档](DEPLOYMENT.md) 了解部署方案

### 按需求查看

#### 🚀 快速部署（主动式Hook）
```bash
# 1. 编译Hook库
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread

# 2. 快速测试
LD_PRELOAD=./libtls_agent_hook.so curl -s https://www.baidu.com

# 3. 验证密钥提取结果
ls -la /tmp/openssl_keys_all.log
cat /tmp/openssl_keys_all.log
```

详细步骤请参考: [快速使用指南 → 编译和安装](../USAGE_GUIDE.md#编译和安装)

#### 🔧 生产部署
- 单机部署: [部署文档 → 单机部署](DEPLOYMENT.md#单机部署)
- 集群部署: [部署文档 → 集群部署](DEPLOYMENT.md#集群部署)
- 容器化: [部署文档 → 容器化部署](DEPLOYMENT.md#容器化部署)

#### 🐛 问题排查
- 常见问题: [使用指南 → 故障排除](USAGE.md#故障排除)
- 调试方法: [使用指南 → 调试模式](USAGE.md#调试模式)
- 性能优化: [使用指南 → 最佳实践](USAGE.md#最佳实践)

## 🏷️ 文档标签

| 标签 | 说明 | 相关文档 |
|------|------|----------|
| 🚀 | 快速开始 | README, PROACTIVE_HOOK_INDEX, USAGE_GUIDE |
| 🔧 | 主动式Hook | PROACTIVE_HOOK_DESIGN, PROACTIVE_HOOK_INDEX |
| 🔧 | API接口 | API |
| 🚀 | 部署运维 | DEPLOYMENT |
| 🔬 | eBPF模式 | EBPF_INJECT_GUIDE, QUICK_EBPF_GUIDE |
| 🧪 | 测试验证 | TESTING |
| 📊 | 项目总结 | PROJECT_SUMMARY |
| 📈 | 实时分析 | LIVE_CAPTURE_ANALYSIS |

## 🔍 快速查找

### 功能查找
- **主动式Hook使用**: [快速使用指南 → 基本使用](../USAGE_GUIDE.md#基本使用)
- **Hook库编译**: [快速使用指南 → 编译和安装](../USAGE_GUIDE.md#编译和安装)
- **多算法密钥提取**: [主动式Hook技术文档 → Client Random提取](../PROACTIVE_HOOK_DESIGN.md#client-random多方法提取)
- **密钥验证算法**: [主动式Hook技术文档 → 智能密钥验证](../PROACTIVE_HOOK_DESIGN.md#智能密钥验证)
- **性能优化**: [快速使用指南 → 性能优化建议](../USAGE_GUIDE.md#性能优化建议)
- **故障排除**: [快速使用指南 → 故障排除](../USAGE_GUIDE.md#故障排除)

### 问题查找
- **编译问题**: [README.md → 故障排除](../README.md#故障排除)
- **权限问题**: [USAGE.md → 权限不足](USAGE.md#权限不足)
- **网络问题**: [USAGE.md → 网络连接失败](USAGE.md#网络连接失败)
- **内存问题**: [USAGE.md → 内存泄漏](USAGE.md#内存泄漏)

### 配置查找
- **基础配置**: [USAGE.md → 基础配置](USAGE.md#基础配置)
- **安全配置**: [USAGE.md → 安全配置](USAGE.md#安全配置)
- **监控配置**: [USAGE.md → 监控和维护](USAGE.md#监控和维护)
- **生产配置**: [DEPLOYMENT.md → 配置优化](DEPLOYMENT.md#配置优化)

## 📝 文档更新

### 版本信息
- **当前版本**: v0.2.0
- **最后更新**: 2025-11-05
- **维护者**: sollor525@hotmail.com

### 更新日志
- **v0.2.0** (2025-11-05): 主动式Hook重构
  - ✅ 完全重新设计TLS密钥提取架构
  - ✅ 主动式Hook功能，不依赖Keylog回调
  - ✅ 多算法密钥提取策略
  - ✅ 智能密钥验证机制
  - ✅ 完整的技术文档和使用指南
  - ✅ 高性能、高并发支持

- **v0.1.0** (2023-11-04): 初始文档发布
  - 完成所有核心文档
  - 包含完整的API说明
  - 提供多种部署方案

### 贡献指南
欢迎参与文档改进！

1. **发现问题**: 在GitHub Issues中提交文档问题
2. **改进建议**: 提交Pull Request改进文档
3. **格式规范**: 遵循Markdown格式规范
4. **内容要求**: 确保内容准确、实用、易懂

## 🔗 相关资源

### 外部链接
- [Rust官方文档](https://doc.rust-lang.org/)
- [OpenSSL文档](https://www.openssl.org/docs/)
- [LD_PRELOAD说明](https://man7.org/linux/man-pages/man8/ld.so.8.html)

### 项目资源
- [GitHub仓库](https://github.com/example/tls_key_agent)
- [问题反馈](https://github.com/example/tls_key_agent/issues)
- [功能请求](https://github.com/example/tls_key_agent/issues/new?template=feature_request.md)

### 社区支持
- [技术讨论](https://github.com/example/tls_key_agent/discussions)
- [FAQ](https://github.com/example/tls_key_agent/wiki/FAQ)
- [最佳实践](https://github.com/example/tls_key_agent/wiki/Best-Practices)

## 📞 联系方式

- **技术支持**: sollor525@hotmail.com
- **Bug报告**: [GitHub Issues](https://github.com/example/tls_key_agent/issues)
- **功能请求**: [GitHub Discussions](https://github.com/example/tls_key_agent/discussions)

---

感谢您使用TLS Key Agent！如有任何问题或建议，请随时联系我们。