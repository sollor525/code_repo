# TLS Key Agent 文档中心

欢迎使用TLS Key Agent文档！这里包含了项目的完整文档集合，帮助您快速上手和深入使用。

## 📚 文档目录

### 🚀 快速开始
- **[项目主README](../README.md)** - 项目概述、快速开始指南
- **[使用指南](USAGE.md)** - 详细的使用说明和配置示例

### 🏗️ 技术文档
- **[设计文档](DESIGN.md)** - 系统架构、技术选型、实现细节
- **[API文档](API.md)** - 完整的API接口说明和示例
- **[测试文档](../TESTING.md)** - 测试策略、用例和验证方法

### 🚀 部署运维
- **[部署文档](DEPLOYMENT.md)** - 各种环境的部署方案
- **[项目总结](../PROJECT_SUMMARY.md)** - 项目完成情况和技术亮点

## 📋 文档导航

### 按角色查看

#### 🔧 开发者
1. 首先阅读 [项目主README](../README.md) 了解项目
2. 查看 [设计文档](DESIGN.md) 理解架构
3. 参考 [API文档](API.md) 进行开发
4. 使用 [测试文档](../TESTING.md) 验证功能

#### 🚀 运维工程师
1. 从 [使用指南](USAGE.md) 开始基础配置
2. 查看 [部署文档](DEPLOYMENT.md) 选择部署方案
3. 参考 [API文档](API.md) 进行监控集成

#### 👨‍💼 管理者
1. 阅读 [项目主README](../README.md) 了解项目价值
2. 查看 [项目总结](../PROJECT_SUMMARY.md) 了解完成情况
3. 浏览 [设计文档](DESIGN.md) 了解技术特点

### 按需求查看

#### 🚀 快速部署
```bash
# 1. 编译项目
cargo build --release

# 2. 快速测试
LD_PRELOAD=./target/release/libopenssl_hook.so curl -s https://www.baidu.com

# 3. 验证结果
./target/release/verify_keys test --host www.baidu.com
```

详细步骤请参考: [使用指南 → 快速开始](USAGE.md#快速开始)

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
| 🚀 | 快速开始 | README, USAGE |
| 🏗️ | 架构设计 | DESIGN |
| 🔧 | API接口 | API |
| 🚀 | 部署运维 | DEPLOYMENT |
| 🧪 | 测试验证 | TESTING |
| 📊 | 项目总结 | PROJECT_SUMMARY |

## 🔍 快速查找

### 功能查找
- **LD_PRELOAD配置**: [USAGE.md → 场景1](USAGE.md#场景1-监控nginx-https流量)
- **过滤规则设置**: [USAGE.md → 高级配置](USAGE.md#高级配置)
- **TCP传输配置**: [USAGE.md → TCP传输配置](USAGE.md#tcp传输配置)
- **性能优化**: [USAGE.md → 高性能配置](USAGE.md#高性能配置)

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
- **当前版本**: v0.1.0
- **最后更新**: 2023-11-04
- **维护者**: sollor525@hotmail.com

### 更新日志
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