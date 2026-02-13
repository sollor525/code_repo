# TLS Key Agent Docker镜像
# 多阶段构建，减小最终镜像大小

# 构建阶段
FROM rust:1.75-slim as builder

# 设置工作目录
WORKDIR /app

# 安装构建依赖
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 复制Cargo文件
COPY Cargo.toml Cargo.lock ./

# 创建虚拟main.rs以预构建依赖
RUN mkdir src && echo "fn main() {}" > src/main.rs

# 构建依赖（利用Docker缓存）
RUN cargo build --release && rm -rf src

# 复制源代码
COPY src ./src
COPY config.toml ./

# 构建应用
RUN cargo build --release

# 运行阶段
FROM debian:12-slim

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# 创建非root用户
RUN useradd -r -s /bin/false tls-key-agent

# 设置工作目录
WORKDIR /opt/tls_key_agent

# 从构建阶段复制文件
COPY --from=builder /app/target/release/tls_key_agent ./bin/
COPY --from=builder /app/target/release/verify_keys ./bin/ 2>/dev/null || true
COPY --from=builder /app/config.toml ./config/
COPY --from=builder /app/demo ./demo/ 2>/dev/null || true

# 创建必要的目录
RUN mkdir -p logs scripts docs && \
    chown -R tls-key-agent:tls-key-agent /opt/tls_key_agent

# 复制Docker专用脚本
COPY docker/docker-entrypoint.sh ./scripts/
COPY docker/start.sh ./scripts/

# 设置权限
RUN chmod +x ./scripts/*.sh

# 切换到非root用户
USER tls-key-agent

# 暴露端口（如果有HTTP服务）
EXPOSE 8080 8081 9999

# 设置环境变量
ENV RUST_LOG=info
ENV CONFIG_FILE=/opt/tls_key_agent/config/config.toml

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD pgrep tls_key_agent > /dev/null || exit 1

# 入口点
ENTRYPOINT ["/opt/tls_key_agent/scripts/docker-entrypoint.sh"]

# 默认命令
CMD ["/opt/tls_key_agent/bin/tls_key_agent", "--config", "/opt/tls_key_agent/config/config.toml"]