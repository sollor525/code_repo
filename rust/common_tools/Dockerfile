# 构建阶段
FROM rust:1.75-slim as builder

# 设置工作目录
WORKDIR /app

# 安装必要的系统依赖
RUN apt-get update && apt-get install -y \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 复制 Cargo 文件
COPY Cargo.toml Cargo.lock ./

# 创建一个空的 src 目录来缓存依赖
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# 复制源代码
COPY src ./src

# 构建应用
RUN touch src/main.rs && cargo build --release

# 运行阶段
FROM debian:bookworm-slim

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 创建非 root 用户
RUN useradd -m -u 1000 rustuser

# 复制构建的二进制文件
COPY --from=builder /app/target/release/common_tools /usr/local/bin/common_tools

# 设置权限
RUN chown rustuser:rustuser /usr/local/bin/common_tools

# 切换到非 root 用户
USER rustuser

# 暴露端口
EXPOSE 3030

# 设置环境变量
ENV RUST_LOG=info

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3030/health || exit 1

# 启动应用
CMD ["common_tools", "--host", "0.0.0.0", "--port", "3030"]