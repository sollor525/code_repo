#!/bin/bash
# TLS Key Agent 部署脚本
# 支持多种部署方式：本地安装、Docker、Kubernetes

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_header() {
    echo -e "${PURPLE}🚀 $1${NC}"
}

print_step() {
    echo -e "${CYAN}➤ $1${NC}"
}

# 项目信息
PROJECT_NAME="tls_key_agent"
VERSION=${VERSION:-"0.1.0"}
REGISTRY=${REGISTRY:-"localhost:5000"}
IMAGE_NAME="${REGISTRY}/${PROJECT_NAME}:${VERSION}"

# 显示帮助信息
show_help() {
    echo "TLS Key Agent 部署脚本"
    echo ""
    echo "用法: $0 <部署方式> [选项]"
    echo ""
    echo "部署方式:"
    echo "  local           本地安装部署"
    echo "  docker          Docker容器部署"
    echo "  k8s             Kubernetes集群部署"
    echo "  package         仅打包不部署"
    echo "  clean           清理构建文件"
    echo ""
    echo "选项:"
    echo "  --version=VER   指定版本号 (默认: 0.1.0)"
    echo "  --registry=REG  指定镜像仓库 (默认: localhost:5000)"
    echo "  --debug         构建Debug版本"
    echo "  --help, -h      显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 local                    # 本地安装"
    echo "  $0 docker                   # Docker部署"
    echo "  $0 k8s                      # Kubernetes部署"
    echo "  $0 package                  # 仅打包"
    echo "  $0 docker --version=v1.2.3 # 指定版本部署"
}

# 解析命令行参数
DEPLOY_TYPE=""
BUILD_ARGS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        local|docker|k8s|package|clean)
            if [ -z "$DEPLOY_TYPE" ]; then
                DEPLOY_TYPE=$1
            else
                print_error "只能指定一种部署方式"
                show_help
                exit 1
            fi
            shift
            ;;
        --version=*)
            VERSION="${1#*=}"
            IMAGE_NAME="${REGISTRY}/${PROJECT_NAME}:${VERSION}"
            shift
            ;;
        --registry=*)
            REGISTRY="${1#*=}"
            IMAGE_NAME="${REGISTRY}/${PROJECT_NAME}:${VERSION}"
            shift
            ;;
        --debug)
            BUILD_ARGS="$BUILD_ARGS --debug"
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            print_error "未知参数: $1"
            show_help
            exit 1
            ;;
    esac
done

# 检查部署类型
if [ -z "$DEPLOY_TYPE" ]; then
    print_error "请指定部署方式"
    show_help
    exit 1
fi

print_header "TLS Key Agent 部署工具"
echo "部署方式: $DEPLOY_TYPE"
echo "版本: $VERSION"
echo "镜像仓库: $REGISTRY"
echo ""

# 打包函数
do_package() {
    print_step "开始打包..."

    if [ ! -f "../build.sh" ]; then
        print_error "未找到build.sh脚本"
        exit 1
    fi

    # 执行打包（输出到deploy/dist目录）
    cd .. && PACKAGE_DIR="deploy/dist" ./build.sh $BUILD_ARGS --version="$VERSION"

    print_success "打包完成"
}

# 本地部署函数
do_local_deploy() {
    print_step "开始本地部署..."

    # 先打包
    do_package

    # 查找最新打包文件
    local package_file=$(ls -t deploy/dist/*.tar.gz | head -1)
    if [ -z "$package_file" ]; then
        print_error "未找到打包文件"
        print_info "请先运行: ./deploy.sh package"
        exit 1
    fi

    print_info "解压安装包: $package_file"
    local temp_dir="/tmp/tls_key_agent_deploy_$$"
    mkdir -p "$temp_dir"

    tar -xzf "$package_file" -C "$temp_dir"

    local extract_dir=$(find "$temp_dir" -maxdepth 1 -type d -name "$PROJECT_NAME-*" | head -1)
    if [ -z "$extract_dir" ]; then
        print_error "解压失败"
        rm -rf "$temp_dir"
        exit 1
    fi

    print_info "执行安装脚本..."
    cd "$extract_dir"

    if [ "$EUID" -ne 0 ]; then
        print_warning "本地安装需要root权限，使用sudo执行"
        sudo ./scripts/install.sh
    else
        ./scripts/install.sh
    fi

    # 清理临时文件
    cd - > /dev/null
    rm -rf "$temp_dir"

    print_success "本地部署完成"
    print_info "启动服务: systemctl start tls-key-agent"
    print_info "查看状态: systemctl status tls-key-agent"
}

# Docker部署函数
do_docker_deploy() {
    print_step "开始Docker部署..."

    # 检查Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker 未安装"
        exit 1
    fi

    # 检查Docker是否运行
    if ! docker info &> /dev/null; then
        print_error "Docker 服务未运行"
        exit 1
    fi

    # 构建镜像
    print_info "构建Docker镜像: $IMAGE_NAME"
    docker build -t "$IMAGE_NAME" -f ../Dockerfile ..

    # 创建网络
    local network_name="tls-key-agent-network"
    if ! docker network ls | grep -q "$network_name"; then
        print_info "创建Docker网络: $network_name"
        docker network create "$network_name"
    fi

    # 停止现有容器
    local existing_container=$(docker ps -aq --filter name=tls-key-agent)
    if [ -n "$existing_container" ]; then
        print_info "停止现有容器"
        docker stop $existing_container
        docker rm $existing_container
    fi

    # 创建必要的目录
    mkdir -p ../logs ../config

    # 复制配置文件
    if [ ! -f "../config/docker.toml" ]; then
        cp ../config.toml ../config/docker.toml
        print_info "已创建Docker配置文件: ../config/docker.toml"
    fi

    # 启动容器
    print_info "启动Docker容器"
    docker run -d \
        --name tls-key-agent \
        --privileged \
        --network host \
        --restart unless-stopped \
        -v "$(pwd)/../config/docker.toml:/opt/tls_key_agent/config/config.toml:ro" \
        -v "$(pwd)/../logs:/opt/tls_key_agent/logs" \
        -v "/sys/kernel/debug:/sys/kernel/debug:ro" \
        -v "/lib/modules:/lib/modules:ro" \
        -e RUST_LOG=info \
        "$IMAGE_NAME"

    print_success "Docker部署完成"
    print_info "查看容器: docker ps | grep tls-key-agent"
    print_info "查看日志: docker logs -f tls-key-agent"
}

# Kubernetes部署函数
do_k8s_deploy() {
    print_step "开始Kubernetes部署..."

    # 检查kubectl
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl 未安装"
        exit 1
    fi

    # 检查集群连接
    if ! kubectl cluster-info &> /dev/null; then
        print_error "无法连接到Kubernetes集群"
        exit 1
    fi

    # 构建镜像
    print_info "构建Docker镜像: $IMAGE_NAME"
    docker build -t "$IMAGE_NAME" -f deploy/Dockerfile ..

    # 推送镜像到仓库
    if [[ "$REGISTRY" != "localhost:5000" ]]; then
        print_info "推送镜像到仓库: $REGISTRY"
        docker push "$IMAGE_NAME"
    fi

    # 创建ConfigMap
    print_info "创建ConfigMap"
    kubectl create configmap tls-key-agent-config \
        --from-file=../config.toml \
        --dry-run=client -o yaml | kubectl apply -f -

    # 应用Kubernetes配置
    print_info "应用Kubernetes配置"

    # 应用ServiceAccount和RBAC
    kubectl apply -f k8s/serviceaccount.yaml

    # 更新Deployment中的镜像
    sed "s|tls-key-agent:latest|$IMAGE_NAME|g" k8s/deployment.yaml | kubectl apply -f -

    # 等待部署完成
    print_info "等待部署完成..."
    kubectl rollout status daemonset/tls-key-agent --timeout=300s

    print_success "Kubernetes部署完成"
    print_info "查看Pod: kubectl get pods -l app=tls-key-agent"
    print_info "查看日志: kubectl logs -l app=tls-key-agent -f"
}

# 清理函数
do_clean() {
    print_step "开始清理..."

    # 清理构建文件
    if [ -d "dist" ]; then
        print_info "删除打包文件"
        rm -rf dist
    fi

    if [ -d "target" ]; then
        print_info "清理构建缓存"
        cargo clean
    fi

    # 清理Docker资源
    if command -v docker &> /dev/null; then
        print_info "清理Docker资源"

        # 停止容器
        local containers=$(docker ps -aq --filter name=tls-key-agent)
        if [ -n "$containers" ]; then
            docker stop $containers
            docker rm $containers
        fi

        # 删除镜像
        local images=$(docker images -q "$PROJECT_NAME")
        if [ -n "$images" ]; then
            docker rmi -f $images
        fi
    fi

    # 清理临时文件
    print_info "清理临时文件"
    rm -rf /tmp/tls_key_agent_deploy_*

    print_success "清理完成"
}

# 主函数
main() {
    print_info "开始部署流程..."

    case $DEPLOY_TYPE in
        "package")
            do_package
            ;;
        "local")
            do_local_deploy
            ;;
        "docker")
            do_docker_deploy
            ;;
        "k8s")
            do_k8s_deploy
            ;;
        "clean")
            do_clean
            ;;
        *)
            print_error "未知的部署方式: $DEPLOY_TYPE"
            show_help
            exit 1
            ;;
    esac

    print_success "部署流程完成"
}

# 执行主函数
main