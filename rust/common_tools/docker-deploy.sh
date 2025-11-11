#!/bin/bash

# Docker 部署脚本

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查Docker是否安装
check_docker() {
    log_info "检查Docker环境..."
    if ! command -v docker &> /dev/null; then
        log_error "Docker未安装，请先安装Docker"
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose未安装，请先安装Docker Compose"
        exit 1
    fi

    log_info "Docker环境检查通过"
}

# 构建镜像
build_image() {
    log_info "构建Docker镜像..."
    docker build -t common-tools:latest .
    log_info "镜像构建完成"
}

# 启动服务
start_service() {
    log_info "启动服务..."
    docker-compose up -d
    log_info "服务启动完成"
}

# 停止服务
stop_service() {
    log_info "停止服务..."
    docker-compose down
    log_info "服务已停止"
}

# 查看日志
show_logs() {
    docker-compose logs -f
}

# 查看服务状态
show_status() {
    docker-compose ps
}

# 更新服务
update_service() {
    log_info "更新服务..."
    docker-compose down
    build_image
    start_service
    log_info "服务更新完成"
}

# 清理资源
cleanup() {
    log_info "清理Docker资源..."
    docker-compose down --rmi all --volumes --remove-orphans
    docker system prune -f
    log_info "清理完成"
}

# 显示帮助信息
show_help() {
    echo "开发者工具箱 Docker 部署脚本"
    echo "用法: $0 [命令]"
    echo ""
    echo "命令:"
    echo "  build     构建Docker镜像"
    echo "  start     启动服务"
    echo "  stop      停止服务"
    echo "  restart   重启服务"
    echo "  status    查看服务状态"
    echo "  logs      查看服务日志"
    echo "  update    更新服务"
    echo "  cleanup   清理Docker资源"
    echo "  help      显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 build    # 构建镜像"
    echo "  $0 start    # 启动服务"
    echo "  $0 logs     # 查看日志"
}

# 主函数
main() {
    case "${1:-help}" in
        "build")
            check_docker
            build_image
            ;;
        "start")
            check_docker
            start_service
            log_info "服务地址: http://localhost:8080"
            ;;
        "stop")
            stop_service
            ;;
        "restart")
            stop_service
            start_service
            log_info "服务地址: http://localhost:8080"
            ;;
        "status")
            show_status
            ;;
        "logs")
            show_logs
            ;;
        "update")
            check_docker
            update_service
            log_info "服务地址: http://localhost:8080"
            ;;
        "cleanup")
            cleanup
            ;;
        "help"|*)
            show_help
            ;;
    esac
}

# 执行主函数
main "$@"