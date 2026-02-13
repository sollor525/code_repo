#!/bin/bash
# eBPF SSL Hook Build Script
# Author: sollor525@hotmail.com
# Version: 2.0.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Build configuration
BUILD_TYPE="${BUILD_TYPE:-release}"
VERBOSE="${VERBOSE:-false}"
CLEAN="${CLEAN:-false}"
INSTALL="${INSTALL:-false}"
VERIFY="${VERIFY:-false}"

# Logging functions
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

# Show usage
show_usage() {
    cat << EOF
eBPF SSL Hook Build Script

Usage: $0 [OPTIONS]

Options:
    -c, --clean      Clean build artifacts before building
    -i, --install    Install eBPF programs after building
    -v, --verify     Verify eBPF object after building
    -d, --debug      Build with debug information
    -h, --help       Show this help message
    --verbose        Verbose build output

Environment Variables:
    BUILD_TYPE       Build type: debug|release (default: release)
    VERBOSE          Verbose output: true|false (default: false)
    CLEAN            Clean before build: true|false (default: false)
    INSTALL          Install after build: true|false (default: false)
    VERIFY           Verify after build: true|false (default: false)

Examples:
    $0                          # Build eBPF programs
    $0 --clean                  # Clean and build
    $0 --install                # Build and install
    $0 --clean --install --verify  # Clean, build, verify, and install

Requirements:
    - clang/llvm (>= 10.0)
    - bpftool (>= 4.14)
    - Linux kernel with eBPF support (>= 4.14)
    - Mounted eBPF filesystem: /sys/fs/bpf
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--clean)
                CLEAN=true
                shift
                ;;
            -i|--install)
                INSTALL=true
                shift
                ;;
            -v|--verify)
                VERIFY=true
                shift
                ;;
            -d|--debug)
                BUILD_TYPE=debug
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."

    # Check kernel version
    if [[ -f /proc/version ]]; then
        local kernel_version=$(uname -r | cut -d. -f1-2)
        local kernel_major=$(echo "$kernel_version" | cut -d. -f1)
        local kernel_minor=$(echo "$kernel_version" | cut -d. -f2)

        if (( kernel_major < 4 || (kernel_major == 4 && kernel_minor < 14) )); then
            log_error "Kernel version $kernel_version is not supported. Requires >= 4.14"
            exit 1
        fi
        log_success "Kernel version: $kernel_version ✓"
    else
        log_warning "Could not determine kernel version"
    fi

    # Check required tools
    local required_tools=("clang" "bpftool" "make")
    local missing_tools=()

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        else
            log_success "Found: $tool ✓"
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install with:"
        log_info "  Ubuntu/Debian: sudo apt install clang llvm linux-tools-common make"
        log_info "  RHEL/CentOS:   sudo yum install clang llvm bpftool make"
        exit 1
    fi

    # Check eBPF filesystem
    if [[ ! -d /sys/fs/bpf ]]; then
        log_warning "eBPF filesystem not mounted at /sys/fs/bpf"
        log_info "Mount with: sudo mount -t bpf bpf /sys/fs/bpf"
    else
        log_success "eBPF filesystem mounted ✓"
    fi

    # Check BTF support
    if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
        log_warning "BTF (BPF Type Format) not available. Debug features may be limited"
    else
        log_success "BTF support available ✓"
    fi

    log_success "System requirements check completed"
}

# Build eBPF programs
build_ebpf() {
    log_info "Building eBPF SSL Hook programs..."

    cd "$SCRIPT_DIR"

    # Set verbose mode
    local make_args=()
    if [[ "$VERBOSE" == "true" ]]; then
        make_args+=("VERBOSE=1")
    fi

    # Clean if requested
    if [[ "$CLEAN" == "true" ]]; then
        log_info "Cleaning build artifacts..."
        make clean
    fi

    # Build
    if [[ "$VERBOSE" == "true" ]]; then
        log_info "Starting verbose build..."
        make "${make_args[@]}" all
    else
        make all
    fi

    # Check if build succeeded
    local target_file="$PROJECT_ROOT/target/release/ebpf_ssl_hook.o"
    if [[ -f "$target_file" ]]; then
        local file_size=$(stat -c%s "$target_file" 2>/dev/null || stat -f%z "$target_file" 2>/dev/null || echo "unknown")
        log_success "eBPF object built successfully: $target_file (${file_size} bytes)"
    else
        log_error "Build failed - eBPF object not found"
        exit 1
    fi
}

# Verify eBPF object
verify_ebpf() {
    log_info "Verifying eBPF object..."

    cd "$SCRIPT_DIR"

    if make verify; then
        log_success "eBPF object verification completed"
    else
        log_warning "eBPF object verification failed (this may be normal)"
    fi
}

# Install eBPF programs
install_ebpf() {
    log_info "Installing eBPF programs to kernel..."

    cd "$SCRIPT_DIR"

    if make install; then
        log_success "eBPF programs installed successfully"
    else
        log_error "Failed to install eBPF programs"
        log_info "Make sure you have sufficient privileges (sudo may be required)"
        exit 1
    fi
}

# Show installation status
show_status() {
    log_info "Checking installation status..."

    if [[ -d /sys/fs/bpf/tls_key_agent ]]; then
        log_success "eBPF programs directory exists: /sys/fs/bpf/tls_key_agent"

        # Check individual maps
        local maps=("ssl_connections" "ssl_events" "socket_connections" "connection_id_map")
        for map in "${maps[@]}"; do
            if [[ -e "/sys/fs/bpf/tls_key_agent/$map" ]]; then
                log_success "  Map: $map ✓"
            else
                log_warning "  Map: $map ✗"
            fi
        done
    else
        log_warning "eBPF programs directory not found"
    fi
}

# Main function
main() {
    log_info "Starting eBPF SSL Hook build process..."
    log_info "Project root: $PROJECT_ROOT"
    log_info "Build type: $BUILD_TYPE"

    parse_args "$@"
    check_requirements
    build_ebpf

    if [[ "$VERIFY" == "true" ]]; then
        verify_ebpf
    fi

    if [[ "$INSTALL" == "true" ]]; then
        install_ebpf
        show_status
    fi

    log_success "Build process completed successfully!"

    if [[ "$INSTALL" != "true" ]]; then
        log_info "To install eBPF programs, run:"
        log_info "  sudo $0 --install"
    fi

    log_info "To uninstall eBPF programs, run:"
    log_info "  sudo make -C $SCRIPT_DIR uninstall"
}

# Run main function
main "$@"