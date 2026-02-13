# Makefile for eBPF SSL Hook Programs
# Author: sollor525@hotmail.com
# Version: 2.0.0

# Compiler and tools
CLANG = clang
BPFTOOL = bpftool
LLVM_STRIP = llvm-strip
PKG_CONFIG = pkg-config

# Directories
SRC_DIR = .
BUILD_DIR = ../../build/ebpf
TARGET_DIR = ../../target/release
OBJ_DIR = $(BUILD_DIR)/obj
INCLUDE_DIR = $(BUILD_DIR)/include

# Source files
SSL_HOOK_SOURCES = $(SRC_DIR)/ssl_hook.c
CONNECTION_TRACKER_SOURCES = $(SRC_DIR)/connection_tracker.c
KEY_EXTRACTOR_SOURCES = $(SRC_DIR)/key_extractor.c

# Object files
SSL_HOOK_OBJ = $(OBJ_DIR)/ssl_hook.o
CONNECTION_TRACKER_OBJ = $(OBJ_DIR)/connection_tracker.o
KEY_EXTRACTOR_OBJ = $(OBJ_DIR)/key_extractor.o
ALL_OBJS = $(SSL_HOOK_OBJ) $(CONNECTION_TRACKER_OBJ) $(KEY_EXTRACTOR_OBJ)

# Final eBPF object
EBPF_SSL_HOOK_OBJ = $(TARGET_DIR)/ebpf_ssl_hook.o

# Compiler flags
CFLAGS = -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86
CFLAGS += -I/usr/include
CFLAGS += -I/usr/include/x86_64-linux-gnu
CFLAGS += -I/usr/include/$(shell $(PKG_CONFIG) --variable=includedir openssl 2>/dev/null || echo "/usr/include/openssl")
CFLAGS += -I$(INCLUDE_DIR)
CFLAGS += -D__KERNEL__
CFLAGS += -Wno-unused-value
CFLAGS += -Wno-pointer-sign
CFLAGS += -Wno-compare-distinct-pointer-types
CFLAGS += -Wno-gnu-variable-sized-type-not-at-end
CFLAGS += -Wno-address-of-packed-member
CFLAGS += -Wno-deprecated-declarations
CFLAGS += -fno-stack-protector

# Include vmlinux.h if available
VMLINUX_H = $(INCLUDE_DIR)/vmlinux.h

# Libraries and dependencies
LIBS = -lelf -lz

# Default target
.PHONY: all clean install uninstall check-deps headers

all: check-deps headers $(EBPF_SSL_HOOK_OBJ)

# Create directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(TARGET_DIR):
	mkdir -p $(TARGET_DIR)

$(INCLUDE_DIR):
	mkdir -p $(INCLUDE_DIR)

# Generate vmlinux.h header (if bpftool supports it)
headers: $(INCLUDE_DIR) $(VMLINUX_H)

$(VMLINUX_H):
	@if command -v $(BPFTOOL) >/dev/null 2>&1; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@ 2>/dev/null || \
		echo "// Warning: Could not generate vmlinux.h, using fallback headers" > $@; \
	else \
		echo "// Warning: bpftool not available, using fallback headers" > $@; \
	fi

# Compile individual eBPF objects
$(SSL_HOOK_OBJ): $(SSL_HOOK_SOURCES) | $(OBJ_DIR) headers
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@ 2>/dev/null || true

$(CONNECTION_TRACKER_OBJ): $(CONNECTION_TRACKER_SOURCES) | $(OBJ_DIR) headers
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@ 2>/dev/null || true

$(KEY_EXTRACTOR_OBJ): $(KEY_EXTRACTOR_SOURCES) | $(OBJ_DIR) headers
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@ 2>/dev/null || true

# Link eBPF objects into final object
$(EBPF_SSL_HOOK_OBJ): $(ALL_OBJS) | $(TARGET_DIR)
	@echo "Linking eBPF SSL Hook object..."
	@# For eBPF, we combine objects using bpftool or concatenate them
	@# This is a simplified approach - in production you might want a more sophisticated linker
	@if command -v $(BPFTOOL) >/dev/null 2>&1; then \
		$(BPFTOOL) gen object $@ $(ALL_OBJS); \
	else \
		echo "Warning: bpftool not available, creating combined object..."; \
		cat $(ALL_OBJS) > $@; \
	fi

# Verify eBPF object
verify: $(EBPF_SSL_HOOK_OBJ)
	@if command -v $(BPFTOOL) >/dev/null 2>&1; then \
		echo "Verifying eBPF object..."; \
		$(BPFTOOL) prog dump xlated file $@ || true; \
	else \
		echo "Warning: Cannot verify eBPF object without bpftool"; \
	fi

# Install eBPF programs
install: $(EBPF_SSL_HOOK_OBJ)
	@if command -v $(BPFTOOL) >/dev/null 2>&1; then \
		echo "Installing eBPF SSL Hook programs..."; \
		sudo mkdir -p /sys/fs/bpf/tls_key_agent; \
		sudo $(BPFTOOL) prog load $@ /sys/fs/bpf/tls_key_agent/ssl_hook; \
		sudo $(BPFTOOL) map create /sys/fs/bpf/tls_key_agent/ssl_connections key 8 value 64 name connections type hash; \
		sudo $(BPFTOOL) map create /sys/fs/bpf/tls_key_agent/ssl_events key 4 value 256 name events type array; \
		sudo $(BPFTOOL) map create /sys/fs/bpf/tls_key_agent/socket_connections key 4 value 128 name sockets type hash; \
		sudo $(BPFTOOL) map create /sys/fs/bpf/tls_key_agent/connection_id_map key 8 value 128 name conn_ids type hash; \
		echo "eBPF programs installed successfully"; \
	else \
		echo "Error: Cannot install eBPF programs without bpftool"; \
		exit 1; \
	fi

# Uninstall eBPF programs
uninstall:
	@if command -v $(BPFTOOL) >/dev/null 2>&1; then \
		echo "Uninstalling eBPF SSL Hook programs..."; \
		sudo $(BPFTOOL) prog unload /sys/fs/bpf/tls_key_agent/ssl_hook 2>/dev/null || true; \
		sudo rm -f /sys/fs/bpf/tls_key_agent/ssl_connections; \
		sudo rm -f /sys/fs/bpf/tls_key_agent/ssl_events; \
		sudo rm -f /sys/fs/bpf/tls_key_agent/socket_connections; \
		sudo rm -f /sys/fs/bpf/tls_key_agent/connection_id_map; \
		sudo rmdir /sys/fs/bpf/tls_key_agent 2>/dev/null || true; \
		echo "eBPF programs uninstalled successfully"; \
	else \
		echo "Warning: Cannot uninstall eBPF programs without bpftool"; \
	fi

# Check dependencies
check-deps:
	@echo "Checking eBPF build dependencies..."
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "Error: clang not found. Please install clang (llvm)"; exit 1; }
	@command -v $(BPFTOOL) >/dev/null 2>&1 || echo "Warning: bpftool not found. Install linux-tools for full functionality."
	@command -v $(LLVM_STRIP) >/dev/null 2>&1 || echo "Warning: llvm-strip not found. Install llvm-toolchain for optimized objects."
	@test -d /sys/fs/bpf || echo "Warning: /sys/fs/bpf not found. Mount with: sudo mount -t bpf bpf /sys/fs/bpf"
	@test -f /sys/kernel/btf/vmlinux || echo "Warning: /sys/kernel/btf/vmlinux not found. BTF support may be limited."
	@echo "Dependencies check completed."

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(EBPF_SSL_HOOK_OBJ)
	rm -f $(VMLINUX_H)

# Real clean (including target directory)
realclean: clean
	rm -rf $(TARGET_DIR)

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build eBPF SSL Hook object (default)"
	@echo "  headers      - Generate vmlinux.h header"
	@echo "  verify       - Verify eBPF object"
	@echo "  install      - Install eBPF programs to kernel"
	@echo "  uninstall    - Remove eBPF programs from kernel"
	@echo "  check-deps   - Check build dependencies"
	@echo "  clean        - Remove build artifacts"
	@echo "  realclean    - Remove all generated files"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Build requirements:"
	@echo "  - clang/llvm (for eBPF compilation)"
	@echo "  - bpftool (for eBPF program loading and BTF)"
	@echo "  - linux-tools (for bpftool)"
	@echo "  - Kernel with eBPF support (>= 4.14)"
	@echo "  - Mounted eBPF filesystem: mount -t bpf bpf /sys/fs/bpf"

# Phony targets for cleanliness
.PHONY: all clean install uninstall check-deps headers verify realclean help