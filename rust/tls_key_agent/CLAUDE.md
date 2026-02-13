# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

<!-- OPENSPEC:START -->
# OpenSpec Instructions

These instructions are for AI assistants working in this project.

Always open `@/openspec/AGENTS.md` when the request:
- Mentions planning or proposals (words like proposal, spec, change, plan)
- Introduces new capabilities, breaking changes, architecture shifts, or big performance/security work
- Sounds ambiguous and you need the authoritative spec before coding

Use `@/openspec/AGENTS.md` to learn:
- How to create and apply change proposals
- Spec format and conventions
- Project structure and guidelines

Keep this managed block so 'openspec update' can refresh the instructions.

<!-- OPENSPEC:END -->

## Build and Development Commands

### Core Build Commands
```bash
# Build everything (Rust agent + C hook library)
./build.sh release

# Build debug version
./build.sh debug

# Clean build artifacts
./build.sh clean

# Build only Rust components
cargo build --release

# Build only C hook library
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread
```

### Testing and Validation
```bash
# Run Rust tests
cargo test

# Run comprehensive integration tests
./test_agent_hook_integration.sh

# Test architecture modes comparison
./test_architecture_comparison.sh

# Run code quality checks
./build.sh check  # Runs cargo fmt and clippy
```

### Agent Usage
```bash
# Start agent with configuration
./target/release/tls_key_agent --config agent_config.toml

# Start agent in daemon mode
./target/release/tls_key_agent --config agent_config.toml --daemon

# Start standalone hook library mode
LD_PRELOAD=./libtls_agent_hook.so curl https://example.com
```

### Development Tools
```bash
# Verify extracted keys
./target/release/verify_keys

# Test specific TLS connection
LD_PRELOAD=./libtls_agent_hook.so ./test_real_tls

# Monitor logs in real-time
tail -f /tmp/openssl_keys_all.log
```

## Architecture Overview

TLS Key Agent implements a **dual-architecture system** for TLS key extraction:

### Architecture Mode 1: Standalone Hook Library (Recommended)
- **Entry Point**: `src/openssl_hook.c` - C LD_PRELOAD library
- **Target Use**: Simple deployments, Wireshark integration, security testing
- **How it works**: Direct SSL function hooking without external dependencies
- **Output**: Direct file output to `/tmp/openssl_keys_all.log`

### Architecture Mode 2: Agent + Hook Combination (Enterprise)
- **Entry Point**: `src/main.rs` - Rust agent process
- **Target Use**: Enterprise deployment, remote collection, complex filtering
- **How it works**: Agent process manages configuration and transport, hook library handles extraction
- **Components**: Configurable filtering, TCP/file transport, centralized management

## Key Code Architecture

### Core Rust Modules (`src/`)
- **`lib.rs`**: Main TLS Key Agent struct and lifecycle management
- **`main.rs`**: CLI interface and agent process bootstrap
- **`config/`**: TOML configuration parsing and management
  - `mod.rs`: Core configuration structures and validation
  - `filter.rs`: Network five-tuple and process filtering rules
- **`extractor/`**: TLS key extraction engine
  - `mod.rs`: Main extractor interface and session management
  - `ssl_hook.rs`: SSL function hooking integration
  - `key_processor.rs`: Key validation and formatting
- **`transport/`**: Data transmission layer
  - `mod.rs`: Transport manager and multiplexing
  - `tcp_transport.rs`: Remote TCP transmission
  - `file_transport.rs`: Local file output with rotation
- **`ffi/`**: Foreign Function Interface for C integration
- **`injector/`**: Process injection mechanisms (LD_PRELOAD, eBPF)

### C Hook Library (`src/openssl_hook.c`)
- **Function Interception**: Hooks SSL_write, SSL_read, SSL_connect, SSL_accept
- **Multi-algorithm Extraction**: Client Random (3 methods) + Master Secret (3 strategies)
- **Thread Safety**: Thread-local storage to prevent duplicate extraction
- **Memory Access**: Direct SSL structure access when APIs fail

### Configuration System
- **Primary Config**: `config.toml` / `agent_config.toml` for enterprise mode
- **Standalone Mode**: No configuration required, uses sensible defaults
- **Filter Rules**: Five-tuple network filtering, process name filtering, time-based rules
- **Transport Config**: TCP remote collection, file output with rotation, compression options

## Development Patterns

### Adding New Extraction Algorithms
1. Implement in `src/openssl_hook.c` under the `extract_*_proactive` functions
2. Add fallback logic in existing multi-algorithm chains
3. Update validation in `is_likely_*_c` functions
4. Test with `./test_real_tls` and verify output format

### Modifying Agent Configuration
1. Update structures in `src/config/mod.rs`
2. Add validation logic in `Config::validate()`
3. Update default configurations in `impl Default`
4. Test with `./target/release/tls_key_agent --config test_config.toml`

### Adding Transport Mechanisms
1. Implement trait in `src/transport/` following existing patterns
2. Register in `TransportManager::new()`
3. Add configuration options in `TransportConfig`
4. Test with both agent and standalone modes

## Important Implementation Details

### OpenSSl Version Compatibility
- The C hook library implements **3-tier fallback strategy** for Client Random extraction:
  1. Official API (`SSL_get_client_random`)
  2. Direct structure access (`ssl->s3->client_random`)
  3. Memory pattern search
- Similar 3-tier strategy for Master Secret extraction
- Always validate with multiple OpenSSL versions before merging

### Thread Safety Considerations
- Hook library uses **thread-local storage** (`__thread`) to prevent duplicate extraction per SSL session
- Agent process uses `Arc<Mutex<>>` for shared state management
- All async operations use `tokio` runtime with proper error handling

### Memory Management
- Agent uses pre-allocated **buffer pools** for high-performance scenarios
- Hook library avoids dynamic allocation in SSL function interceptors
- All extracted keys are validated for entropy and format before output

### Security Considerations
- **Sensitive data**: TLS keys are highly sensitive - ensure proper access controls
- **Production deployment**: Use encrypted transmission for remote key collection
- **Process filtering**: Agent supports filtering critical system processes for safety
- **Audit logging**: Enable comprehensive logging for compliance requirements

## Testing Strategy

### Unit Testing
```bash
# Test specific Rust module
cargo test config
cargo test extractor
cargo test transport

# Run with backtrace for debugging
RUST_BACKTRACE=1 cargo test
```

### Integration Testing
```bash
# Test hook library extraction
gcc -o test_hook test_hook_simple.c -lssl -lcrypto
LD_PRELOAD=./libtls_agent_hook.so ./test_hook

# Test agent functionality
./target/release/tls_key_agent --config test_config.toml &
LD_PRELOAD=./libtls_agent_hook.so curl https://example.com
```

### Performance Testing
```bash
# High-concurrency test
./test_performance.sh

# Memory leak detection
valgrind --tool=memcheck --leak-check=full ./target/release/tls_key_agent
```

## Common Development Workflows

### Adding New TLS Library Support
1. Extend C hook library with new library detection
2. Implement library-specific extraction functions
3. Add configuration options for library selection
4. Update OpenSpec specs in `openspec/specs/tls-extraction/`

### Debugging Hook Issues
```bash
# Enable debug logging
export RUST_LOG=debug

# Check library loading
LD_PRELOAD=./libtls_agent_hook.so LD_DEBUG=libs your_app

# Monitor hook calls
strace -e trace=write -o debug.log LD_PRELOAD=./libtls_agent_hook.so your_app
```

### Agent Configuration Debugging
```bash
# Validate configuration syntax
./target/release/tls_key_agent --config config.toml --help

# Test with minimal config
cargo run -- --config examples/minimal_config.toml

# Check filter rule matching
RUST_LOG=debug ./target/release/tls_key_agent --config config.toml 2>&1 | grep -i filter
```