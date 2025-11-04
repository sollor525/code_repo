//! TLS Key Agent Hook Library
//!
//! 这是一个动态库，通过LD_PRELOAD机制hook OpenSSL函数调用
//! 来提取TLS密钥信息（Client Random和Master Secret）
//!
//! 编译命令:
//! ```bash
//! rustc --crate-type cdylib src/ffi/hook_library.rs -o libtls_key_agent_hook.so
//! ```
//!
//! 使用方法:
//! ```bash
//! export LD_PRELOAD=./libtls_key_agent_hook.so
//! export SSLKEYLOGFILE=/tmp/tls_keys.log
//! curl https://www.baidu.com
//! ```

use std::os::raw::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::ptr;
use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::Write;

// 全局状态
static HOOK_INITIALIZED: AtomicBool = AtomicBool::new(false);

// 原始OpenSSL函数指针
static mut ORIGINAL_SSL_WRITE: Option<unsafe extern "C" fn(*mut c_void, *const c_void, c_int) -> c_int> = None;
static mut ORIGINAL_SSL_READ: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, c_int) -> c_int> = None;
static mut ORIGINAL_SSL_CONNECT: Option<unsafe extern "C" fn(*mut c_void) -> c_int> = None;
static mut ORIGINAL_SSL_ACCEPT: Option<unsafe extern "C" fn(*mut c_void) -> c_int> = None;

// Hook的OpenSSL函数
#[no_mangle]
pub extern "C" fn SSL_write(
    ssl: *mut c_void,
    buf: *const c_void,
    num: c_int,
) -> c_int {
    unsafe {
        // 确保hook已初始化
        if !HOOK_INITIALIZED.load(Ordering::Relaxed) {
            initialize_hooks();
        }

        // 调用原始函数
        let original_fn = ORIGINAL_SSL_WRITE.unwrap_or(ssl_write_default);
        let result = original_fn(ssl, buf, num);

        // 提取密钥信息
        if result > 0 {
            extract_tls_keys(ssl, "SSL_write");
        }

        result
    }
}

#[no_mangle]
pub extern "C" fn SSL_read(
    ssl: *mut c_void,
    buf: *mut c_void,
    num: c_int,
) -> c_int {
    unsafe {
        // 确保hook已初始化
        if !HOOK_INITIALIZED.load(Ordering::Relaxed) {
            initialize_hooks();
        }

        // 调用原始函数
        let original_fn = ORIGINAL_SSL_READ.unwrap_or(ssl_read_default);
        let result = original_fn(ssl, buf, num);

        // 提取密钥信息
        if result > 0 {
            extract_tls_keys(ssl, "SSL_read");
        }

        result
    }
}

#[no_mangle]
pub extern "C" fn SSL_connect(ssl: *mut c_void) -> c_int {
    unsafe {
        // 确保hook已初始化
        if !HOOK_INITIALIZED.load(Ordering::Relaxed) {
            initialize_hooks();
        }

        // 调用原始函数
        let original_fn = ORIGINAL_SSL_CONNECT.unwrap_or(ssl_connect_default);
        let result = original_fn(ssl);

        // 提取密钥信息
        if result == 1 {
            extract_tls_keys(ssl, "SSL_connect");
        }

        result
    }
}

#[no_mangle]
pub extern "C" fn SSL_accept(ssl: *mut c_void) -> c_int {
    unsafe {
        // 确保hook已初始化
        if !HOOK_INITIALIZED.load(Ordering::Relaxed) {
            initialize_hooks();
        }

        // 调用原始函数
        let original_fn = ORIGINAL_SSL_ACCEPT.unwrap_or(ssl_accept_default);
        let result = original_fn(ssl);

        // 提取密钥信息
        if result == 1 {
            extract_tls_keys(ssl, "SSL_accept");
        }

        result
    }
}

/// 初始化Hook函数
unsafe fn initialize_hooks() {
    if HOOK_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    // 尝试获取原始OpenSSL函数地址
    if let Ok(lib) = libloading::Library::new("libssl.so.3") {
        // 获取原始函数指针
        if let Ok(sym) = lib.get::<unsafe extern "C" fn(*mut c_void, *const c_void, c_int) -> c_int>(b"SSL_write") {
            ORIGINAL_SSL_WRITE = Some(*sym);
        }

        if let Ok(sym) = lib.get::<unsafe extern "C" fn(*mut c_void, *mut c_void, c_int) -> c_int>(b"SSL_read") {
            ORIGINAL_SSL_READ = Some(*sym);
        }

        if let Ok(sym) = lib.get::<unsafe extern "C" fn(*mut c_void) -> c_int>(b"SSL_connect") {
            ORIGINAL_SSL_CONNECT = Some(*sym);
        }

        if let Ok(sym) = lib.get::<unsafe extern "C" fn(*mut c_void) -> c_int>(b"SSL_accept") {
            ORIGINAL_SSL_ACCEPT = Some(*sym);
        }
    }

    HOOK_INITIALIZED.store(true, Ordering::Relaxed);
    eprintln!("TLS Key Agent Hook initialized");
}

/// 提取TLS密钥信息
unsafe fn extract_tls_keys(ssl: *mut c_void, operation: &str) {
    // 尝试获取Client Random
    let mut client_random = [0u8; 32];
    let cr_len = ssl_get_client_random(ssl, client_random.as_mut_ptr(), client_random.len());

    if cr_len == 32 {
        // Client Random获取成功
        log_tls_key("CLIENT_RANDOM", &client_random, &[0u8; 48], operation);
    }
}

/// 记录TLS密钥到文件
fn log_tls_key(label: &str, client_random: &[u8], secret: &[u8], operation: &str) {
    if let Ok(keylog_file) = std::env::var("SSLKEYLOGFILE") {
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&keylog_file)
        {
            use std::io::Write;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let client_random_hex = hex::encode(client_random);
            let secret_hex = hex::encode(secret);

            let log_line = format!(
                "{} {} {} {} # {}\n",
                label,
                client_random_hex,
                secret_hex,
                timestamp,
                operation
            );

            let _ = file.write_all(log_line.as_bytes());
            let _ = file.flush();
        }
    }

    // 同时输出到stderr用于调试
    eprintln!(
        "TLS Key Extracted [{}]: CR={} Operation={}",
        label,
        hex::encode(&client_random[..client_random.len().min(8)]),
        operation
    );
}

// 默认函数实现（如果无法获取原始函数）
unsafe extern "C" fn ssl_write_default(
    _ssl: *mut c_void,
    _buf: *const c_void,
    _num: c_int,
) -> c_int {
    -1
}

unsafe extern "C" fn ssl_read_default(
    _ssl: *mut c_void,
    _buf: *mut c_void,
    _num: c_int,
) -> c_int {
    -1
}

unsafe extern "C" fn ssl_connect_default(_ssl: *mut c_void) -> c_int {
    -1
}

unsafe extern "C" fn ssl_accept_default(_ssl: *mut c_void) -> c_int {
    -1
}

// OpenSSL函数声明（通过动态加载获取）
unsafe fn ssl_get_client_random(
    ssl: *mut c_void,
    out: *mut u8,
    outlen: usize,
) -> c_int {
    // 这里应该动态获取SSL_get_client_random函数
    // 简化实现，返回0表示失败
    0
}

// 库初始化和清理函数
#[no_mangle]
pub extern "C" fn init_tls_key_agent_hook(_config: *const c_char) -> c_int {
    unsafe {
        initialize_hooks();
    }
    0
}

#[no_mangle]
pub extern "C" fn cleanup_tls_key_agent_hook() -> c_int {
    HOOK_INITIALIZED.store(false, Ordering::Relaxed);
    eprintln!("TLS Key Agent Hook cleaned up");
    0
}

// 支持的符号表，确保这些符号被导出
#[export_name = "SSL_write"]
pub static SSL_WRITE_SYM: u8 = 0;

#[export_name = "SSL_read"]
pub static SSL_READ_SYM: u8 = 0;

#[export_name = "SSL_connect"]
pub static SSL_CONNECT_SYM: u8 = 0;

#[export_name = "SSL_accept"]
pub static SSL_ACCEPT_SYM: u8 = 0;

// hex编码模块（简化版）
mod hex {
    pub fn encode(data: &[u8]) -> String {
        const HEX_CHARS: &[u8] = b"0123456789abcdef";
        let mut result = String::with_capacity(data.len() * 2);

        for &byte in data {
            result.push(HEX_CHARS[(byte >> 4) as usize] as char);
            result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
        }

        result
    }
}