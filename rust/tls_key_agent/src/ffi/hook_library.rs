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
use std::mem;
use libloading::{Library, Symbol};

// 全局状态
static HOOK_INITIALIZED: AtomicBool = AtomicBool::new(false);

// 原始OpenSSL函数指针
static mut ORIGINAL_SSL_WRITE: Option<unsafe extern "C" fn(*mut c_void, *const c_void, c_int) -> c_int> = None;
static mut ORIGINAL_SSL_READ: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, c_int) -> c_int> = None;
static mut ORIGINAL_SSL_CONNECT: Option<unsafe extern "C" fn(*mut c_void) -> c_int> = None;
static mut ORIGINAL_SSL_ACCEPT: Option<unsafe extern "C" fn(*mut c_void) -> c_int> = None;

// OpenSSL密钥提取函数指针
static mut SSL_GET_CLIENT_RANDOM: Option<unsafe extern "C" fn(*const c_void, *mut u8, c_int) -> c_int> = None;
static mut SSL_GET_MASTER_KEY: Option<unsafe extern "C" fn(*const c_void, *mut u8, c_int) -> c_int> = None;

// OpenSSL库实例
static mut OPENSSL_LIB: Option<Library> = None;

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

    // 尝试多个OpenSSL库版本
    let ssl_libs = ["libssl.so.3", "libssl.so.1.1", "libssl.so"];

    for lib_name in &ssl_libs {
        match libloading::Library::new(lib_name) {
            Ok(lib) => {
                eprintln!("Loaded OpenSSL library: {}", lib_name);
                OPENSSL_LIB = Some(lib);
                break;
            }
            Err(e) => {
                eprintln!("Failed to load {}: {}", lib_name, e);
                continue;
            }
        }
    }

    if let Some(ref lib) = OPENSSL_LIB {
        // 获取原始SSL函数指针
        if let Ok(sym) = unsafe { lib.get::<unsafe extern "C" fn(*mut c_void, *const c_void, c_int) -> c_int>(b"SSL_write") } {
            ORIGINAL_SSL_WRITE = Some(*sym);
        }

        if let Ok(sym) = unsafe { lib.get::<unsafe extern "C" fn(*mut c_void, *mut c_void, c_int) -> c_int>(b"SSL_read") } {
            ORIGINAL_SSL_READ = Some(*sym);
        }

        if let Ok(sym) = unsafe { lib.get::<unsafe extern "C" fn(*mut c_void) -> c_int>(b"SSL_connect") } {
            ORIGINAL_SSL_CONNECT = Some(*sym);
        }

        if let Ok(sym) = unsafe { lib.get::<unsafe extern "C" fn(*mut c_void) -> c_int>(b"SSL_accept") } {
            ORIGINAL_SSL_ACCEPT = Some(*sym);
        }

        // 获取密钥提取函数指针
        if let Ok(sym) = unsafe { lib.get::<unsafe extern "C" fn(*const c_void, *mut u8, c_int) -> c_int>(b"SSL_get_client_random") } {
            SSL_GET_CLIENT_RANDOM = Some(*sym);
            eprintln!("Successfully loaded SSL_get_client_random");
        } else {
            eprintln!("Warning: SSL_get_client_random not found");
        }

        if let Ok(sym) = unsafe { lib.get::<unsafe extern "C" fn(*const c_void, *mut u8, c_int) -> c_int>(b"SSL_get_master_key") } {
            SSL_GET_MASTER_KEY = Some(*sym);
            eprintln!("Successfully loaded SSL_get_master_key");
        }

        // 尝试获取SSL_CTX_new和SSL_CTX_set_keylog_callback
        if let Ok(_) = unsafe { lib.get::<unsafe extern "C" fn() -> *mut c_void>(b"SSL_CTX_new") } {
            eprintln!("SSL_CTX_new found - keylog callback available");
        }
    } else {
        eprintln!("Failed to load any OpenSSL library");
    }

    HOOK_INITIALIZED.store(true, Ordering::Relaxed);
    eprintln!("TLS Key Agent Hook initialized");
}

/// 提取TLS密钥信息
unsafe fn extract_tls_keys(ssl: *mut c_void, operation: &str) {
    // 尝试获取Client Random
    let mut client_random = [0u8; 32];
    let mut master_secret = [0u8; 48];

    let cr_len = if let Some(func) = SSL_GET_CLIENT_RANDOM {
        func(ssl, client_random.as_mut_ptr(), client_random.len() as c_int)
    } else {
        ssl_get_client_random_fallback(ssl, client_random.as_mut_ptr(), client_random.len() as c_int)
    };

    if cr_len == 32 {
        // Client Random获取成功
        eprintln!("Successfully extracted Client Random: {}", hex::encode(&client_random[..8]));

        // 尝试获取Master Secret
        let ms_len = if let Some(func) = SSL_GET_MASTER_KEY {
            func(ssl, master_secret.as_mut_ptr(), master_secret.len() as c_int)
        } else {
            ssl_get_master_secret_fallback(ssl, master_secret.as_mut_ptr(), master_secret.len() as c_int)
        };

        if ms_len == 48 {
            eprintln!("Successfully extracted Master Secret: {}", hex::encode(&master_secret[..8]));
            log_tls_key("CLIENT_RANDOM", &client_random, &master_secret, operation);
        } else {
            // 只有Client Random
            log_tls_key("CLIENT_RANDOM", &client_random, &[0u8; 48], operation);
        }
    } else {
        eprintln!("Failed to extract Client Random (length: {})", cr_len);
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

// 回退的密钥提取函数（当动态加载失败时使用）
unsafe fn ssl_get_client_random_fallback(
    ssl: *const c_void,
    out: *mut u8,
    outlen: c_int,
) -> c_int {
    // 尝试通过结构体偏移量访问Client Random
    // 这是OpenSSL SSL结构体的简化访问方法

    if outlen < 32 || out.is_null() || ssl.is_null() {
        return 0;
    }

    // OpenSSL SSL结构体布局（简化版本）
    // 注意：这种方法依赖于具体的OpenSSL版本，可能不稳定
    let ssl_ptr = ssl as *const u8;

    // 尝试多个可能的偏移量（根据不同OpenSSL版本）
    let offsets = [
        0x0,   // 尝试不同的偏移量
        0x10,
        0x20,
        0x30,
        0x40,
        0x50,
        0x60,
        0x70,
    ];

    for offset in &offsets {
        let target_ptr = unsafe { ssl_ptr.add(*offset) } as *const u8;

        // 检查这个位置是否可能是Client Random（32字节）
        if unsafe { is_likely_client_random(target_ptr) } {
            // 复制数据
            for i in 0..32 {
                if i < outlen as usize {
                    unsafe {
                        *out.add(i) = *target_ptr.add(i);
                    }
                }
            }
            return 32;
        }
    }

    eprintln!("Fallback: Could not locate Client Random in SSL structure");
    0
}

unsafe fn ssl_get_master_secret_fallback(
    ssl: *const c_void,
    out: *mut u8,
    outlen: c_int,
) -> c_int {
    // Master Secret通常位于Client Random附近
    // 这里实现一个简化的搜索逻辑

    if outlen < 48 || out.is_null() || ssl.is_null() {
        return 0;
    }

    let ssl_ptr = ssl as *const u8;
    let search_range = 512; // 搜索范围

    for offset in 0..search_range {
        let target_ptr = unsafe { ssl_ptr.add(offset) } as *const u8;

        // 检查这个位置是否可能是Master Secret（48字节）
        if unsafe { is_likely_master_secret(target_ptr) } {
            // 复制数据
            for i in 0..48 {
                if i < outlen as usize {
                    unsafe {
                        *out.add(i) = *target_ptr.add(i);
                    }
                }
            }
            return 48;
        }
    }

    0
}

// 辅助函数：检查是否可能是Client Random
unsafe fn is_likely_client_random(ptr: *const u8) -> bool {
    // Client Random应该是32字节的高熵数据
    let data = std::slice::from_raw_parts(ptr, 32);

    // 简单的熵检测：检查是否有足够的随机性
    let mut byte_counts = [0u8; 256];
    for &byte in data {
        byte_counts[byte as usize] += 1;
    }

    // 计算熵（简化版本）
    let max_count = byte_counts.iter().max().unwrap_or(&0);

    // 如果某个字节出现次数过多，说明不是随机数据
    *max_count <= 2
}

// 辅助函数：检查是否可能是Master Secret
unsafe fn is_likely_master_secret(ptr: *const u8) -> bool {
    // Master Secret是48字节，通常比Client Random更有结构
    let data = std::slice::from_raw_parts(ptr, 48);

    // 简单的检查：不应该全零或全相同
    let first_byte = data[0];
    if data.iter().all(|&b| b == first_byte) {
        return false;
    }

    // 检查是否有一些合理的模式
    let mut non_zero_count = 0;
    for &byte in data {
        if byte != 0 {
            non_zero_count += 1;
        }
    }

    // 至少有一半字节非零
    non_zero_count >= 24
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