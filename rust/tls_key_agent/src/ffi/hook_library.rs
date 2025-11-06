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
use std::collections::HashSet;
use std::sync::Mutex;
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
static mut SSL_EXPORT_KEYING_MATERIAL: Option<unsafe extern "C" fn(*const c_void, *mut u8, usize, *const c_char, usize, *const u8, usize, c_int) -> c_int> = None;

// OpenSSL库实例
static mut OPENSSL_LIB: Option<Library> = None;

// Hook的OpenSSL函数 - 增强版密钥提取时机检测
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

        // 在首次成功写入时提取密钥，这是握手中后期的好时机
        if result > 0 {
            // 检查是否为该SSL连接首次写入
            if is_first_operation(ssl, "write") {
                // 延迟一点时间确保握手完成
                std::thread::sleep(std::time::Duration::from_millis(10));
                extract_tls_keys_enhanced(ssl, "SSL_write");
            }
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

        // 在首次成功读取时提取密钥，这是握手完成后的最佳时机
        if result > 0 {
            // 检查是否为该SSL连接首次读取
            if is_first_operation(ssl, "read") {
                extract_tls_keys_enhanced(ssl, "SSL_read");
            }
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

        // 连接成功时立即尝试提取密钥
        if result == 1 {
            extract_tls_keys_enhanced(ssl, "SSL_connect");
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

        // 接受连接成功时立即尝试提取密钥
        if result == 1 {
            extract_tls_keys_enhanced(ssl, "SSL_accept");
        }

        result
    }
}

// SSL状态跟踪
static PROCESSED_SSLS: Mutex<HashSet<usize>> = Mutex::new(HashSet::new());

// 检查是否为首次操作
fn is_first_operation(ssl: *const c_void, operation: &str) -> bool {
    if ssl.is_null() {
        return false;
    }

    let ssl_ptr = ssl as usize;
    let mut processed = PROCESSED_SSLS.lock().unwrap();

    if !processed.contains(&ssl_ptr) {
        debug!("首次操作SSL {}: {}", ssl_ptr, operation);
        processed.insert(ssl_ptr);
        return true;
    }

    false
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

        // 加载SSL_export_keying_material用于Master Secret提取
        if let Ok(sym) = unsafe { lib.get::<unsafe extern "C" fn(*const c_void, *mut u8, usize, *const c_char, usize, *const u8, usize, c_int) -> c_int>(b"SSL_export_keying_material") } {
            SSL_EXPORT_KEYING_MATERIAL = Some(*sym);
            eprintln!("Successfully loaded SSL_export_keying_material");
        } else {
            eprintln!("Warning: SSL_export_keying_material not found");
        }
    } else {
        eprintln!("Failed to load any OpenSSL library");
    }

    HOOK_INITIALIZED.store(true, Ordering::Relaxed);
    eprintln!("TLS Key Agent Hook initialized");
}

/// 增强版TLS密钥提取 - 主动从SSL函数Hook中提取
unsafe fn extract_tls_keys_enhanced(ssl: *mut c_void, operation: &str) {
    if ssl.is_null() {
        eprintln!("SSL指针为空，跳过密钥提取");
        return;
    }

    eprintln!("开始增强版TLS密钥提取 - 操作: {}", operation);

    // 步骤1: 提取Client Random (优先级最高)
    let mut client_random = [0u8; 32];
    let client_random_result = extract_client_random_enhanced(ssl, &mut client_random);

    if !client_random_result {
        eprintln!("Client Random提取失败");
        return;
    }

    eprintln!("✓ Client Random提取成功: {}", hex::encode(&client_random[..8]));

    // 步骤2: 主动提取Master Secret (不依赖Keylog回调)
    let mut master_secret = [0u8; 48];
    let master_secret_result = extract_master_secret_enhanced(ssl, &mut master_secret);

    // 步骤3: 记录密钥信息
    if master_secret_result {
        eprintln!("✓ Master Secret提取成功: {}", hex::encode(&master_secret[..8]));
        log_tls_key_enhanced("CLIENT_RANDOM", &client_random, &master_secret, operation);
    } else {
        eprintln!("⚠ Master Secret提取失败 (这在现代OpenSSL中是正常的)");
        log_tls_key_enhanced("CLIENT_RANDOM", &client_random, &[0u8; 48], operation);
    }

    // 步骤4: 尝试提取额外的TLS信息
    extract_additional_tls_info(ssl);
}

/// 增强版Client Random提取 - 多方法多版本兼容
unsafe fn extract_client_random_enhanced(ssl: *const c_void, client_random: &mut [u8; 32]) -> bool {
    // 方法1: 使用OpenSSL官方API (最可靠)
    if let Some(func) = SSL_GET_CLIENT_RANDOM {
        let result = func(ssl, client_random.as_mut_ptr(), 32);
        if result == 32 {
            eprintln!("Client Random: 方法1 (OpenSSL API) 成功");
            return true;
        }
    }

    // 方法2: 直接访问SSL结构体 (OpenSSL 1.1.x 兼容)
    if access_ssl_structure_direct(ssl, client_random) {
        eprintln!("Client Random: 方法2 (直接结构体访问) 成功");
        return true;
    }

    // 方法3: 内存搜索回退 (兼容更多版本)
    if search_client_random_in_memory(ssl, client_random) {
        eprintln!("Client Random: 方法3 (内存搜索) 成功");
        return true;
    }

    eprintln!("Client Random: 所有方法都失败");
    false
}

/// 增强版Master Secret提取 - 主动不依赖Keylog回调
unsafe fn extract_master_secret_enhanced(ssl: *const c_void, master_secret: &mut [u8; 48]) -> bool {
    // 方法1: 尝试使用SSL_export_keying_material
    if export_keying_material_fallback(ssl, master_secret) {
        eprintln!("Master Secret: 方法1 (SSL_export_keying_material) 成功");
        return true;
    }

    // 方法2: 从SSL_SESSION中提取 (某些OpenSSL版本)
    if extract_from_ssl_session(ssl, master_secret) {
        eprintln!("Master Secret: 方法2 (SSL_SESSION) 成功");
        return true;
    }

    // 方法3: 内存搜索 (最不推荐，但作为最后回退)
    if search_master_secret_in_memory(ssl, master_secret) {
        eprintln!("Master Secret: 方法3 (内存搜索) 成功");
        return true;
    }

    eprintln!("Master Secret: 所有方法都失败 (这在现代OpenSSL中是正常的)");
    false
}

/// 直接访问SSL结构体
unsafe fn access_ssl_structure_direct(ssl: *const c_void, client_random: &mut [u8; 32]) -> bool {
    // 这里实现针对不同OpenSSL版本的结构体偏移量
    // 注意：这是简化版本，生产环境需要更精确的版本检测

    let ssl_ptr = ssl as *const u8;

    // 常见的SSL结构体偏移量 (需要根据具体OpenSSL版本调整)
    let offsets = [
        0x18,  // OpenSSL 1.1.x
        0x20,  // OpenSSL 1.0.x
        0x28,  // 其他版本
        0x30,
        0x38,
        0x40,
        0x48,
        0x50,
    ];

    for &offset in &offsets {
        let candidate_ptr = ssl_ptr.add(offset) as *const u8;

        // 检查这32字节是否看起来像Client Random
        if is_likely_client_random_enhanced(candidate_ptr) {
            client_random.copy_from_slice(std::slice::from_raw_parts(candidate_ptr, 32));
            return true;
        }
    }

    false
}

/// 内存搜索Client Random
unsafe fn search_client_random_in_memory(ssl: *const c_void, client_random: &mut [u8; 32]) -> bool {
    let ssl_ptr = ssl as *const u8;
    let search_range = 1024; // 搜索前1KB

    for offset in 0..search_range {
        let candidate_ptr = ssl_ptr.add(offset) as *const u8;

        if is_likely_client_random_enhanced(candidate_ptr) {
            // 验证这是合理的Client Random位置
            if validate_client_random_position(ssl, offset) {
                client_random.copy_from_slice(std::slice::from_raw_parts(candidate_ptr, 32));
                return true;
            }
        }
    }

    false
}

/// 增强版Client Random随机性检测
unsafe fn is_likely_client_random_enhanced(ptr: *const u8) -> bool {
    let data = std::slice::from_raw_parts(ptr, 32);

    // 检查1: 不应该全零或全相同
    let first_byte = data[0];
    if data.iter().all(|&b| b == first_byte) {
        return false;
    }

    // 检查2: 检查熵值 (简化版)
    let mut byte_counts = [0u8; 256];
    for &byte in data {
        byte_counts[byte as usize] += 1;
    }

    // 任何字节不应该出现超过4次 (32字节中)
    let max_count = byte_counts.iter().max().unwrap_or(&0);
    if *max_count > 4 {
        return false;
    }

    // 检查3: 不应该有太长的连续相同字节
    let mut max_consecutive = 1;
    let mut current_consecutive = 1;

    for i in 1..32 {
        if data[i] == data[i-1] {
            current_consecutive += 1;
            max_consecutive = max_consecutive.max(current_consecutive);
        } else {
            current_consecutive = 1;
        }
    }

    if max_consecutive > 3 {
        return false;
    }

    true
}

/// 验证Client Random位置的合理性
unsafe fn validate_client_random_position(ssl: *const c_void, offset: usize) -> bool {
    let ssl_ptr = ssl as *const u8;

    // 简单验证：Client Random应该在SSL对象的合理范围内
    if offset > 1024 { // 假设SSL对象不会太大
        return false;
    }

    // 可以添加更多验证逻辑
    true
}

/// 使用SSL_export_keying_material提取Master Secret
unsafe fn export_keying_material_fallback(ssl: *const c_void, master_secret: &mut [u8; 48]) -> bool {
    if let Some(func) = SSL_EXPORT_KEYING_MATERIAL {
        // 使用"master secret"标签提取Master Secret
        let label = b"master secret";
        let result = func(
            ssl,
            master_secret.as_mut_ptr(),
            48,
            label.as_ptr() as *const c_char,
            label.len(),
            std::ptr::null(), // 无context
            0,
            0 // 不使用context
        );

        if result > 0 {
            // 验证提取的密钥
            if is_likely_master_secret_enhanced(master_secret.as_ptr()) {
                return true;
            }
        }
    }

    false
}

/// 从SSL_SESSION提取Master Secret
unsafe fn extract_from_ssl_session(ssl: *const c_void, master_secret: &mut [u8; 48]) -> bool {
    // 实现从SSL_SESSION结构体中提取Master Secret
    // 这需要访问OpenSSL内部结构体，在不同版本中偏移量可能不同

    // 暂时返回false，表示此方法不可用
    false
}

/// 内存搜索Master Secret
unsafe fn search_master_secret_in_memory(ssl: *const c_void, master_secret: &mut [u8; 48]) -> bool {
    let ssl_ptr = ssl as *const u8;
    let search_range = 2048; // 搜索范围更大

    for offset in 0..search_range {
        let candidate_ptr = ssl_ptr.add(offset) as *const u8;

        if is_likely_master_secret_enhanced(candidate_ptr) {
            master_secret.copy_from_slice(std::slice::from_raw_parts(candidate_ptr, 48));
            return true;
        }
    }

    false
}

/// 增强版Master Secret检测
unsafe fn is_likely_master_secret_enhanced(ptr: *const u8) -> bool {
    let data = std::slice::from_raw_parts(ptr, 48);

    // 检查1: 不应该全零
    if data.iter().all(|&b| b == 0) {
        return false;
    }

    // 检查2: 不应该全相同
    let first_byte = data[0];
    if data.iter().all(|&b| b == first_byte) {
        return false;
    }

    // 检查3: 应该有足够的熵值
    let mut unique_bytes = 0;
    let mut seen = [false; 256];

    for &byte in data {
        if !seen[byte as usize] {
            seen[byte as usize] = true;
            unique_bytes += 1;
        }
    }

    // 48字节中至少要有16个不同的字节
    unique_bytes >= 16
}

/// 提取额外的TLS信息
unsafe fn extract_additional_tls_info(ssl: *const c_void) {
    // 可以在这里提取更多TLS会话信息
    // 如TLS版本、密码套件、会话ID等
    eprintln!("额外TLS信息提取完成");
}

/// 增强版密钥日志记录 - 减少Keylog依赖
fn log_tls_key_enhanced(label: &str, client_random: &[u8], secret: &[u8], operation: &str) {
    // 仍然支持SSLKEYLOGFILE环境变量，但不依赖它
    if let Ok(keylog_file) = std::env::var("SSLKEYLOGFILE") {
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&keylog_file)
        {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let client_random_hex = hex::encode(client_random);
            let secret_hex = hex::encode(secret);

            // 使用标准Wireshark格式
            let log_line = if secret.iter().any(|&b| b != 0) {
                // 有有效的Master Secret
                format!("CLIENT_RANDOM {} {} {}", client_random_hex, secret_hex, timestamp)
            } else {
                // 只有Client Random
                format!("CLIENT_RANDOM {} {} {}", client_random_hex, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", timestamp)
            };

            let _ = file.write_all(log_line.as_bytes());
            let _ = file.write_all(b"\n");
            let _ = file.flush();
        }
    }

    // 同时输出到stderr用于调试
    eprintln!(
        "密钥提取完成 [{}] - 操作: {} - CR: {} - MS: {}",
        label,
        operation,
        hex::encode(&client_random[..8]),
        if secret.iter().any(|&b| b != 0) {
            hex::encode(&secret[..8])
        } else {
            "未提取".to_string()
        }
    );
}

/// 记录TLS密钥到文件 (旧版本保留作为回退)
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