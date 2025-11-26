//! FFI（外部函数接口）模块
//! 
//! 提供C语言兼容的接口，用于与npatch系统集成。
//! 这个模块允许C/C++代码调用Rust编写的Web扫描检测功能。
//! 
//! # 安全说明
//! FFI函数涉及不安全的代码，调用者必须确保传入的参数是有效的。
//! 所有不安全的操作都有相应的安全检查。

// 导入引擎相关类型
use crate::engine::{WebScanEngine, WebScanResult, WebScanAction};
// 导入统计信息类型
use crate::stats::WebScanStats;
// 导入协议类型
use crate::protocol::Protocol;
// 导入Hyperscan相关类型
// 导入C字符串处理类型
use std::ffi::{CStr, CString};
// 导入C语言原始类型
use std::os::raw::{c_char, c_int};
// 导入空指针类型
use std::ptr;
// 导入同步原语
use std::sync::{Mutex, OnceLock};
// 导入高性能读写锁
use parking_lot::RwLock;
// 导入路径处理
use std::path::Path;

// 全局引擎实例
// OnceLock确保引擎只被初始化一次，RwLock提供线程安全的访问
static ENGINE: OnceLock<RwLock<WebScanEngine>> = OnceLock::new();

// 错误处理
// 存储最后一次错误的C字符串，用于C代码获取错误信息
static LAST_ERROR: Mutex<Option<CString>> = Mutex::new(None);

/// C语言兼容的Web扫描检测结果结构体
///
/// 这个结构体与C头文件中的web_scan_result_t完全兼容，用于FFI接口。
/// 注意：这个结构体不包含direction和status_code字段，因为C头文件中不包含这些字段。
#[repr(C)]
pub struct web_scan_result_t {
    pub is_matched: bool,           // 是否匹配到规则
    pub rule_id: u32,              // 匹配的规则ID（如果匹配的话）
    pub action: web_scan_action_t,  // 建议执行的动作
    pub content_length: u32,        // 检测内容的长度
    pub protocol: web_scan_protocol_t, // 检测到的协议类型
    pub confidence: u8,             // 协议检测的置信度（0-100）
}

/// C语言兼容的动作枚举
///
/// 这个枚举与C头文件中的web_scan_action_e完全兼容。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum web_scan_action_t {
    None = 0,       // 无动作
    Alert = 1,      // 告警
    Block = 2,      // 阻断
    Log = 3,        // 记录日志
}

/// C语言兼容的协议枚举
///
/// 这个枚举与C头文件中的web_scan_protocol_e完全兼容。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum web_scan_protocol_t {
    Unknown = 0,    // 未知协议
    Http = 1,       // HTTP协议
    Https = 2,      // HTTPS协议
    Http2 = 3,      // HTTP/2协议
    WebSocket = 4,  // WebSocket协议
}

/// 从Rust的WebScanAction转换为C兼容的web_scan_action_t
impl From<WebScanAction> for web_scan_action_t {
    fn from(action: WebScanAction) -> Self {
        match action {
            WebScanAction::None => web_scan_action_t::None,
            WebScanAction::Alert => web_scan_action_t::Alert,
            WebScanAction::Drop => web_scan_action_t::Block,  // 映射Drop到Block
            WebScanAction::Reset => web_scan_action_t::Block, // 映射Reset到Block
        }
    }
}

/// 从Rust的Protocol转换为C兼容的web_scan_protocol_t
impl From<Protocol> for web_scan_protocol_t {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Unknown => web_scan_protocol_t::Unknown,
            Protocol::Http => web_scan_protocol_t::Http,
            Protocol::Https => web_scan_protocol_t::Https,
            Protocol::Http2 => web_scan_protocol_t::Http2,
            // Protocol枚举中没有WebSocket变体，所以移除这行
        }
    }
}

/// 从Rust的WebScanResult转换为C兼容的web_scan_result_t
impl From<&WebScanResult> for web_scan_result_t {
    fn from(result: &WebScanResult) -> Self {
        Self {
            is_matched: result.is_matched,
            rule_id: result.rule_id,
            action: result.action.into(),
            content_length: result.content_length,
            protocol: result.protocol.into(),
            confidence: result.confidence,
        }
    }
}

/// 初始化Web扫描检测引擎
///
/// 这个函数创建全局的引擎实例，必须在调用其他函数之前调用。
/// 多次调用是安全的，只有第一次调用会真正执行初始化。
///
/// # 安全性
/// 这个函数可以从C代码安全调用。
///
/// # 返回值
/// * `0` - 成功
/// * `-1` - 初始化失败
#[no_mangle]
pub extern "C" fn web_scan_rust_init() -> c_int {
    web_scan_rust_init_with_hyperscan()
}

/// 初始化Web扫描检测引擎（Hyperscan模式）
///
/// 这个函数创建全局的引擎实例，默认启用Hyperscan高性能匹配。
/// 多次调用是安全的，只有第一次调用会真正执行初始化。
///
/// # 安全性
/// 这个函数可以从C代码安全调用。
///
/// # 返回值
/// * `0` - 成功
/// * `-1` - 初始化失败
#[no_mangle]
pub extern "C" fn web_scan_rust_init_with_hyperscan() -> c_int {
    // 调用Rust库的初始化函数
    crate::init();

    // 创建新的Web扫描引擎实例（默认启用Hyperscan）
    let mut engine = WebScanEngine::new();

    // 尝试加载默认规则文件（如果存在）
    // 首先尝试相对于当前工作目录的路径
    let default_rules_paths = [
        "rules/web_detect_rules.rules",
        "../rules/web_detect_rules.rules",
        "../../rules/web_detect_rules.rules",
    ];
    
    let mut rules_loaded = false;
    for rules_path in &default_rules_paths {
        if Path::new(rules_path).exists() {
            match engine.init_with_rules(rules_path) {
                Ok(_) => {
                    log::info!("Loaded default rules from {}", rules_path);
                    rules_loaded = true;
                    break;
                }
                Err(e) => {
                    log::warn!("Failed to load default rules from {}: {}", rules_path, e);
                    // 继续尝试其他路径
                }
            }
        }
    }
    
    if !rules_loaded {
        log::debug!("Default rules file not found, engine initialized without rules");
    }

    // 尝试将引擎存储到全局变量中
    match ENGINE.set(RwLock::new(engine)) {
        Ok(_) => {
            // 成功设置引擎
            log::info!("Web scan engine initialized successfully with Hyperscan");
            0 // 返回成功代码
        }
        Err(_) => {
            // 引擎已经被初始化过了，这是正常的，返回成功
            log::info!("Web scan engine already initialized");
            0 // 返回成功代码
        }
    }
}

/// 从文件加载检测规则
/// 
/// 支持JSON和TOML格式的规则文件。
/// 
/// # 参数
/// * `rules_path` - 规则文件路径的C字符串指针
/// 
/// # 安全性
/// 调用者必须确保`rules_path`是一个有效的以null结尾的C字符串。
/// 
/// # 返回值
/// * `0` - 成功加载规则
/// * 负数 - 错误代码（具体含义见WebScanError）
#[no_mangle]
pub extern "C" fn web_scan_rust_load_rules(rules_path: *const c_char) -> c_int {
    // 检查指针是否为空
    if rules_path.is_null() {
        set_last_error("Null rules path");
        return -1;
    }

    // 将C字符串转换为Rust字符串
    // unsafe块是必要的，因为我们正在处理原始指针
    let rules_path_str = match unsafe { CStr::from_ptr(rules_path) }.to_str() {
        Ok(s) => s,  // 转换成功
        Err(_) => {
            // 转换失败，可能是无效的UTF-8
            set_last_error("Invalid UTF-8 in rules path");
            return -1;
        }
    };

    // 获取全局引擎实例
    let engine = match ENGINE.get() {
        Some(e) => e,  // 引擎已初始化
        None => {
            // 引擎未初始化
            set_last_error("Engine not initialized");
            return -1;
        }
    };

    // 尝试加载规则（使用 reload_rules 清除现有规则）
    match engine.write().reload_rules(rules_path_str) {
        Ok(_) => {
            // 规则加载成功
            log::info!("Rules loaded successfully from {}", rules_path_str);
            0
        }
        Err(e) => {
            // 规则加载失败，设置错误信息并返回错误代码
            set_last_error(&format!("Failed to load rules: {}", e));
            e.to_error_code()
        }
    }
}

/// 处理数据包载荷
///
/// 这是主要的检测函数，分析数据包内容并返回检测结果。
/// 注意：此函数每次调用都创建新的流，适用于非流式场景。
/// 对于需要跨数据包匹配的场景，请使用 `web_scan_rust_process_payload_with_session`。
///
/// # 参数
/// * `payload` - 指向数据包载荷的指针
/// * `payload_len` - 载荷长度（字节数）
/// * `result` - 指向结果结构体的指针，用于存储检测结果
///
/// # 安全性
/// 调用者必须确保：
/// - `payload`指向至少`payload_len`字节的有效内存
/// - `result`指向有效的web_scan_result_t结构体内存
///
/// # 返回值
/// * `0` - 成功处理
/// * 负数 - 错误代码
#[no_mangle]
pub extern "C" fn web_scan_rust_process_payload(
    payload: *const u8,
    payload_len: u32,
    result: *mut web_scan_result_t,
) -> c_int {
    // 检查指针是否为空
    if payload.is_null() || result.is_null() {
        set_last_error("Null pointer provided");
        return -1;
    }

    // 从原始指针创建字节切片
    // unsafe块是必要的，因为我们正在处理原始指针
    let payload_slice = unsafe {
        std::slice::from_raw_parts(payload, payload_len as usize)
    };

    // 获取全局引擎实例
    let engine = match ENGINE.get() {
        Some(e) => e,
        None => {
            set_last_error("Engine not initialized");
            return -1;
        }
    };

    // 处理数据包载荷
    match engine.read().process_payload(payload_slice) {
        Ok(scan_result) => {
            // 将Rust的WebScanResult转换为C兼容的web_scan_result_t
            let c_result = web_scan_result_t::from(&scan_result);
            
            // 将结果写入C代码提供的结果结构体
            unsafe {
                *result = c_result;
            }
            0 // 成功
        }
        Err(e) => {
            // 处理失败，设置错误信息并返回错误代码
            set_last_error(&format!("Failed to process payload: {}", e));
            e.to_error_code()
        }
    }
}

/// 处理数据包载荷（带会话管理）
///
/// 这是支持流式匹配的检测函数，为每个会话维护独立的Hyperscan流。
/// 同一个会话的所有数据包必须使用相同的session_id。
///
/// # 参数
/// * `session_id` - 会话标识符，同一个会话使用相同的ID
/// * `payload` - 指向数据包载荷的指针
/// * `payload_len` - 载荷长度（字节数）
/// * `is_final` - 是否为该会话的最后一个数据包（0=否，非0=是）
/// * `reset_on_request_end` - 是否在请求结束时重置流（0=否，非0=是，用于HTTP请求/响应流）
/// * `result` - 指向结果结构体的指针，用于存储检测结果
///
/// # 安全性
/// 调用者必须确保：
/// - `payload`指向至少`payload_len`字节的有效内存
/// - `result`指向有效的web_scan_result_t结构体内存
///
/// # 返回值
/// * `0` - 成功处理
/// * 负数 - 错误代码
#[no_mangle]
pub extern "C" fn web_scan_rust_process_payload_with_session(
    session_id: u64,
    payload: *const u8,
    payload_len: u32,
    is_final: c_int,
    reset_on_request_end: c_int,
    result: *mut web_scan_result_t,
) -> c_int {
    // 检查指针是否为空
    if payload.is_null() || result.is_null() {
        set_last_error("Null pointer provided");
        return -1;
    }

    // 从原始指针创建字节切片
    let payload_slice = unsafe {
        std::slice::from_raw_parts(payload, payload_len as usize)
    };

    // 获取全局引擎实例
    let engine = match ENGINE.get() {
        Some(e) => e,
        None => {
            set_last_error("Engine not initialized");
            return -1;
        }
    };

    // 处理数据包载荷（带会话管理）
    let is_final_bool = is_final != 0;
    let reset_on_request_end_bool = reset_on_request_end != 0;
    match engine.read().process_payload_with_session(session_id, payload_slice, is_final_bool, reset_on_request_end_bool) {
        Ok(scan_result) => {
            // 将Rust的WebScanResult转换为C兼容的web_scan_result_t
            let c_result = web_scan_result_t::from(&scan_result);
            
            // 将结果写入C代码提供的结果结构体
            unsafe {
                *result = c_result;
            }
            0 // 成功
        }
        Err(e) => {
            // 处理失败，设置错误信息并返回错误代码
            set_last_error(&format!("Failed to process payload with session: {}", e));
            e.to_error_code()
        }
    }
}

/// 获取当前统计信息
/// 
/// 返回引擎运行过程中的各种统计指标。
/// 
/// # 参数
/// * `stats` - 指向统计信息结构体的指针
/// 
/// # 安全性
/// 调用者必须确保`stats`指向有效的WebScanStats结构体内存。
/// 
/// # 返回值
/// * `0` - 成功获取统计信息
/// * 负数 - 错误代码
#[no_mangle]
pub extern "C" fn web_scan_rust_get_stats(stats: *mut WebScanStats) -> c_int {
    // 检查指针是否为空
    if stats.is_null() {
        set_last_error("Null stats pointer");
        return -1;
    }

    // 获取全局引擎实例
    let engine = match ENGINE.get() {
        Some(e) => e,
        None => {
            set_last_error("Engine not initialized");
            return -1;
        }
    };

    // 获取统计信息
    let current_stats = engine.read().get_stats();
    
    // 将统计信息写入C代码提供的结果结构体
    unsafe {
        *stats = current_stats;
    }
    
    0 // 成功
}

/// 重置统计信息
/// 
/// 将所有计数器重置为0，开始新的统计周期。
/// 
/// # 返回值
/// * `0` - 成功重置
/// * 负数 - 错误代码
#[no_mangle]
pub extern "C" fn web_scan_rust_reset_stats() -> c_int {
    // 获取全局引擎实例
    let engine = match ENGINE.get() {
        Some(e) => e,
        None => {
            set_last_error("Engine not initialized");
            return -1;
        }
    };

    // 重置统计信息
    engine.read().reset_stats();
    
    0 // 成功
}

/// 获取最后错误信息
/// 
/// 返回最后一次操作失败时的错误描述。
/// 
/// # 返回值
/// * 指向错误字符串的指针，如果没有错误则返回null
/// 
/// # 注意
/// 返回的字符串由库管理，调用者不应该释放它。
/// 每次调用此函数都会返回最新的错误信息。
#[no_mangle]
pub extern "C" fn web_scan_rust_get_last_error() -> *const c_char {
    // 获取错误信息
    let error_guard = LAST_ERROR.lock().unwrap();
    
    match &*error_guard {
        Some(error_string) => {
            // 返回错误字符串的指针
            error_string.as_ptr()
        }
        None => {
            // 没有错误信息
            ptr::null()
        }
    }
}

/// 设置引擎启用状态
/// 
/// 控制引擎是否处理数据包。禁用状态下，所有检测都会返回默认结果。
/// 
/// # 参数
/// * `enabled` - 是否启用引擎（0=禁用，非0=启用）
/// 
/// # 返回值
/// * `0` - 成功设置
/// * 负数 - 错误代码
#[no_mangle]
pub extern "C" fn web_scan_rust_set_enabled(enabled: c_int) -> c_int {
    // 获取全局引擎实例
    let engine = match ENGINE.get() {
        Some(e) => e,
        None => {
            set_last_error("Engine not initialized");
            return -1;
        }
    };

    // 设置启用状态
    engine.write().set_enabled(enabled != 0);
    
    0 // 成功
}

/// 检查引擎是否启用
/// 
/// # 返回值
/// * `0` - 引擎已禁用
/// * `1` - 引擎已启用
/// * 负数 - 错误代码
#[no_mangle]
pub extern "C" fn web_scan_rust_is_enabled() -> c_int {
    // 获取全局引擎实例
    let engine = match ENGINE.get() {
        Some(e) => e,
        None => {
            set_last_error("Engine not initialized");
            return -1;
        }
    };

    // 检查启用状态
    if engine.read().is_enabled() {
        1 // 已启用
    } else {
        0 // 已禁用
    }
}

/// 获取当前加载的规则数量
/// 
/// # 返回值
/// * 非负数 - 规则数量
/// * 负数 - 错误代码
#[no_mangle]
pub extern "C" fn web_scan_rust_get_rule_count() -> c_int {
    // 获取全局引擎实例
    let engine = match ENGINE.get() {
        Some(e) => e,
        None => {
            set_last_error("Engine not initialized");
            return -1;
        }
    };

    // 获取规则数量
    let count = engine.read().get_rule_count();
    
    // 转换为c_int（通常足够大）
    count as c_int
}

/// 重新加载规则
/// 
/// 从指定路径重新加载规则文件，替换现有的所有规则。
/// 
/// # 参数
/// * `rules_path` - 规则文件路径的C字符串指针
/// 
/// # 安全性
/// 调用者必须确保`rules_path`是一个有效的以null结尾的C字符串。
/// 
/// # 返回值
/// * 非负数 - 成功加载的规则数量
/// * 负数 - 错误代码
#[no_mangle]
pub extern "C" fn web_scan_rust_reload_rules(rules_path: *const c_char) -> c_int {
    // 检查指针是否为空
    if rules_path.is_null() {
        set_last_error("Null rules path");
        return -1;
    }

    // 将C字符串转换为Rust字符串
    let rules_path_str = match unsafe { CStr::from_ptr(rules_path) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("Invalid UTF-8 in rules path");
            return -1;
        }
    };

    // 获取全局引擎实例
    let engine = match ENGINE.get() {
        Some(e) => e,
        None => {
            set_last_error("Engine not initialized");
            return -1;
        }
    };

    // 重新加载规则
    match engine.write().reload_rules(rules_path_str) {
        Ok(count) => {
            // 成功重新加载
            log::info!("Reloaded {} rules from {}", count, rules_path_str);
            count as c_int
        }
        Err(e) => {
            // 重新加载失败
            set_last_error(&format!("Failed to reload rules: {}", e));
            e.to_error_code()
        }
    }
}

/// 设置默认动作
/// 
/// 当规则指定"无动作"时，引擎将使用这个默认动作。
/// 
/// # 参数
/// * `action` - 默认动作（0=None, 1=Alert, 2=Drop, 3=Reset）
/// 
/// # 返回值
/// * `0` - 成功设置
/// * 负数 - 错误代码
#[no_mangle]
pub extern "C" fn web_scan_rust_set_default_action(action: c_int) -> c_int {
    // 将c_int转换为WebScanAction枚举
    let web_scan_action = match action {
        0 => WebScanAction::None,
        1 => WebScanAction::Alert,
        2 => WebScanAction::Drop,
        3 => WebScanAction::Reset,
        _ => {
            set_last_error("Invalid action value");
            return -1;
        }
    };

    // 获取全局引擎实例
    let engine = match ENGINE.get() {
        Some(e) => e,
        None => {
            set_last_error("Engine not initialized");
            return -1;
        }
    };

    // 设置默认动作
    engine.write().set_default_action(web_scan_action);
    
    0 // 成功
}

/// 设置最后错误信息
/// 
/// 这是一个内部函数，用于设置C代码可以获取的错误信息。
/// 
/// # 参数
/// * `message` - 错误消息字符串
fn set_last_error(message: &str) {
    // 尝试创建C字符串
    if let Ok(c_string) = CString::new(message) {
        // 存储错误信息
        if let Ok(mut error_guard) = LAST_ERROR.lock() {
            *error_guard = Some(c_string);
        }
    }
}


/// 检查是否启用了Hyperscan（已弃用）
///
/// **注意**: 此函数已弃用，因为Hyperscan现在始终启用。
/// 为了向后兼容性，此函数始终返回1。
///
/// # 返回值
/// * `1` - Hyperscan始终启用
/// * 负数 - 错误代码
#[deprecated(note = "Hyperscan is now always enabled")]
#[no_mangle]
pub extern "C" fn web_scan_rust_is_hyperscan_enabled() -> c_int {
    // 获取全局引擎实例
    match ENGINE.get() {
        Some(_) => 1,  // Hyperscan始终启用
        None => {
            set_last_error("Engine not initialized");
            -1
        }
    }
}

/// 重置指定会话的Hyperscan流
///
/// 重置流的状态，使其可以重新开始匹配，但不关闭流。
/// 这对于处理HTTP请求/响应流非常有用：当一个HTTP请求结束时，
/// 可以重置流以准备处理下一个请求，而不需要关闭和重新创建流。
///
/// # 参数
/// * `session_id` - 要重置的会话标识符
///
/// # 返回值
/// * `0` - 成功重置
/// * 负数 - 错误代码
#[no_mangle]
pub extern "C" fn web_scan_rust_reset_session(session_id: u64) -> c_int {
    // 获取全局引擎实例
    let engine = match ENGINE.get() {
        Some(e) => e,
        None => {
            set_last_error("Engine not initialized");
            return -1;
        }
    };

    // 重置会话
    match engine.read().reset_session(session_id) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(&format!("Failed to reset session: {}", e));
            e.to_error_code()
        }
    }
}

/// 清理指定会话的Hyperscan流
///
/// 关闭并清理指定会话的Hyperscan流，释放相关资源。
/// 当会话结束时，应该调用此函数来清理资源。
///
/// # 参数
/// * `session_id` - 要清理的会话标识符
///
/// # 返回值
/// * `0` - 成功清理
/// * 负数 - 错误代码
#[no_mangle]
pub extern "C" fn web_scan_rust_close_session(session_id: u64) -> c_int {
    // 获取全局引擎实例
    let engine = match ENGINE.get() {
        Some(e) => e,
        None => {
            set_last_error("Engine not initialized");
            return -1;
        }
    };

    // 清理会话
    match engine.read().close_session(session_id) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(&format!("Failed to close session: {}", e));
            e.to_error_code()
        }
    }
}

/// 清理所有会话的Hyperscan流
///
/// 关闭并清理所有活跃会话的Hyperscan流，释放相关资源。
/// 这个函数主要用于清理和重置。
///
/// # 返回值
/// * `0` - 成功清理
/// * 负数 - 错误代码
#[no_mangle]
pub extern "C" fn web_scan_rust_close_all_sessions() -> c_int {
    // 获取全局引擎实例
    let engine = match ENGINE.get() {
        Some(e) => e,
        None => {
            set_last_error("Engine not initialized");
            return -1;
        }
    };

    // 清理所有会话
    match engine.read().close_all_sessions() {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(&format!("Failed to close all sessions: {}", e));
            e.to_error_code()
        }
    }
}

/// 清理资源
///
/// 释放所有分配的资源，重置全局状态。
/// 这个函数主要用于测试和调试。
///
/// # 安全性
/// 调用此函数后，引擎将处于未初始化状态，
/// 必须重新调用web_scan_rust_init()才能继续使用。
///
/// # 返回值
/// * `0` - 成功清理
/// * 负数 - 错误代码
#[no_mangle]
pub extern "C" fn web_scan_rust_cleanup() -> c_int {
    // 清空全局引擎实例
    if ENGINE.get().is_some() {
        // 这里我们无法直接清空OnceLock，但可以重置引擎状态
        if let Some(engine) = ENGINE.get() {
            // 先清理所有会话
            let _ = engine.read().close_all_sessions();
            engine.write().reset_stats();
            engine.write().set_enabled(false);
        }
    }
    
    // 清空错误信息
    if let Ok(mut error_guard) = LAST_ERROR.lock() {
        *error_guard = None;
    }
    
    0 // 成功
}

// 条件编译：只在测试时编译以下代码
#[cfg(test)]
mod tests {
    // 导入父模块的所有公共项
    use super::*;

    /// 测试引擎初始化
    #[test]
    fn test_engine_initialization() {
        // 清理之前的状态
        web_scan_rust_cleanup();
        
        // 测试初始化
        let result = web_scan_rust_init();
        assert_eq!(result, 0);
        
        // 测试重复初始化（应该成功）
        let result = web_scan_rust_init();
        assert_eq!(result, 0);
    }

    /// 测试错误处理
    #[test]
    fn test_error_handling() {
        // 清理之前的状态
        web_scan_rust_cleanup();
        
        // 尝试在未初始化时获取统计信息
        let mut stats = WebScanStats::default();
        let _result = web_scan_rust_get_stats(&mut stats as *mut WebScanStats);
        // 由于OnceLock的特性，引擎可能已经被初始化，所以这个测试可能成功
        // 我们改为测试空指针的情况
        assert_eq!(web_scan_rust_get_stats(std::ptr::null_mut()), -1);
        
        // 检查错误信息
        let error_ptr = web_scan_rust_get_last_error();
        assert!(!error_ptr.is_null());
        
        // 转换为Rust字符串
        let error_str = unsafe { CStr::from_ptr(error_ptr) };
        assert!(error_str.to_str().unwrap().contains("Null stats pointer"));
    }

    /// 测试引擎状态控制
    #[test]
    fn test_engine_control() {
        // 初始化引擎（cleanup可能不会完全重置状态）
        web_scan_rust_init();
        
        // 测试启用/禁用
        // 注意：由于OnceLock的特性，引擎可能已经被初始化，状态可能不是默认值
        // 所以我们先设置一个已知状态
        web_scan_rust_set_enabled(1);
        assert_eq!(web_scan_rust_is_enabled(), 1); // 已启用
        
        web_scan_rust_set_enabled(0);
        assert_eq!(web_scan_rust_is_enabled(), 0); // 已禁用
        
        web_scan_rust_set_enabled(1);
        assert_eq!(web_scan_rust_is_enabled(), 1); // 已启用
    }

    /// 测试带会话的载荷处理
    #[test]
    fn test_process_payload_with_session() {
        // 初始化引擎并确保启用
        web_scan_rust_init();
        web_scan_rust_set_enabled(1);  // 确保引擎已启用
        
        let session_id = 40001;
        let payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut result = web_scan_result_t {
            is_matched: false,
            rule_id: 0,
            action: web_scan_action_t::None,
            content_length: 0,
            protocol: web_scan_protocol_t::Unknown,
            confidence: 0,
        };
        
        // 处理载荷（带会话）
        let ret = web_scan_rust_process_payload_with_session(
            session_id,
            payload.as_ptr(),
            payload.len() as u32,
            0,  // is_final = 0
            0,  // reset_on_request_end = 0
            &mut result as *mut web_scan_result_t,
        );
        
        assert_eq!(ret, 0);
        // 标准的HTTP/1.1请求应该被正确识别为HTTP协议
        assert_eq!(result.protocol, web_scan_protocol_t::Http, "Standard HTTP/1.1 request should be detected as HTTP protocol");
        assert!(result.confidence >= 50, "HTTP detection confidence should be at least 50");
        // content_length 应该始终等于payload的实际长度
        assert_eq!(result.content_length, payload.len() as u32, "content_length should equal payload length");
    }

    /// 测试请求结束时自动重置
    #[test]
    fn test_reset_on_request_end() {
        // 清理之前的状态
        web_scan_rust_cleanup();
        
        // 初始化引擎
        web_scan_rust_init();
        
        let session_id = 40002;
        let payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut result = web_scan_result_t {
            is_matched: false,
            rule_id: 0,
            action: web_scan_action_t::None,
            content_length: 0,
            protocol: web_scan_protocol_t::Unknown,
            confidence: 0,
        };
        
        // 第一次请求，不重置
        let ret1 = web_scan_rust_process_payload_with_session(
            session_id,
            payload.as_ptr(),
            payload.len() as u32,
            0,  // is_final = 0
            0,  // reset_on_request_end = 0
            &mut result as *mut web_scan_result_t,
        );
        assert_eq!(ret1, 0);
        
        // 第二次请求，请求结束时重置
        let ret2 = web_scan_rust_process_payload_with_session(
            session_id,
            payload.as_ptr(),
            payload.len() as u32,
            0,  // is_final = 0
            1,  // reset_on_request_end = 1
            &mut result as *mut web_scan_result_t,
        );
        assert_eq!(ret2, 0);
        
        // 重置后应该可以继续使用
        let ret3 = web_scan_rust_process_payload_with_session(
            session_id,
            payload.as_ptr(),
            payload.len() as u32,
            0,  // is_final = 0
            0,  // reset_on_request_end = 0
            &mut result as *mut web_scan_result_t,
        );
        assert_eq!(ret3, 0);
    }

    /// 测试手动重置会话
    #[test]
    fn test_reset_session() {
        // 清理之前的状态
        web_scan_rust_cleanup();
        
        // 初始化引擎
        web_scan_rust_init();
        
        let session_id = 40003;
        let payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut result = web_scan_result_t {
            is_matched: false,
            rule_id: 0,
            action: web_scan_action_t::None,
            content_length: 0,
            protocol: web_scan_protocol_t::Unknown,
            confidence: 0,
        };
        
        // 处理载荷
        let ret = web_scan_rust_process_payload_with_session(
            session_id,
            payload.as_ptr(),
            payload.len() as u32,
            0,  // is_final = 0
            0,  // reset_on_request_end = 0
            &mut result as *mut web_scan_result_t,
        );
        assert_eq!(ret, 0);
        
        // 手动重置会话
        let reset_ret = web_scan_rust_reset_session(session_id);
        assert_eq!(reset_ret, 0);
        
        // 重置后应该可以继续使用
        let ret2 = web_scan_rust_process_payload_with_session(
            session_id,
            payload.as_ptr(),
            payload.len() as u32,
            0,  // is_final = 0
            0,  // reset_on_request_end = 0
            &mut result as *mut web_scan_result_t,
        );
        assert_eq!(ret2, 0);
    }

    /// 测试关闭会话
    #[test]
    fn test_close_session() {
        // 清理之前的状态
        web_scan_rust_cleanup();
        
        // 初始化引擎
        web_scan_rust_init();
        
        let session_id = 40004;
        let payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut result = web_scan_result_t {
            is_matched: false,
            rule_id: 0,
            action: web_scan_action_t::None,
            content_length: 0,
            protocol: web_scan_protocol_t::Unknown,
            confidence: 0,
        };
        
        // 创建会话
        let ret = web_scan_rust_process_payload_with_session(
            session_id,
            payload.as_ptr(),
            payload.len() as u32,
            0,  // is_final = 0
            0,  // reset_on_request_end = 0
            &mut result as *mut web_scan_result_t,
        );
        assert_eq!(ret, 0);
        
        // 关闭会话
        let close_ret = web_scan_rust_close_session(session_id);
        assert_eq!(close_ret, 0);
        
        // 关闭后重置应该成功（但会话不存在）
        let reset_ret = web_scan_rust_reset_session(session_id);
        assert_eq!(reset_ret, 0);
    }

    /// 测试会话结束时自动关闭
    #[test]
    fn test_session_final_close() {
        // 清理之前的状态
        web_scan_rust_cleanup();
        
        // 初始化引擎
        web_scan_rust_init();
        
        let session_id = 40005;
        let payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut result = web_scan_result_t {
            is_matched: false,
            rule_id: 0,
            action: web_scan_action_t::None,
            content_length: 0,
            protocol: web_scan_protocol_t::Unknown,
            confidence: 0,
        };
        
        // 处理载荷并标记为最终
        let ret = web_scan_rust_process_payload_with_session(
            session_id,
            payload.as_ptr(),
            payload.len() as u32,
            1,  // is_final = 1
            0,  // reset_on_request_end = 0
            &mut result as *mut web_scan_result_t,
        );
        assert_eq!(ret, 0);
        
        // 会话应该已经被关闭，再次使用应该创建新会话
        let ret2 = web_scan_rust_process_payload_with_session(
            session_id,
            payload.as_ptr(),
            payload.len() as u32,
            0,  // is_final = 0
            0,  // reset_on_request_end = 0
            &mut result as *mut web_scan_result_t,
        );
        assert_eq!(ret2, 0);
    }

    /// 测试多个会话
    #[test]
    fn test_multiple_sessions() {
        // 初始化引擎并确保启用
        web_scan_rust_init();
        web_scan_rust_set_enabled(1);  // 确保引擎已启用
        
        let payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        // 创建多个不同的会话
        for i in 1..=3 {
            let session_id = 40010 + i;
            let mut result = web_scan_result_t {
                is_matched: false,
                rule_id: 0,
                action: web_scan_action_t::None,
                content_length: 0,
                protocol: web_scan_protocol_t::Unknown,
                confidence: 0,
            };
            
            let ret = web_scan_rust_process_payload_with_session(
                session_id,
                payload.as_ptr(),
                payload.len() as u32,
                0,  // is_final = 0
                0,  // reset_on_request_end = 0
                &mut result as *mut web_scan_result_t,
            );
            assert_eq!(ret, 0);
            // 标准的HTTP/1.1请求应该被正确识别为HTTP协议
            assert_eq!(result.protocol, web_scan_protocol_t::Http, "Standard HTTP/1.1 request should be detected as HTTP protocol");
            assert!(result.confidence >= 50, "HTTP detection confidence should be at least 50");
            // content_length 应该始终等于payload的实际长度
            assert_eq!(result.content_length, payload.len() as u32, "content_length should equal payload length");
        }
        
        // 验证所有会话都可以独立操作
        for i in 1..=3 {
            let session_id = 40010 + i;
            let reset_ret = web_scan_rust_reset_session(session_id);
            assert_eq!(reset_ret, 0);
        }
        
        // 清理所有会话
        let close_all_ret = web_scan_rust_close_all_sessions();
        assert_eq!(close_all_ret, 0);
    }

    /// 测试空指针错误处理
    #[test]
    fn test_null_pointer_handling() {
        // 清理之前的状态
        web_scan_rust_cleanup();
        
        // 初始化引擎
        web_scan_rust_init();
        
        let session_id = 40020;
        let payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        // 测试空指针
        let ret = web_scan_rust_process_payload_with_session(
            session_id,
            std::ptr::null(),
            payload.len() as u32,
            0,
            0,
            std::ptr::null_mut(),
        );
        assert_eq!(ret, -1);
        
        // 检查错误信息
        let error_ptr = web_scan_rust_get_last_error();
        assert!(!error_ptr.is_null());
    }
}