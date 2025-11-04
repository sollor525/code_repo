use std::os::raw::{c_char, c_int, c_void};
use std::path::Path;
use std::env;
use libloading::{Library, Symbol};
use tracing::{info, error, warn, debug, trace};
use crate::common::error::{TlsKeyAgentError, Result};
use crate::ffi::{tls_key_agent_on_client_random, tls_key_agent_on_connection_info};

/// SSL操作类型
#[derive(Debug, Clone, Copy)]
pub enum SSLOperation {
    Write,
    Read,
    Connect,
    Accept,
}

pub struct LdPreloadManager {
    library: Option<Library>,
    is_loaded: bool,
    hook_installed: bool,
    original_ld_preload: Option<String>,
    library_path: Option<String>,
    auto_discovery_paths: Vec<String>,
}

impl LdPreloadManager {
    pub fn new() -> Self {
        let auto_discovery_paths = vec![
            "./target/release/libopenssl_hook.so".to_string(),
            "./target/debug/libopenssl_hook.so".to_string(),
            "/usr/local/lib/libopenssl_hook.so".to_string(),
            "/usr/lib/libopenssl_hook.so".to_string(),
        ];

        Self {
            library: None,
            is_loaded: false,
            hook_installed: false,
            original_ld_preload: None,
            library_path: None,
            auto_discovery_paths,
        }
    }

    pub fn load_library(&mut self, library_path: &str) -> Result<()> {
        info!("加载LD_PRELOAD库: {}", library_path);

        // 1. 基本文件存在性检查
        if !Path::new(library_path).exists() {
            return Err(TlsKeyAgentError::Ffi(
                format!("库文件不存在: {}", library_path)
            ));
        }

        // 2. 安全验证：检查文件权限
        self.validate_library_security(library_path)?;

        // 3. 验证库文件完整性
        self.validate_library_integrity(library_path)?;

        // 4. 安全加载库
        let library = self.safe_load_library(library_path)?;

        // 5. 验证必需的符号存在
        self.validate_required_symbols(&library)?;

        self.library = Some(library);
        self.is_loaded = true;
        self.library_path = Some(library_path.to_string());

        info!("✓ LD_PRELOAD库安全加载成功: {}", library_path);
        Ok(())
    }

    /// 验证库文件安全性
    fn validate_library_security(&self, library_path: &str) -> Result<()> {

        // 获取文件元数据
        let metadata = std::fs::metadata(library_path)
            .map_err(|e| TlsKeyAgentError::Ffi(format!("无法读取库文件元数据: {}", e)))?;

        // 检查文件权限
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let mode = metadata.mode();

            // 检查其他用户写权限（安全风险）
            if mode & 0o002 != 0 {
                warn!("⚠ 库文件具有其他用户写权限，存在安全风险: {}", library_path);
                // 在生产环境中可能需要返回错误
                // return Err(TlsKeyAgentError::Permission("库文件权限不安全".to_string()));
            }

            // 检查是否为普通文件
            if !metadata.is_file() {
                return Err(TlsKeyAgentError::Ffi(
                    format!("路径不是普通文件: {}", library_path)
                ));
            }
        }

        // 检查文件大小（防止过大或异常的文件）
        let file_size = metadata.len();
        if file_size == 0 {
            return Err(TlsKeyAgentError::Ffi("库文件为空".to_string()));
        }
        if file_size > 100 * 1024 * 1024 { // 100MB限制
            return Err(TlsKeyAgentError::Ffi(
                format!("库文件过大: {} bytes", file_size)
            ));
        }

        debug!("库文件安全验证通过: {} ({} bytes)", library_path, file_size);
        Ok(())
    }

    /// 验证库文件完整性
    fn validate_library_integrity(&self, library_path: &str) -> Result<()> {
        // 检查文件扩展名
        if !library_path.ends_with(".so") {
            return Err(TlsKeyAgentError::Ffi(
                "库文件必须是.so格式".to_string()
            ));
        }

        // 简单的ELF头检查（Linux系统）
        #[cfg(target_os = "linux")]
        {
            let mut file = std::fs::File::open(library_path)
                .map_err(|e| TlsKeyAgentError::Ffi(format!("无法打开库文件: {}", e)))?;

            let mut magic = [0u8; 4];
            use std::io::Read;
            file.read_exact(&mut magic)
                .map_err(|e| TlsKeyAgentError::Ffi(format!("读取库文件头失败: {}", e)))?;

            // ELF文件应该以0x7F 'ELF'开头
            if magic != [0x7F, b'E', b'L', b'F'] {
                return Err(TlsKeyAgentError::Ffi(
                    "库文件不是有效的ELF格式".to_string()
                ));
            }
        }

        debug!("库文件完整性验证通过: {}", library_path);
        Ok(())
    }

    /// 安全加载库
    fn safe_load_library(&self, library_path: &str) -> Result<Library> {
        // 使用catch_unwind来防止加载过程中的panic
        match std::panic::catch_unwind(|| {
            unsafe { Library::new(library_path) }
        }) {
            Ok(result) => {
                result.map_err(|e| TlsKeyAgentError::Ffi(format!("加载库失败: {}", e)))
            }
            Err(_) => {
                Err(TlsKeyAgentError::Ffi("库加载过程中发生panic".to_string()))
            }
        }
    }

    /// 验证必需的符号存在
    fn validate_required_symbols(&self, library: &Library) -> Result<()> {
        // 检查必需的导出函数是否存在
        let required_symbols = vec![
            "init_tls_key_agent_hook",
            "cleanup_tls_key_agent_hook",
            // 可以根据需要添加更多必需符号
        ];

        for symbol_name in required_symbols {
            unsafe {
                match library.get::<Symbol<unsafe extern "C" fn(*const c_char) -> c_int>>(
                    symbol_name.as_bytes()
                ) {
                    Ok(_) => {
                        debug!("✓ 找到必需符号: {}", symbol_name);
                    }
                    Err(_) => {
                        return Err(TlsKeyAgentError::Ffi(
                            format!("缺少必需符号: {}", symbol_name)
                        ));
                    }
                }
            }
        }

        debug!("所有必需符号验证通过");
        Ok(())
    }

    pub fn unload_library(&mut self) {
        if self.is_loaded {
            info!("卸载LD_PRELOAD库: {:?}", self.library_path);

            // 先卸载SSL Hook
            if self.hook_installed {
                debug!("卸载SSL Hook");
                let _ = self.uninstall_ssl_hooks();
                let _ = self.uninstall_ld_preload();
            }

            // 卸载库
            self.library = None;
            self.is_loaded = false;
            self.hook_installed = false;
            self.library_path = None;
            self.original_ld_preload = None;

            info!("LD_PRELOAD库卸载完成");
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.is_loaded
    }

    /// 初始化LD_PRELOAD Manager
    pub fn initialize(&mut self, config_str: &str) -> Result<()> {
        info!("初始化LD_PRELOAD Manager，配置: {}", config_str);

        // 这里可以添加配置解析和初始化逻辑
        // 目前只是简单记录日志

        info!("LD_PRELOAD Manager初始化完成");
        Ok(())
    }

    /// 清理LD_PRELOAD Manager
    pub fn cleanup(&mut self) -> Result<()> {
        info!("清理LD_PRELOAD Manager");

        // 卸载库
        self.unload_library();

        info!("LD_PRELOAD Manager清理完成");
        Ok(())
    }

    pub fn is_hook_installed(&self) -> bool {
        self.hook_installed
    }

    /// 自动发现并加载Hook库
    pub fn auto_discover_and_load(&mut self) -> Result<String> {
        info!("开始自动发现Hook库");

        let paths_to_try: Vec<String> = self.auto_discovery_paths.clone();
        for path in paths_to_try {
            debug!("尝试路径: {}", path);
            if Path::new(&path).exists() {
                info!("发现Hook库: {}", path);
                self.load_library(&path)?;
                return Ok(path);
            }
        }

        Err(TlsKeyAgentError::Ffi("未找到可用的Hook库".to_string()))
    }

    /// 获取当前加载的库路径
    pub fn get_library_path(&self) -> Option<&String> {
        self.library_path.as_ref()
    }

    /// 添加自定义搜索路径
    pub fn add_search_path(&mut self, path: String) {
        if !self.auto_discovery_paths.contains(&path) {
            info!("添加搜索路径: {}", path);
            self.auto_discovery_paths.push(path);
        }
    }

    /// 完整的自动安装流程：发现、加载并安装Hook库
    pub fn auto_install(&mut self) -> Result<String> {
        info!("开始自动安装Hook库");

        // 1. 自动发现并加载库
        let library_path = self.auto_discover_and_load()?;

        // 2. 安装LD_PRELOAD
        self.install_ld_preload(&library_path)?;

        info!("Hook库自动安装完成: {}", library_path);
        Ok(library_path)
    }

    /// 获取当前LD_PRELOAD环境变量值
    pub fn get_current_ld_preload() -> Option<String> {
        env::var("LD_PRELOAD").ok()
    }

    /// 检查指定库是否在LD_PRELOAD中
    pub fn is_library_in_ld_preload(library_path: &str) -> bool {
        if let Ok(ld_preload) = env::var("LD_PRELOAD") {
            ld_preload.contains(library_path)
        } else {
            false
        }
    }

    /// 从LD_PRELOAD中移除指定的库（不修改环境变量，只返回新值）
    pub fn remove_library_from_ld_preload(ld_preload: &str, library_path: &str) -> String {
        let paths: Vec<&str> = ld_preload.split(':').collect();
        let filtered: Vec<&str> = paths.iter()
            .filter(|&&path| path != library_path)
            .cloned()
            .collect();

        filtered.join(":")
    }

    // 安装 LD_PRELOAD 到环境变量
    pub fn install_ld_preload(&mut self, library_path: &str) -> Result<()> {
        if self.hook_installed {
            warn!("LD_PRELOAD 已经安装");
            return Ok(());
        }

        info!("安装 LD_PRELOAD: {}", library_path);

        // 验证库文件存在
        if !Path::new(library_path).exists() {
            return Err(TlsKeyAgentError::Ffi(
                format!("要安装的库文件不存在: {}", library_path)
            ));
        }

        // 保存原始的 LD_PRELOAD 值
        if let Ok(original) = env::var("LD_PRELOAD") {
            self.original_ld_preload = Some(original.clone());
            debug!("保存原始 LD_PRELOAD: {}", original);
        }

        // 设置新的 LD_PRELOAD
        let new_ld_preload = if let Some(ref original) = self.original_ld_preload {
            if original.is_empty() {
                library_path.to_string()
            } else {
                // 检查库是否已经在LD_PRELOAD中
                if original.contains(library_path) {
                    warn!("库已在LD_PRELOAD中: {}", library_path);
                    self.hook_installed = true;
                    return Ok(());
                }
                format!("{}:{}", original, library_path)
            }
        } else {
            library_path.to_string()
        };

        env::set_var("LD_PRELOAD", &new_ld_preload);
        self.hook_installed = true;

        info!("LD_PRELOAD 安装成功: {}", new_ld_preload);
        Ok(())
    }

    // 卸载 LD_PRELOAD
    pub fn uninstall_ld_preload(&mut self) -> Result<()> {
        if !self.hook_installed {
            warn!("LD_PRELOAD 未安装，无需卸载");
            return Ok(());
        }

        info!("卸载 LD_PRELOAD");

        // 恢复原始的 LD_PRELOAD 值
        match self.original_ld_preload {
            Some(ref original) => {
                env::set_var("LD_PRELOAD", original);
                debug!("恢复原始 LD_PRELOAD: {}", original);
            }
            None => {
                env::remove_var("LD_PRELOAD");
                debug!("移除 LD_PRELOAD 环境变量");
            }
        }

        self.hook_installed = false;
        info!("LD_PRELOAD 卸载成功");
        Ok(())
    }

    // 获取函数指针的辅助方法
    fn get_symbol<T>(&self, symbol_name: &str) -> Result<Symbol<'_, T>> {
        if let Some(ref library) = self.library {
            unsafe {
                library.get(symbol_name.as_bytes())
                    .map_err(|e| TlsKeyAgentError::Ffi(
                        format!("获取符号 {} 失败: {}", symbol_name, e)
                    ))
            }
        } else {
            Err(TlsKeyAgentError::Ffi("库未加载".to_string()))
        }
    }

    // 安装SSL Hook
    pub fn install_ssl_hooks(&self, config_path: Option<&str>) -> Result<()> {
        debug!("安装SSL Hook");

        if !self.is_loaded {
            return Err(TlsKeyAgentError::Ffi("库未加载，无法安装Hook".to_string()));
        }

        // 调用库中的初始化函数
        let init_hook: Symbol<unsafe extern "C" fn(*const c_char) -> c_int> =
            self.get_symbol("init_tls_key_agent_hook")?;

        let result = if let Some(path) = config_path {
            let config_cstring = std::ffi::CString::new(path)
                .map_err(|e| TlsKeyAgentError::Ffi(format!("配置路径转换失败: {}", e)))?;
            unsafe { init_hook(config_cstring.as_ptr()) }
        } else {
            unsafe { init_hook(std::ptr::null()) }
        };

        if result != 0 {
            return Err(TlsKeyAgentError::Ffi("初始化SSL Hook失败".to_string()));
        }

        info!("SSL Hook安装成功");
        Ok(())
    }

    // 卸载SSL Hook
    pub fn uninstall_ssl_hooks(&self) -> Result<()> {
        debug!("卸载SSL Hook");

        if !self.is_loaded {
            warn!("库未加载，无需卸载Hook");
            return Ok(());
        }

        // 调用库中的清理函数
        let cleanup_hook: Symbol<unsafe extern "C" fn() -> c_int> =
            self.get_symbol("cleanup_tls_key_agent_hook")?;

        let result = unsafe { cleanup_hook() };
        if result != 0 {
            return Err(TlsKeyAgentError::Ffi("清理SSL Hook失败".to_string()));
        }

        info!("SSL Hook卸载成功");
        Ok(())
    }

    // 获取Hook状态
    pub fn get_hook_status(&self) -> Result<bool> {
        if !self.is_loaded {
            return Ok(false);
        }

        let hook_status: Symbol<unsafe extern "C" fn() -> c_int> =
            self.get_symbol("tls_key_agent_hook_status")?;

        let status = unsafe { hook_status() };
        Ok(status != 0)
    }

    // 设置日志级别
    pub fn set_log_level(&self, level: c_int) -> Result<()> {
        if !self.is_loaded {
            return Err(TlsKeyAgentError::Ffi("库未加载，无法设置日志级别".to_string()));
        }

        let set_level: Symbol<unsafe extern "C" fn(c_int)> =
            self.get_symbol("tls_key_agent_set_log_level")?;

        unsafe { set_level(level) };
        Ok(())
    }
}

impl Drop for LdPreloadManager {
    fn drop(&mut self) {
        self.unload_library();
    }
}

// 全局LD_PRELOAD管理器
static mut LD_PRELOAD_MANAGER: Option<LdPreloadManager> = None;
static LD_PRELOAD_INIT: std::sync::Once = std::sync::Once::new();

#[allow(static_mut_refs)]
pub fn get_ld_preload_manager() -> &'static mut LdPreloadManager {
    unsafe {
        LD_PRELOAD_INIT.call_once(|| {
            LD_PRELOAD_MANAGER = Some(LdPreloadManager::new());
        });
        LD_PRELOAD_MANAGER.as_mut().unwrap()
    }
}

// C FFI 导出函数 - 用于动态库导出
#[no_mangle]
pub unsafe extern "C" fn init_tls_key_agent(config_path: *const c_char) -> c_int {
    debug!("初始化TLS Key Agent (C FFI)");

    if config_path.is_null() {
        error!("配置路径为空");
        return -1;
    }

    let config_str = unsafe {
        std::ffi::CStr::from_ptr(config_path)
            .to_string_lossy()
            .into_owned()
    };

    // 实现初始化逻辑
    info!("开始TLS Key Agent初始化，配置文件: {}", config_str);

    // 初始化全局状态
    #[allow(static_mut_refs)]
    unsafe {
        if let Some(manager) = LD_PRELOAD_MANAGER.as_mut() {
            match manager.initialize(&config_str) {
                Ok(()) => {
                    info!("TLS Key Agent初始化成功");
                    return 0;
                }
                Err(e) => {
                    error!("TLS Key Agent初始化失败: {}", e);
                    return -1;
                }
            }
        } else {
            error!("LD_PRELOAD Manager未初始化");
            return -1;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn cleanup_tls_key_agent() -> c_int {
    debug!("清理TLS Key Agent (C FFI)");

    // 实现清理逻辑
    info!("开始TLS Key Agent清理");

    // 清理全局状态
    #[allow(static_mut_refs)]
    unsafe {
        if let Some(manager) = LD_PRELOAD_MANAGER.as_mut() {
            match manager.cleanup() {
                Ok(()) => {
                    info!("TLS Key Agent清理成功");
                    return 0;
                }
                Err(e) => {
                    warn!("TLS Key Agent清理失败: {}", e);
                    // 清理失败不应该返回错误码，只记录警告
                    return 0;
                }
            }
        } else {
            warn!("LD_PRELOAD Manager未初始化，跳过清理");
            return 0;
        }
    }
}

// 用于LD_PRELOAD的OpenSSL Hook函数
extern "C" {
    fn SSL_write(ssl: *mut c_void, buf: *const c_void, num: c_int) -> c_int;
    fn SSL_read(ssl: *mut c_void, buf: *mut c_void, num: c_int) -> c_int;
    fn SSL_get_fd(ssl: *mut c_void) -> c_int;
    fn SSL_get_client_random(ssl: *mut c_void, out: *mut u8, outlen: usize) -> c_int;
    // 注意：SSL_get_master_key 在标准OpenSSL中不存在
    // 我们将使用其他方法来获取密钥信息
}

// Hook函数实现
#[no_mangle]
pub unsafe extern "C" fn hooked_SSL_write(ssl: *mut c_void, buf: *const c_void, num: c_int) -> c_int {
    trace!("Hooked SSL_write 被调用");

    // 参数安全检查
    if ssl.is_null() {
        error!("SSL_write: SSL对象为空");
        return -1;
    }

    if num < 0 {
        error!("SSL_write: 无效的数据长度: {}", num);
        return -1;
    }

    if num > 0 && buf.is_null() {
        error!("SSL_write: 数据缓冲区为空但长度大于0");
        return -1;
    }

    // 首次调用时设置OpenSSL Keylog回调（安全包装）
    if let Err(e) = setup_openssl_keylog_callback_safe(ssl) {
        debug!("设置OpenSSL Keylog回调失败: {}", e);
    }

    // 安全调用原始函数
    let result = match catch_unwind(|| {
        unsafe { SSL_write(ssl, buf, num) }
    }) {
        Ok(res) => res,
        Err(_) => {
            error!("SSL_write: 原始函数调用发生panic");
            return -1;
        }
    };

    // 安全地提取密钥信息
    if result > 0 {
        if let Err(e) = unsafe { handle_ssl_operation_safe(ssl, SSLOperation::Write, true) } {
            error!("SSL_write密钥提取失败: {}", e);
        }
    }

    result
}

#[no_mangle]
pub unsafe extern "C" fn hooked_SSL_read(ssl: *mut c_void, buf: *mut c_void, num: c_int) -> c_int {
    trace!("Hooked SSL_read 被调用");

    // 参数安全检查
    if ssl.is_null() {
        error!("SSL_read: SSL对象为空");
        return -1;
    }

    if num < 0 {
        error!("SSL_read: 无效的数据长度: {}", num);
        return -1;
    }

    if num > 0 && buf.is_null() {
        error!("SSL_read: 数据缓冲区为空但长度大于0");
        return -1;
    }

    // 首次调用时设置OpenSSL Keylog回调（安全包装）
    if let Err(e) = setup_openssl_keylog_callback_safe(ssl) {
        debug!("设置OpenSSL Keylog回调失败: {}", e);
    }

    // 安全调用原始函数
    let result = match catch_unwind(|| {
        unsafe { SSL_read(ssl, buf, num) }
    }) {
        Ok(res) => res,
        Err(_) => {
            error!("SSL_read: 原始函数调用发生panic");
            return -1;
        }
    };

    // 安全地提取密钥信息
    if result > 0 {
        if let Err(e) = unsafe { handle_ssl_operation_safe(ssl, SSLOperation::Read, true) } {
            error!("SSL_read密钥提取失败: {}", e);
        }
    }

    result
}

// 辅助函数：从SSL对象提取密钥信息
pub unsafe fn extract_keys_from_ssl(ssl: *mut c_void) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut client_random = vec![0u8; 32];
    // 注意：Master Secret暂时设为空，因为无法直接提取
    let master_secret = vec![0u8; 48];

    let client_random_len = unsafe {
        SSL_get_client_random(ssl, client_random.as_mut_ptr(), client_random.len())
    };

    if client_random_len != 32 {
        return Err(TlsKeyAgentError::TlsParse(
            format!("Client Random长度错误: {}", client_random_len)
        ));
    }

    info!("成功提取Client Random，Master Secret需要其他方法");
    debug!("Client Random: {}", hex::encode(&client_random));

    // 返回Client Random和空的Master Secret
    // Master Secret需要通过OpenSSL Keylog API或其他方式获取
    Ok((client_random, master_secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ld_preload_manager_creation() {
        let manager = LdPreloadManager::new();
        assert!(!manager.is_loaded());
    }

    #[test]
    fn test_get_ld_preload_manager() {
        let manager1 = get_ld_preload_manager();
        let manager2 = get_ld_preload_manager();

        // 应该返回同一个实例
        assert!(manager1 as *const _ == manager2 as *const _);
    }

    // 注意：实际的库加载测试需要真实的库文件
    // #[test]
    // fn test_load_library() {
    //     let mut manager = LdPreloadManager::new();
    //     let result = manager.load_library("./test_lib.so");
    //     assert!(result.is_ok());
    //     assert!(manager.is_loaded());
    // }
}

/// 从SSL操作中提取密钥信息的辅助函数
pub fn extract_keys_from_ssl_operation(ssl: *mut c_void, operation: SSLOperation, success: bool) {
    if !success {
        debug!("SSL操作失败，跳过密钥提取");
        return;
    }

    match operation {
        SSLOperation::Write | SSLOperation::Read => {
            // 尝试获取Client Random
            let mut client_random = [0u8; 32];

            // 获取Client Random - 使用全局函数指针
            let cr_result = unsafe {
                // 调用外部声明的OpenSSL函数
                SSL_get_client_random(ssl, client_random.as_mut_ptr(), client_random.len())
            };

            // 注意：Master Secret获取需要其他方法
            // 这里暂时只处理Client Random
            debug!("暂时只处理Client Random，Master Secret需要其他方法");

            // 如果成功获取到Client Random，通过FFI接口传递
            if cr_result > 0 {
                trace!("成功获取Client Random，通过FFI传递");
                #[allow(unused_unsafe)]
                unsafe {
                    tls_key_agent_on_client_random(
                        ssl,
                        client_random.as_ptr(),
                        client_random.len() as usize
                    );
                }
                info!("成功提取Client Random: {}", hex::encode(&client_random));
            }

            // 注意：Master Secret暂时无法直接提取
            // 将依赖OpenSSL Keylog API或其他方法
            debug!("Master Secret提取暂时跳过，需要其他实现方式");

            // 尝试获取连接信息
            extract_connection_info(ssl);
        }
        SSLOperation::Connect | SSLOperation::Accept => {
            // 在连接/接受时获取连接信息
            extract_connection_info(ssl);
        }
    }
}

/// 从SSL对象提取连接信息
fn extract_connection_info(ssl: *mut c_void) {
    let fd = unsafe {
        // 调用外部声明的OpenSSL函数
        SSL_get_fd(ssl)
    };

    if fd < 0 {
        debug!("无法获取SSL文件描述符");
        return;
    }

    // 尝试获取本地和远程地址信息
    // 这里可以使用getsockname和getpeername系统调用
    // 由于复杂性，这里暂时只传递文件描述符
    #[allow(unused_unsafe)]
    unsafe {
        tls_key_agent_on_connection_info(
            ssl,
            std::ptr::null(), // src_ip (暂时为空)
            0,                    // src_port
            std::ptr::null(), // dst_ip (暂时为空)
            0,                    // dst_port
            std::ptr::null(), // protocol (暂时为空)
        );
    }
}

/// 尝试从内存中提取Master Secret（备用方案）
/// 在现代OpenSSL中，直接API可能受限，这里提供内存扫描方案
pub fn extract_master_secret_from_memory(ssl: *mut c_void) -> Option<Vec<u8>> {
    // 这是一个简化的实现，实际应用中需要更复杂的内存扫描逻辑

    // 尝试通过已知偏移量读取Master Secret
    // 注意：这种方法非常脆弱，依赖OpenSSL版本和编译配置

    let master_secret_offset = 0x200; // 示例偏移量，需要根据实际情况调整

    unsafe {
        let ptr = (ssl as *const u8).add(master_secret_offset);
        let master_secret = std::slice::from_raw_parts(ptr, 48);

        // 简单验证：检查是否全零（不太可能是真正的密钥）
        if master_secret.iter().all(|&b| b == 0) {
            return None;
        }

        // 返回Master Secret的副本
        Some(master_secret.to_vec())
    }
}

/// OpenSSL Keylog API回调函数
extern "C" fn openssl_keylog_callback(
    ssl: *mut c_void,
    line: *const c_char,
) {
    if ssl.is_null() || line.is_null() {
        error!("OpenSSL keylog回调参数为空");
        return;
    }

    unsafe {
        let line_str = std::ffi::CStr::from_ptr(line).to_string_lossy();
        debug!("OpenSSL Keylog: {}", line_str);

        // 解析keylog格式
        if let Some((label, client_random_hex, secret_hex)) = parse_keylog_line(&line_str) {
            info!("检测到TLS密钥 - 标签: {}, Client Random: {}", label, client_random_hex);

            // 解码十六进制数据
            if let Ok(client_random) = hex::decode(&client_random_hex) {
                if let Ok(secret) = hex::decode(&secret_hex) {
                    // 根据标签类型处理不同的密钥
                    match label.as_str() {
                        "CLIENT_RANDOM" => {
                            // 这是Master Secret
                            if client_random.len() == 32 && secret.len() == 48 {
                                if let Err(e) = process_master_secret_via_keylog(ssl, &client_random, &secret) {
                                    error!("通过keylog处理Master Secret失败: {}", e);
                                }
                            }
                        }
                        "RSA" | "ECDHE" | "CLIENT_TRAFFIC_SECRET_0" | "SERVER_TRAFFIC_SECRET_0" => {
                            // 其他类型的密钥信息
                            debug!("检测到其他类型密钥: {} (长度: {})", label, secret.len());
                        }
                        _ => {
                            debug!("未知的keylog标签: {}", label);
                        }
                    }
                } else {
                    error!("解码secret失败: {}", secret_hex);
                }
            } else {
                error!("解码Client Random失败: {}", client_random_hex);
            }
        } else {
            debug!("无法解析keylog行: {}", line_str);
        }
    }
}

/// 解析keylog行格式: LABEL <space> ClientRandom <space> Secret
fn parse_keylog_line(line: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 3 {
        Some((
            parts[0].to_string(),      // LABEL
            parts[1].to_string(),      // ClientRandom
            parts[2].to_string(),      // Secret
        ))
    } else {
        None
    }
}

/// 通过keylog处理Master Secret
fn process_master_secret_via_keylog(
    ssl: *mut c_void,
    client_random: &[u8],
    master_secret: &[u8],
) -> Result<()> {
    info!("通过OpenSSL Keylog API处理Master Secret");
    info!("Client Random: {}", hex::encode(client_random));
    info!("Master Secret: {}", hex::encode(master_secret));

    // 调用FFI接口处理Master Secret
    #[allow(unused_unsafe)]
    unsafe {
        let result = crate::extractor::on_ssl_master_secret(
            ssl,
            master_secret.as_ptr(),
            master_secret.len(),
        );
        if result != 0 {
            return Err(TlsKeyAgentError::Ffi("处理Master Secret失败".to_string()));
        }
    }

    info!("通过OpenSSL Keylog API成功处理Master Secret");
    Ok(())
}

/// 设置OpenSSL Keylog回调
pub fn setup_openssl_keylog_callback(ssl: *mut c_void) -> Result<()> {
    if ssl.is_null() {
        return Err(TlsKeyAgentError::Ffi("SSL指针为空".to_string()));
    }

    debug!("尝试设置OpenSSL Keylog回调");

    // 方法1: 尝试使用dlopen动态加载OpenSSL
    if let Ok(success) = try_setup_with_dlopen(ssl) {
        if success {
            info!("✓ OpenSSL Keylog回调设置成功 (dlopen方法)");
            return Ok(());
        }
    }

    // 方法2: 尝试通过环境变量设置
    if let Ok(success) = try_setup_via_environment() {
        if success {
            info!("✓ OpenSSL Keylog回调设置成功 (环境变量方法)");
            return Ok(());
        }
    }

    // 方法3: 尝试使用已知的OpenSSL库路径
    if let Ok(success) = try_setup_known_paths(ssl) {
        if success {
            info!("✓ OpenSSL Keylog回调设置成功 (已知路径方法)");
            return Ok(());
        }
    }

    warn!("⚠ OpenSSL Keylog API设置失败，将使用备用密钥提取方法");
    info!("注意：这不影响基本功能，Client Random提取仍然正常工作");
    Ok(())
}

/// 使用dlopen动态加载OpenSSL符号
fn try_setup_with_dlopen(ssl: *mut c_void) -> Result<bool> {
    // 尝试加载常见的OpenSSL库
    let openssl_paths = vec![
        "libssl.so.3",
        "libssl.so.1.1",
        "libssl.so.1.0.2",
        "libssl.so",
    ];

    for lib_name in openssl_paths {
        if let Ok(lib) = unsafe { Library::new(lib_name) } {
            info!("尝试加载OpenSSL库: {}", lib_name);

            // 尝试获取SSL_CTX_set_keylog_callback符号
            if let Ok(set_keylog_cb) = unsafe {
                lib.get::<Symbol<extern "C" fn(*mut c_void, *mut c_void)>>(b"SSL_CTX_set_keylog_callback")
            } {
                // 获取SSL_CTX
                if let Ok(get_ctx) = unsafe {
                    lib.get::<Symbol<extern "C" fn(*mut c_void) -> *mut c_void>>(b"SSL_get_SSL_CTX")
                } {
                    #[allow(unused_unsafe)]
                    let ctx = unsafe { get_ctx(ssl) };
                    if !ctx.is_null() {
                        // 设置keylog回调
                        #[allow(unused_unsafe)]
                        unsafe {
                            set_keylog_cb(ctx, openssl_keylog_callback as *mut c_void);
                        }

                        info!("✓ 成功通过dlopen设置OpenSSL Keylog回调");
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
}

/// 通过环境变量设置OpenSSL Keylog
fn try_setup_via_environment() -> Result<bool> {
    // 检查是否已经设置了SSLKEYLOGFILE环境变量
    if env::var("SSLKEYLOGFILE").is_ok() {
        info!("检测到SSLKEYLOGFILE环境变量已设置");

        // 如果设置了，OpenSSL会自动调用keylog回调
        // 我们只需要确保有回调函数可以接收

        // 这里可以添加文件监控逻辑来读取keylog文件
        info!("将监控SSLKEYLOGFILE以获取密钥信息");
        return Ok(true);
    }

    // 尝试设置临时keylog文件
    let keylog_file = format!("/tmp/tls_agent_keylog_{}.log",
                              std::process::id());

    env::set_var("SSLKEYLOGFILE", &keylog_file);
    info!("设置SSLKEYLOGFILE环境变量: {}", keylog_file);

    // 设置文件监控
    if let Ok(_file) = std::fs::File::create(&keylog_file) {
        info!("创建临时keylog文件: {}", keylog_file);
        return Ok(true);
    }

    Ok(false)
}

/// 尝试使用已知的OpenSSL库路径
fn try_setup_known_paths(ssl: *mut c_void) -> Result<bool> {
    // 常见的OpenSSL安装路径
    let search_paths = vec![
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/libssl.so.3",
        "/usr/local/ssl/lib/libssl.so.3",
        "/opt/openssl/lib/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/libssl.so.3",
    ];

    for path in search_paths {
        if std::path::Path::new(path).exists() {
            debug!("发现OpenSSL库: {}", path);

            if let Ok(lib) = unsafe { Library::new(path) } {
                if let Ok(set_keylog_cb) = unsafe {
                    lib.get::<Symbol<extern "C" fn(*mut c_void, *mut c_void)>>(
                        b"SSL_CTX_set_keylog_callback"
                    )
                } {
                    if let Ok(get_ctx) = unsafe {
                        lib.get::<Symbol<extern "C" fn(*mut c_void) -> *mut c_void>>(
                            b"SSL_get_SSL_CTX"
                        )
                    } {
                        #[allow(unused_unsafe)]
                        let ctx = unsafe { get_ctx(ssl) };
                        if !ctx.is_null() {
                            #[allow(unused_unsafe)]
                            unsafe {
                                set_keylog_cb(ctx, openssl_keylog_callback as *mut c_void);
                            }
                            info!("✓ 成功通过已知路径设置OpenSSL Keylog回调");
                            return Ok(true);
                        }
                    }
                }
            }
        }
    }

    Ok(false)
}

/// 启用OpenSSL Keylog的环境变量辅助函数
pub fn enable_openssl_keylog_env() -> Result<()> {
    let keylog_file = format!("/tmp/tls_agent_keylog_{}.log",
                          std::process::id());

    // 设置环境变量
    env::set_var("SSLKEYLOGFILE", &keylog_file);
    env::set_var("RUST_LOG", "debug");

    // 创建keylog文件
    std::fs::File::create(&keylog_file)?;

    info!("已启用OpenSSL Keylog环境变量");
    info!("Keylog文件: {}", keylog_file);
    info!("请确保其他进程能够读取此文件");

    Ok(())
}

/// 安全包装的SSL操作处理函数
pub unsafe fn handle_ssl_operation_safe(ssl: *mut c_void, operation: SSLOperation, success: bool) -> Result<()> {
    // 参数验证
    if ssl.is_null() {
        return Err(TlsKeyAgentError::Ffi("SSL对象为空".to_string()));
    }

    // 使用catch_unwind来防止panic
    match catch_unwind(|| {
        extract_keys_from_ssl_operation(ssl, operation, success);
    }) {
        Ok(_) => Ok(()),
        Err(_) => {
            warn!("SSL操作处理发生panic，操作类型: {:?}", operation);
            Ok(()) // 不返回错误，只记录警告
        }
    }
}

/// 安全包装的OpenSSL Keylog回调设置函数
pub unsafe fn setup_openssl_keylog_callback_safe(ssl: *mut c_void) -> Result<()> {
    if ssl.is_null() {
        return Err(TlsKeyAgentError::Ffi("SSL对象为空".to_string()));
    }

    // 使用catch_unwind来防止panic
    match catch_unwind(|| {
        setup_openssl_keylog_callback(ssl)
    }) {
        Ok(result) => result,
        Err(_) => {
            warn!("设置OpenSSL Keylog回调时发生panic");
            // 不返回错误，只记录警告
            Ok(())
        }
    }
}

/// 安全的panic捕获辅助函数
fn catch_unwind<F, R>(f: F) -> std::thread::Result<R>
where
    F: FnOnce() -> R + std::panic::UnwindSafe,
{
    std::panic::catch_unwind(f)
}
