//! 许可证和程序激活管理
//!
//! 处理程序过期时间和使用次数限制

use std::time::{SystemTime, UNIX_EPOCH};
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use std::env;
use base64::{Engine as _, engine::general_purpose};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use sha2::{Sha256, Digest};

/// 程序配置
pub struct ProgramConfig {
    /// 过期时间 (2026年5月31日 23:59:59 UTC)
    pub expiration_timestamp: u64,
    /// 激活所需的PCAP生成次数
    pub activation_threshold: u64,
    /// 加密密钥 (派生)
    encryption_key: Key,
    /// 存储文件名 (隐藏)
    storage_file: String,
}

/// 加密的使用数据
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedUsageData {
    /// 加密的计数器数据
    data: String,
    /// 校验和
    checksum: String,
    /// 版本标识
    version: u8,
    /// 混淆时间戳
    obfuscated_time: u64,
    /// 解密后的计数器 (运行时使用)
    #[serde(skip)]
    pub counter: UsageCounter,
}

impl Default for EncryptedUsageData {
    fn default() -> Self {
        Self {
            data: String::new(),
            checksum: String::new(),
            version: 1,
            obfuscated_time: 0,
            counter: UsageCounter::default(),
        }
    }
}

impl Default for ProgramConfig {
    fn default() -> Self {
        // 2026年5月31日 23:59:59 UTC 的时间戳 (1780271999)
        let expiration_timestamp = 1780271999u64;

        // 生成基于硬件信息的加密密钥
        let encryption_key = Self::generate_encryption_key();

        // 生成隐藏的存储文件路径
        let storage_file = Self::get_hidden_storage_path();

        Self {
            expiration_timestamp,
            activation_threshold: 10000, // 正式版本：10000个文件
            encryption_key,
            storage_file,
        }
    }
}

impl ProgramConfig {
    /// 生成基于硬件信息的加密密钥
    fn generate_encryption_key() -> Key {
        // 收集系统信息来生成唯一的密钥
        let mut hasher = Sha256::new();

        // 使用多个系统标识符
        if let Ok(hostname) = env::var("HOSTNAME") {
            hasher.update(hostname.as_bytes());
        } else if let Ok(computername) = env::var("COMPUTERNAME") {
            hasher.update(computername.as_bytes());
        }

        if let Ok(username) = env::var("USER") {
            hasher.update(username.as_bytes());
        } else if let Ok(username) = env::var("USERNAME") {
            hasher.update(username.as_bytes());
        }

        // 添加常量盐值确保唯一性
        hasher.update(b"gen_pcap_license_2025");

        // 使用哈希结果生成密钥
        let hash_result = hasher.finalize();
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&hash_result[..32]);

        *Key::from_slice(&key_bytes)
    }

    /// 获取隐藏的存储文件路径
    fn get_hidden_storage_path() -> String {
        let mut path = env::temp_dir();

        // 生成基于硬件信息的固定文件名
        let mut hasher = Sha256::new();

        if let Ok(hostname) = env::var("HOSTNAME") {
            hasher.update(hostname.as_bytes());
        } else if let Ok(computername) = env::var("COMPUTERNAME") {
            hasher.update(computername.as_bytes());
        }

        if let Ok(username) = env::var("USER") {
            hasher.update(username.as_bytes());
        } else if let Ok(username) = env::var("USERNAME") {
            hasher.update(username.as_bytes());
        }

        hasher.update(b"gen_pcap_license_storage");
        let hash_result = hasher.finalize();

        // 使用哈希的前8个字符作为文件名
        let filename = format!("sys_cache_{:x}.dat", u64::from_be_bytes([
            hash_result[0], hash_result[1], hash_result[2], hash_result[3],
            hash_result[4], hash_result[5], hash_result[6], hash_result[7],
        ]));

        path.push(filename);
        path.to_string_lossy().to_string()
    }
}

/// 使用计数器结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageCounter {
    /// 总生成次数
    pub total_generated: u64,
    /// 唯一PCAP文件集合 (使用简单的哈希集合)
    pub unique_pcaps: std::collections::HashSet<String>,
    /// 最后更新时间
    pub last_updated: u64,
}

impl Default for UsageCounter {
    fn default() -> Self {
        Self {
            total_generated: 0,
            unique_pcaps: std::collections::HashSet::new(),
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// 许可证管理器
pub struct LicenseManager {
    pub config: ProgramConfig,
}

impl LicenseManager {
    pub fn new() -> Self {
        Self {
            config: ProgramConfig::default(),
        }
    }

    pub fn with_config(config: ProgramConfig) -> Self {
        Self { config }
    }

    /// 检查程序是否过期
    pub fn check_expiration(&self) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("无法获取当前时间")?
            .as_secs();

        if current_time >= self.config.expiration_timestamp {
            let expiration_date = std::time::UNIX_EPOCH + std::time::Duration::from_secs(self.config.expiration_timestamp);
            if let Ok(_datetime) = expiration_date.elapsed() {
                return Err(anyhow::anyhow!(
                    "程序已过期！过期时间: 2026年5月31日。请联系开发者获取更新版本。"
                ));
            }
        }

        Ok(())
    }

    /// 加载使用计数器 (加密存储)
    fn load_counter(&self) -> Result<UsageCounter> {
        if Path::new(&self.config.storage_file).exists() {
            let content = fs::read(&self.config.storage_file)
                .context("无法读取存储文件")?;

            // 尝试解密数据
            self.decrypt_usage_data(&content)
                .context("无法解密使用数据")
                .map(|data| data.counter)
        } else {
            Ok(UsageCounter::default())
        }
    }

    /// 保存使用计数器 (加密存储)
    fn save_counter(&self, counter: &UsageCounter) -> Result<()> {
        // 创建加密数据结构
        let encrypted_data = self.encrypt_usage_data(counter)?;

        // 写入加密数据到文件
        fs::write(&self.config.storage_file, encrypted_data)
            .context("无法保存存储文件")?;

        // 设置文件为隐藏 (在支持的系统上)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(&self.config.storage_file) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o600); // 仅所有者可读写
                let _ = fs::set_permissions(&self.config.storage_file, perms);
            }
        }

        Ok(())
    }

    /// 加密使用数据
    fn encrypt_usage_data(&self, counter: &UsageCounter) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.config.encryption_key);

        // 生成随机nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // 序列化计数器数据
        let counter_data = serde_json::to_vec(counter)
            .context("无法序列化计数器")?;

        // 加密数据
        let ciphertext = cipher.encrypt(&nonce, counter_data.as_ref())
            .map_err(|e| anyhow::anyhow!("加密失败: {}", e))?;

        // 创建包含nonce和密文的数据包
        let mut encrypted_data = nonce.to_vec();
        encrypted_data.extend_from_slice(&ciphertext);

        // 创建最终的加密结构
        let data_struct = EncryptedUsageData {
            data: general_purpose::STANDARD.encode(&encrypted_data),
            checksum: self.calculate_checksum(&encrypted_data),
            version: 1,
            obfuscated_time: self.obfuscate_timestamp(),
            counter: counter.clone(),
        };

        // 序列化并返回
        serde_json::to_vec(&data_struct)
            .context("无法序列化加密数据")
    }

    /// 解密使用数据
    fn decrypt_usage_data(&self, encrypted_content: &[u8]) -> Result<EncryptedUsageData> {
        // 解析加密数据结构
        let data_struct: EncryptedUsageData = serde_json::from_slice(encrypted_content)
            .context("无法解析加密数据结构")?;

        // 验证校验和
        let encrypted_data = general_purpose::STANDARD.decode(&data_struct.data)
            .context("无法解码base64数据")?;

        if data_struct.checksum != self.calculate_checksum(&encrypted_data) {
            return Err(anyhow::anyhow!("数据校验失败，可能被篡改"));
        }

        // 验证时间戳 (防止文件被复制到其他地方使用)
        if !self.verify_obfuscated_timestamp(data_struct.obfuscated_time) {
            return Err(anyhow::anyhow!("时间戳验证失败"));
        }

        // 解密数据
        let cipher = ChaCha20Poly1305::new(&self.config.encryption_key);

        if encrypted_data.len() < 12 { // nonce长度为12字节
            return Err(anyhow::anyhow!("加密数据格式错误"));
        }

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let decrypted_data = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("解密失败: {}", e))?;

        // 反序列化计数器
        let counter: UsageCounter = serde_json::from_slice(&decrypted_data)
            .context("无法反序列化计数器")?;

        Ok(EncryptedUsageData {
            data: data_struct.data,
            checksum: data_struct.checksum,
            version: data_struct.version,
            obfuscated_time: data_struct.obfuscated_time,
            counter,
        })
    }

    /// 计算数据校验和
    fn calculate_checksum(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(b"gen_pcap_checksum");
        format!("{:x}", hasher.finalize())
    }

    /// 混淆时间戳
    fn obfuscate_timestamp(&self) -> u64 {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 简单的时间戳混淆
        current_time ^ 0x5A5A5A5A5A5A5A5A
    }

    /// 验证混淆的时间戳
    fn verify_obfuscated_timestamp(&self, obfuscated_time: u64) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expected_time = current_time ^ 0x5A5A5A5A5A5A5A5A;

        // 允许一定的时间差 (30天)
        (expected_time as i64 - obfuscated_time as i64).abs() < 30 * 24 * 3600
    }

    /// 检查程序是否被限制（达到使用阈值）
    pub fn check_activation(&self) -> Result<bool> {
        let counter = self.load_counter()?;
        Ok(counter.unique_pcaps.len() >= self.config.activation_threshold as usize)
    }

    /// 检查程序是否允许使用
    pub fn check_usage_allowed(&self) -> Result<bool> {
        let counter = self.load_counter()?;
        let is_expired = self.check_is_expired()?;
        let is_usage_limit_reached = counter.unique_pcaps.len() >= self.config.activation_threshold as usize;

        // 如果程序已过期或达到使用限制，则不允许使用
        if is_expired || is_usage_limit_reached {
            Ok(false)
        } else {
            Ok(true)
        }
    }

    /// 检查程序是否已过期
    pub fn check_is_expired(&self) -> Result<bool> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("无法获取当前时间")?
            .as_secs();

        Ok(current_time >= self.config.expiration_timestamp)
    }

    /// 记录PCAP生成
    pub fn record_pcap_generation(&self, output_file: &str) -> Result<()> {
        let mut counter = self.load_counter()?;

        // 生成文件标识符 (基于路径和内容哈希)
        let file_id = self.generate_file_id(output_file)?;

        // 更新计数器
        counter.total_generated += 1;
        counter.unique_pcaps.insert(file_id);
        counter.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 保存更新后的计数器
        self.save_counter(&counter)?;

        Ok(())
    }

    /// 生成文件唯一标识符
    fn generate_file_id(&self, file_path: &str) -> Result<String> {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        // 简单的哈希：基于文件路径、大小和当前时间戳
        let mut hasher = DefaultHasher::new();

        // 路径哈希
        file_path.hash(&mut hasher);

        // 文件大小哈希 (如果文件存在)
        if Path::new(file_path).exists() {
            if let Ok(metadata) = fs::metadata(file_path) {
                metadata.len().hash(&mut hasher);
            }
        }

        // 时间戳哈希 (确保同一文件在不同时间生成也被认为是不同的)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        timestamp.hash(&mut hasher);

        Ok(format!("{:x}", hasher.finish()))
    }

    /// 获取当前使用统计
    pub fn get_usage_stats(&self) -> Result<(u64, u64, bool)> {
        let counter = self.load_counter()?;
        let is_limit_reached = counter.unique_pcaps.len() >= self.config.activation_threshold as usize;
        let is_expired = self.check_is_expired()?;
        let is_blocked = is_limit_reached || is_expired;
        Ok((counter.total_generated, counter.unique_pcaps.len() as u64, is_blocked))
    }

    /// 显示许可证状态
    pub fn show_license_status(&self) -> Result<()> {
        // 检查过期时间
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("无法获取当前时间")?
            .as_secs();

        let remaining_days = if self.config.expiration_timestamp > current_time {
            let remaining_seconds = self.config.expiration_timestamp - current_time;
            remaining_seconds / 86400 // 转换为天数
        } else {
            0
        };

        // 获取使用统计
        let (total, unique, is_blocked) = self.get_usage_stats()?;
        let is_expired = self.check_is_expired()?;

        println!("[*] 许可证状态:");
        println!("    过期时间: 2026年5月31日");
        if is_expired {
            println!("    过期状态: [已过期]");
        } else {
            println!("    过期状态: [未过期]");
        }
        println!("    剩余天数: {} 天", remaining_days);
        println!("    总生成次数: {}", total);
        println!("    唯一PCAP文件: {}", unique);
        println!("    使用限制: {}", self.config.activation_threshold);

        if is_blocked {
            if is_expired {
                println!("    程序状态: [已禁用 - 已过期]");
            } else {
                println!("    程序状态: [已禁用 - 达到使用限制]");
            }
        } else {
            println!("    程序状态: [可正常使用]");
        }

        Ok(())
    }
}

/// 全局许可证检查函数
pub fn check_program_license() -> Result<()> {
    let license_manager = LicenseManager::new();

    // 检查程序是否允许使用
    let is_allowed = license_manager.check_usage_allowed()?;
    if !is_allowed {
        let (_, unique, _) = license_manager.get_usage_stats()?;
        let is_expired = license_manager.check_is_expired()?;

        if is_expired {
            let expiration_date = std::time::UNIX_EPOCH + std::time::Duration::from_secs(license_manager.config.expiration_timestamp);
            let _remaining_days = if expiration_date.duration_since(SystemTime::now()).is_ok() {
                0
            } else {
                expiration_date.duration_since(SystemTime::now()).unwrap().as_secs() / 86400
            };

            return Err(anyhow::anyhow!(
                "程序已过期！过期时间: 2026年5月31日。\n\
                请联系开发者获取更新版本。"
            ));
        } else {
            return Err(anyhow::anyhow!(
                "程序使用次数已达到限制！当前唯一PCAP文件数: {}/{}。\n\
                程序已达到最大使用次数，无法继续生成PCAP文件。\n\
                如需继续使用，请联系开发者获取新的许可证。",
                unique, license_manager.config.activation_threshold
            ));
        }
    }

    Ok(())
}