//! 许可证和程序激活管理
//!
//! 处理程序过期时间和使用次数限制

use std::time::{SystemTime, UNIX_EPOCH};
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};

/// 程序配置
pub struct ProgramConfig {
    /// 过期时间 (2026年5月31日 23:59:59 UTC)
    pub expiration_timestamp: u64,
    /// 激活所需的PCAP生成次数
    pub activation_threshold: u64,
    /// 计数器文件路径
    pub counter_file: String,
}

impl Default for ProgramConfig {
    fn default() -> Self {
        // 2026年5月31日 23:59:59 UTC 的时间戳 (1780271999)
        let expiration_timestamp = 1780271999u64;

        Self {
            expiration_timestamp,
            activation_threshold: 10000, // 正式版本：10000个文件
            counter_file: "gen_pcap_counter.txt".to_string(),
        }
    }
}

/// 使用计数器结构
#[derive(Debug, Serialize, Deserialize)]
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

    /// 加载使用计数器
    fn load_counter(&self) -> Result<UsageCounter> {
        if Path::new(&self.config.counter_file).exists() {
            let content = fs::read_to_string(&self.config.counter_file)
                .context("无法读取计数器文件")?;

            serde_json::from_str(&content)
                .context("无法解析计数器文件")
        } else {
            Ok(UsageCounter::default())
        }
    }

    /// 保存使用计数器
    fn save_counter(&self, counter: &UsageCounter) -> Result<()> {
        let content = serde_json::to_string_pretty(counter)
            .context("无法序列化计数器")?;

        fs::write(&self.config.counter_file, content)
            .context("无法保存计数器文件")?;

        Ok(())
    }

    /// 检查程序是否已激活
    pub fn check_activation(&self) -> Result<bool> {
        let counter = self.load_counter()?;
        Ok(counter.unique_pcaps.len() >= self.config.activation_threshold as usize)
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
        let is_activated = counter.unique_pcaps.len() >= self.config.activation_threshold as usize;
        Ok((counter.total_generated, counter.unique_pcaps.len() as u64, is_activated))
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
        let (total, unique, is_activated) = self.get_usage_stats()?;

        println!("[*] 许可证状态:");
        println!("    过期时间: 2026年5月31日");
        println!("    剩余天数: {} 天", remaining_days);
        println!("    总生成次数: {}", total);
        println!("    唯一PCAP文件: {}", unique);
        println!("    激活阈值: {}", self.config.activation_threshold);
        println!("    激活状态: {}", if is_activated { "已激活" } else { "未激活" });

        Ok(())
    }
}

/// 全局许可证检查函数
pub fn check_program_license() -> Result<()> {
    let license_manager = LicenseManager::new();

    // 检查过期时间
    license_manager.check_expiration()?;

    // 检查激活状态
    let is_activated = license_manager.check_activation()?;
    if !is_activated {
        let (_, unique, _) = license_manager.get_usage_stats()?;
        return Err(anyhow::anyhow!(
            "程序尚未激活！当前唯一PCAP文件数: {}/{}。\n\
            请继续生成不同的PCAP文件直到达到激活阈值。",
            unique, license_manager.config.activation_threshold
        ));
    }

    Ok(())
}