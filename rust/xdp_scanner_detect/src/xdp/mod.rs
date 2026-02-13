//! XDP 管理模块
//!
//! 负责 eBPF/XDP 程序的生命周期管理，包括：
//! - 程序加载和卸载
//! - 网络接口配置
//! - 与 eBPF 程序的交互
//! - 错误处理和恢复

use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use anyhow::{anyhow, Context, Result};
use log::{info, warn, error, debug};
use std::fs;
use std::net::Ipv4Addr;
use tokio::time::{sleep, Duration};

pub mod manager;
pub mod program;
pub mod maps;
pub mod stats;

pub use manager::XdpManager;
pub use program::XdpProgram;
pub use stats::XdpStats;

/// XDP 运行模式
#[derive(Debug, Clone, Copy)]
pub enum XdpMode {
    /// 通用模式 (SKB)，兼容性最好
    Skb,
    /// 驱动模式 (Native)，性能最好
    Native,
    /// 硬件卸载模式，需要网卡支持
    Hardware,
}

impl From<XdpMode> for XdpFlags {
    fn from(mode: XdpMode) -> Self {
        match mode {
            XdpMode::Skb => XdpFlags::SKB_MODE,
            XdpMode::Native => XdpFlags::DRV_MODE,
            XdpMode::Hardware => XdpFlags::HW_MODE,
        }
    }
}

/// eBPF 程序元数据
#[derive(Debug, Clone)]
pub struct ProgramMetadata {
    /// 程序名称
    pub name: String,
    /// 程序标签
    pub tag: String,
    /// 程序 ID
    pub id: u32,
    /// 加载时间
    pub load_time: std::time::SystemTime,
}

/// 网络接口信息
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// 接口名称
    pub name: String,
    /// 接口索引
    pub index: u32,
    /// MAC 地址
    pub mac_address: [u8; 6],
    /// MTU 大小
    pub mtu: u32,
    /// 是否支持 XDP
    pub xdp_supported: bool,
    /// 支持的 XDP 模式
    pub xdp_modes: Vec<XdpMode>,
    /// 原始混杂模式状态（用于恢复）
    pub original_promisc: bool,
}

impl InterfaceInfo {
    /// 获取网络接口信息
    pub fn new(if_name: &str) -> Result<Self> {
        use nix::net::if_::if_nametoindex;
        use std::os::unix::fs::MetadataExt;

        // 获取接口索引
        let index = if_nametoindex(if_name)
            .map_err(|e| anyhow!("无效的网络接口 {}: {}", if_name, e))?;

        // 读取接口信息
        let mac_path = format!("/sys/class/net/{}/address", if_name);
        let mtu_path = format!("/sys/class/net/{}/mtu", if_name);
        let xdp_path = format!("/sys/class/net/{}/xdp", if_name);

        let mac_address = fs::read_to_string(&mac_path)
            .context(format!("读取 MAC 地址失败: {}", mac_path))?
            .trim()
            .split(':')
            .map(|s| u8::from_str_radix(s, 16).unwrap_or(0))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or([0; 6]);

        let mtu = fs::read_to_string(&mtu_path)
            .context(format!("读取 MTU 失败: {}", mtu_path))?
            .trim()
            .parse()
            .unwrap_or(1500);

        // XDP 支持检测 - 不提前检查，直接尝试加载
        // 所有接口都至少支持 SKB 模式
        let xdp_supported = true;  // 假设支持，实际加载时会验证

        // 确定支持的 XDP 模式 - 尝试所有模式
        let mut xdp_modes = Vec::new();
        xdp_modes.push(XdpMode::Skb);      // SKB 模式所有接口都支持
        xdp_modes.push(XdpMode::Native);   // 尝试 Native 模式
        xdp_modes.push(XdpMode::Hardware); // 尝试 Hardware 模式

        // 读取原始混杂模式状态
        let promisc_path = format!("/sys/class/net/{}/promiscuity", if_name);
        let original_promisc = fs::read_to_string(&promisc_path)
            .and_then(|s| Ok(s.trim().parse::<u32>().unwrap_or(0) == 1))
            .unwrap_or(false);

        Ok(Self {
            name: if_name.to_string(),
            index,
            mac_address,
            mtu,
            xdp_supported,
            xdp_modes,
            original_promisc,
        })
    }

    /// 设置接口混杂模式
    pub fn set_promisc(&self, enable: bool) -> Result<()> {
        // 使用 ip link 命令来设置
        let status = if enable { "on" } else { "off" };
        let output = std::process::Command::new("ip")
            .args(["link", "set", &self.name, "promisc", status])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                info!("接口 {} 混杂模式设置为: {}", self.name, status);
                Ok(())
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                Err(anyhow!("设置混杂模式失败: {}", stderr))
            }
            Err(e) => Err(anyhow!("执行 ip 命令失败: {}", e)),
        }
    }

    /// 恢复接口混杂模式到原始状态
    pub fn restore_promisc(&self) -> Result<()> {
        self.set_promisc(self.original_promisc)
    }
}

/// XDP 程序加载配置
#[derive(Debug, Clone)]
pub struct LoadConfig {
    /// XDP 模式
    pub mode: XdpMode,
    /// 是否启用多队列
    pub multi_queue: bool,
    /// 队列数量
    pub queue_count: Option<u32>,
    /// CPU 亲和性映射
    pub cpu_mapping: Option<Vec<u32>>,
    /// 程序重试次数
    pub retry_count: u32,
    /// 重试间隔（毫秒）
    pub retry_interval_ms: u64,
}

impl Default for LoadConfig {
    fn default() -> Self {
        Self {
            mode: XdpMode::Skb,
            multi_queue: false,
            queue_count: None,
            cpu_mapping: None,
            retry_count: 3,
            retry_interval_ms: 1000,
        }
    }
}

/// XDP 程序统计信息
#[derive(Debug, Clone)]
pub struct XdpProgramStats {
    /// 总处理数据包数
    pub total_packets: u64,
    /// TCP 包数
    pub tcp_packets: u64,
    /// 新会话数
    pub new_sessions: u64,
    /// 格式错误包数
    pub malformed_packets: u64,
    /// 检测到的扫描器数量
    pub scanner_detected: u64,
    /// 恶意会话数
    pub malicious_sessions: u64,
    /// 丢弃的数据包数
    pub dropped_packets: u64,
    /// 转发的数据包数
    pub passed_packets: u64,
    /// 重定向的数据包数
    pub redirected_packets: u64,
    /// 异常退出数
    pub aborted_packets: u64,
    /// 平均处理时间（纳秒）
    pub avg_processing_time_ns: u64,
    /// 最后更新时间
    pub last_update: std::time::SystemTime,
}

impl Default for XdpProgramStats {
    fn default() -> Self {
        Self {
            total_packets: 0,
            tcp_packets: 0,
            new_sessions: 0,
            malformed_packets: 0,
            scanner_detected: 0,
            malicious_sessions: 0,
            dropped_packets: 0,
            passed_packets: 0,
            redirected_packets: 0,
            aborted_packets: 0,
            avg_processing_time_ns: 0,
            last_update: std::time::SystemTime::now(),
        }
    }
}

impl XdpProgramStats {
    /// 计算丢包率
    pub fn drop_rate(&self) -> f64 {
        if self.total_packets == 0 {
            0.0
        } else {
            self.dropped_packets as f64 / self.total_packets as f64 * 100.0
        }
    }

    /// 计算通过率
    pub fn pass_rate(&self) -> f64 {
        if self.total_packets == 0 {
            0.0
        } else {
            self.passed_packets as f64 / self.total_packets as f64 * 100.0
        }
    }
}

/// 验证 eBPF 程序权限
pub fn verify_ebpf_permissions() -> Result<()> {
    // 检查是否以 root 权限运行
    if !nix::unistd::getuid().is_root() {
        return Err(anyhow!("需要 root 权限来加载 eBPF 程序"));
    }

    // 增加 RLIMIT_MEMLOCK 限制
    // eBPF map 创建需要足够的内存锁定空间
    unsafe {
        let mut rlim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) == 0 {
            // 设置为 RLIM_INFINITY
            rlim.rlim_cur = libc::RLIM_INFINITY;
            rlim.rlim_max = libc::RLIM_INFINITY;

            if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) != 0 {
                warn!("无法增加 RLIMIT_MEMLOCK: {}", std::io::Error::last_os_error());
            } else {
                info!("已将 RLIMIT_MEMLOCK 设置为无限制");
            }
        }
    }

    Ok(())
}

/// 检查系统支持
pub fn check_system_support() -> Result<SystemSupport> {
    let mut support = SystemSupport::default();

    // 检查内核版本
    let uname = nix::sys::utsname::uname()?;
    if let Some(version_str) = uname.release().to_str() {
        if let Some(version) = parse_kernel_version(version_str) {
            support.kernel_version = Some(version);
            support.ebpf_supported = version >= (5, 8, 0);
        }
    }

    // 检查是否支持 BPF JIT
    if let Ok(jit_enabled) = fs::read_to_string("/proc/sys/net/core/bpf_jit_enable") {
        support.bpf_jit_enabled = jit_enabled.trim() != "0";
    }

    // 检查是否支持 HugePages
    if let Ok(hugepages) = fs::read_dir("/sys/kernel/mm/hugepages") {
        support.hugepages_supported = hugepages.count() > 0;
    }

    Ok(support)
}

/// 系统支持信息
#[derive(Debug, Default)]
pub struct SystemSupport {
    /// 内核版本 (major, minor, patch)
    pub kernel_version: Option<(u32, u32, u32)>,
    /// 是否支持 eBPF
    pub ebpf_supported: bool,
    /// 是否启用 BPF JIT
    pub bpf_jit_enabled: bool,
    /// 是否支持 HugePages
    pub hugepages_supported: bool,
}

impl SystemSupport {
    /// 检查是否支持特定功能
    pub fn supports_xdp(&self) -> bool {
        self.ebpf_supported
    }

    pub fn supports_lpm_trie(&self) -> bool {
        self.ebpf_supported && self.kernel_version.map_or(false, |v| v >= (4, 11, 0))
    }

    pub fn supports_percpu_maps(&self) -> bool {
        self.ebpf_supported
    }
}

/// 解析内核版本字符串
fn parse_kernel_version(version: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() >= 2 {
        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let patch = if parts.len() >= 3 {
            parts[2].split('-').next()?.parse().ok()?
        } else {
            0
        };
        Some((major, minor, patch))
    } else {
        None
    }
}

/// 配置系统参数以优化 eBPF 性能
pub async fn configure_system_for_ebpf() -> Result<()> {
    info!("配置系统参数以优化 eBPF 性能");

    // 配置内存映射限制
    if let Err(e) = fs::write("/proc/sys/vm/max_map_count", "262144") {
        warn!("设置 max_map_count 失败: {}", e);
    }

    // 增加网络缓冲区大小
    if let Err(e) = fs::write("/proc/sys/net/core/rmem_max", "134217728") {
        warn!("设置 rmem_max 失败: {}", e);
    }

    if let Err(e) = fs::write("/proc/sys/net/core/wmem_max", "134217728") {
        warn!("设置 wmem_max 失败: {}", e);
    }

    // 启用 BPF JIT
    if let Err(e) = fs::write("/proc/sys/net/core/bpf_jit_enable", "1") {
        warn!("启用 BPF JIT 失败: {}", e);
    }

    // 启用 BPF JIT kallsyms
    if let Err(e) = fs::write("/proc/sys/net/core/bpf_jit_kallsyms", "1") {
        warn!("启用 BPF JIT kallsyms 失败: {}", e);
    }

    // 配置 HugePages（如果支持）
    if check_system_support()?.hugepages_supported {
        configure_hugepages().await?;
    }

    info!("系统参数配置完成");
    Ok(())
}

/// 配置 HugePages
async fn configure_hugepages() -> Result<()> {
    // 这里可以实现 HugePages 配置
    // 由于需要 root 权限和系统配置，暂时跳过具体实现
    info!("HugePages 支持已检测到");
    Ok(())
}

/// 清理系统配置
pub async fn cleanup_system_config() -> Result<()> {
    info!("清理系统配置");

    // 这里可以恢复原始的系统参数
    // 由于安全问题，通常不会自动恢复

    info!("系统配置清理完成");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kernel_version() {
        assert_eq!(parse_kernel_version("5.15.0"), Some((5, 15, 0)));
        assert_eq!(parse_kernel_version("5.15.0-50-generic"), Some((5, 15, 0)));
        assert_eq!(parse_kernel_version("4.19"), Some((4, 19, 0)));
        assert_eq!(parse_kernel_version("invalid"), None);
    }

    #[test]
    fn test_xdp_mode_conversion() {
        // XdpFlags 不支持 PartialEq，所以只测试转换不会 panic
        let _ = XdpFlags::from(XdpMode::Skb);
        let _ = XdpFlags::from(XdpMode::Native);
        let _ = XdpFlags::from(XdpMode::Hardware);
    }

    #[test]
    fn test_xdp_program_stats() {
        let mut stats = XdpProgramStats::default();
        stats.total_packets = 1000;
        stats.dropped_packets = 100;
        stats.passed_packets = 800;

        assert!((stats.drop_rate() - 10.0).abs() < 0.001);
        assert!((stats.pass_rate() - 80.0).abs() < 0.001);
    }
}