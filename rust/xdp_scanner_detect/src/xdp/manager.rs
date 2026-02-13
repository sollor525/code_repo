//! XDP 管理器实现
//!
//! 负责 eBPF/XDP 程序的完整生命周期管理

use aya::{Ebpf, programs::Xdp, include_bytes_aligned};
use aya_log::EbpfLogger;
use crate::config::InterfaceConfig;
use crate::xdp::{
    InterfaceInfo, LoadConfig, ProgramMetadata, XdpMode, XdpProgram, XdpStats,
    verify_ebpf_permissions, configure_system_for_ebpf, cleanup_system_config,
};
use crate::xdp::maps::XdpMaps;
use crate::stats::StatsCollector;
use crate::stats::XdpStatsData;
use anyhow::{anyhow, Context, Result};
use log::{info, warn, error, debug};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, Duration, interval};

/// XDP 管理器
///
/// 负责：
/// - 加载和管理多个 XDP 程序
/// - 维护网络接口状态
/// - 监控程序性能
/// - 处理错误和恢复
pub struct XdpManager {
    /// eBPF 程序实例
    ebpf: Arc<Mutex<Option<Ebpf>>>,
    /// 已加载的程序映射
    programs: Arc<RwLock<HashMap<String, XdpProgram>>>,
    /// 接口信息缓存
    interfaces: Arc<RwLock<HashMap<String, InterfaceInfo>>>,
    /// 程序元数据
    metadata: Arc<RwLock<HashMap<String, ProgramMetadata>>>,
    /// 统计信息收集器（XDP 内部统计）
    stats: Arc<XdpStats>,
    /// 全局统计收集器
    stats_collector: Arc<StatsCollector>,
    /// 是否已初始化
    initialized: Arc<RwLock<bool>>,
}

impl XdpManager {
    /// 创建新的 XDP 管理器
    pub fn new(stats_collector: Arc<StatsCollector>) -> Self {
        Self {
            ebpf: Arc::new(Mutex::new(None)),
            programs: Arc::new(RwLock::new(HashMap::new())),
            interfaces: Arc::new(RwLock::new(HashMap::new())),
            metadata: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(XdpStats::new()),
            stats_collector,
            initialized: Arc::new(RwLock::new(false)),
        }
    }

    /// 初始化 XDP 管理器
    pub async fn initialize(&mut self) -> Result<()> {
        info!("初始化 XDP 管理器");

        // 验证权限
        verify_ebpf_permissions()
            .context("验证 eBPF 权限失败")?;

        // 配置系统
        configure_system_for_ebpf().await
            .context("配置系统参数失败")?;

        // 初始化统计系统
        self.stats.initialize().await?;

        // 标记为已初始化
        let mut initialized = self.initialized.write().await;
        *initialized = true;

        info!("XDP 管理器初始化完成");
        Ok(())
    }

    /// 加载并附加 XDP 程序到指定接口
    pub async fn load_and_attach(&mut self, interface_name: &str, promisc_mode: bool) -> Result<()> {
        self.ensure_initialized().await?;

        info!("在接口 {} 上加载 XDP 程序", interface_name);

        // 获取接口信息
        let interface = self.get_or_load_interface_info(interface_name).await?;

        if !interface.xdp_supported {
            return Err(anyhow!("接口 {} 不支持 XDP", interface_name));
        }

        // 设置混杂模式（如果需要）
        if promisc_mode {
            info!("启用接口 {} 混杂模式", interface_name);
            interface.set_promisc(true)?;
        }

        // 加载 eBPF 字节码
        let mut ebpf_lock = self.ebpf.lock().await;
        let ebpf = if ebpf_lock.is_none() {
            let bpf = self.load_ebpf_program().await?;
            *ebpf_lock = Some(bpf);
            ebpf_lock.as_mut().unwrap()
        } else {
            ebpf_lock.as_mut().unwrap()
        };

        // 尝试不同的 XDP 模式
        let modes = vec![
            XdpMode::Native,
            XdpMode::Skb,
            XdpMode::Hardware,
        ];

        let mut last_error = None;
        let mut program_loaded = false;

        for mode in modes {
            match self.try_attach_mode(ebpf, &interface, mode, &mut program_loaded).await {
                Ok(program) => {
                    info!("成功以 {:?} 模式附加 XDP 程序到接口 {}", mode, interface_name);

                    // 保存程序信息
                    let metadata = ProgramMetadata {
                        name: "xdp_scanner_xdp".to_string(),
                        tag: format!("{}-{:?}", interface_name, mode),
                        id: 0,  // 暂时使用 0
                        load_time: std::time::SystemTime::now(),
                    };

                    let mut programs = self.programs.write().await;
                    programs.insert(interface_name.to_string(), program);

                    let mut metadata_map = self.metadata.write().await;
                    metadata_map.insert(interface_name.to_string(), metadata);

                    // 启动监控任务
                    self.start_monitoring_task(interface_name.to_string()).await;

                    return Ok(());
                },
                Err(e) => {
                    warn!("以 {:?} 模式附加失败: {}", mode, e);
                    last_error = Some(e);
                    continue;
                }
            }
        }

        // 如果所有模式都失败，恢复混杂模式并返回错误
        if promisc_mode {
            let _ = interface.restore_promisc();
        }

        Err(last_error.unwrap_or_else(|| anyhow!("所有 XDP 模式都失败了")))
    }

    /// 加载 XDP 程序到内核
    async fn load_xdp_program(&self, ebpf: &mut Ebpf) -> Result<()> {
        use aya::programs::{Xdp, Program};

        let program = ebpf.program_mut("xdp_main")
            .ok_or_else(|| anyhow!("找不到 xdp_main 程序"))?;

        let xdp_program = match program {
            Program::Xdp(xdp) => xdp,
            _ => return Err(anyhow!("程序类型不是 XDP")),
        };

        xdp_program.load()
            .context("加载 eBPF 程序失败")?;

        info!("eBPF 程序已加载到内核");
        Ok(())
    }

    /// 尝试以特定模式附加程序
    async fn try_attach_mode(
        &self,
        ebpf: &mut Ebpf,
        interface: &InterfaceInfo,
        mode: XdpMode,
        program_loaded: &mut bool,
    ) -> Result<XdpProgram> {
        use aya::programs::{Xdp, Program};

        // 获取程序
        let program = ebpf.program_mut("xdp_main")
            .ok_or_else(|| anyhow!("找不到 xdp_main 程序"))?;

        let xdp_program = match program {
            Program::Xdp(xdp) => xdp,
            _ => return Err(anyhow!("程序类型不是 XDP")),
        };

        // 只在第一次时加载程序
        if !*program_loaded {
            xdp_program.load()
                .context("加载 eBPF 程序失败")?;
            *program_loaded = true;
            info!("eBPF 程序已加载到内核");
        }

        // 附加到接口
        xdp_program.attach(&interface.name, mode.into())
            .with_context(|| format!("以 {:?} 模式附加到接口 {} 失败", mode, interface.name))?;

        // 获取不可变引用用于创建 XdpProgram
        let program_ref = ebpf.program("xdp_main")
            .ok_or_else(|| anyhow!("找不到 xdp_main 程序"))?;

        let xdp_ref = match program_ref {
            Program::Xdp(xdp) => xdp,
            _ => return Err(anyhow!("程序类型不是 XDP")),
        };

        Ok(XdpProgram::new(xdp_ref, mode))
    }

    /// 加载 eBPF 程序
    async fn load_ebpf_program(&self) -> Result<Ebpf> {
        // 尝试从多个位置加载 eBPF 字节码
        let bytecode = Self::load_bytecode()?;
        let mut bpf = aya::Ebpf::load(&bytecode)?;

        // 初始化 eBPF 日志
        let _ = aya_log::EbpfLogger::init(&mut bpf);

        Ok(bpf)
    }

    /// 加载 eBPF 字节码
    fn load_bytecode() -> Result<Vec<u8>> {
        // 1. 检查环境变量
        if let Ok(path) = std::env::var("XDP_SCANNER_EBPF_PATH") {
            info!("从环境变量加载 eBPF 字节码: {}", path);
            return std::fs::read(&path)
                .with_context(|| format!("读取 eBPF 字节码失败: {}", path));
        }

        // 2. 检查可执行文件所在目录
        if let Ok(exe_path) = std::env::current_exe() {
            let exe_dir = exe_path.parent().ok_or_else(|| anyhow!("无法获取可执行文件目录"))?;
            let bytecode_path = exe_dir.join("xdp-scanner-detect-ebpf");

            if bytecode_path.exists() {
                info!("从可执行文件目录加载 eBPF 字节码: {:?}", bytecode_path);
                return std::fs::read(&bytecode_path)
                    .with_context(|| format!("读取 eBPF 字节码失败: {:?}", bytecode_path));
            }
        }

        // 3. 使用编译时嵌入的字节码（从项目目录运行）
        #[cfg(debug_assertions)]
        let bytecode = include_bytes_aligned!("../../target/bpfel-unknown-none/release/xdp-scanner-detect-ebpf");

        #[cfg(not(debug_assertions))]
        let bytecode = include_bytes_aligned!("../../target/bpfel-unknown-none/release/xdp-scanner-detect-ebpf");

        info!("使用编译时嵌入的 eBPF 字节码");
        Ok(bytecode.to_vec())
    }

    /// 获取或加载接口信息
    async fn get_or_load_interface_info(&self, interface_name: &str) -> Result<InterfaceInfo> {
        let mut interfaces = self.interfaces.write().await;

        if let Some(info) = interfaces.get(interface_name) {
            Ok(info.clone())
        } else {
            let info = InterfaceInfo::new(interface_name)?;
            interfaces.insert(interface_name.to_string(), info.clone());
            Ok(info)
        }
    }

    /// 启动监控任务
    async fn start_monitoring_task(&self, interface_name: String) {
        info!("启动接口 {} 的监控任务", interface_name);
        let stats = self.stats.clone();
        let stats_collector = self.stats_collector.clone();
        let interface = interface_name.clone();
        let ebpf = self.ebpf.clone();

        tokio::spawn(async move {
            info!("监控任务已启动，开始轮询接口 {}", interface);
            let mut interval = interval(Duration::from_secs(5));

            loop {
                interval.tick().await;

                // 直接读取统计数据
                let ebpf_guard = ebpf.lock().await;
                if let Some(ebpf_ref) = ebpf_guard.as_ref() {
                    let maps = XdpMaps::new(ebpf_ref);
                    match maps.get_stats() {
                        Ok(xdp_stats) => {
                            drop(ebpf_guard); // 释放锁
                            info!("读取到统计: total={}, tcp={}, sessions={}",
                                xdp_stats.total_packets, xdp_stats.tcp_packets, xdp_stats.new_sessions);

                            // 更新内部 XDP 统计
                            if let Err(e) = stats.update_interface_stats_direct(&interface, xdp_stats.clone()).await {
                                warn!("更新接口 {} 统计失败: {}", interface, e);
                            }

                            // 更新全局统计收集器
                            let stats_data = XdpStatsData {
                                total_packets: xdp_stats.total_packets,
                                tcp_packets: xdp_stats.tcp_packets,
                                new_sessions: xdp_stats.new_sessions,
                                malformed_packets: xdp_stats.malformed_packets,
                                scanner_detected: xdp_stats.scanner_detected,
                                malicious_sessions: xdp_stats.malicious_sessions,
                                dropped_packets: xdp_stats.dropped_packets,
                            };
                            stats_collector.update_xdp_stats(stats_data).await;
                        }
                        Err(e) => {
                            warn!("读取 eBPF maps 统计失败: {}", e);
                        }
                    }
                } else {
                    warn!("eBPF 实例不可用");
                }
            }
        });
    }

    /// 卸载 XDP 程序
    pub async fn unload(&mut self, interface_name: &str) -> Result<()> {
        info!("从接口 {} 卸载 XDP 程序", interface_name);

        // 获取接口信息（用于恢复混杂模式）
        let interface_opt = {
            let interfaces = self.interfaces.read().await;
            interfaces.get(interface_name).cloned()
        };

        let mut programs = self.programs.write().await;
        if let Some(program) = programs.remove(interface_name) {
            // 程序会在 Drop 时自动卸载
            drop(program);
        }

        let mut metadata = self.metadata.write().await;
        metadata.remove(interface_name);

        // 恢复混杂模式到原始状态
        if let Some(interface) = interface_opt {
            if let Err(e) = interface.restore_promisc() {
                warn!("恢复接口 {} 混杂模式失败: {}", interface_name, e);
            }
        }

        Ok(())
    }

    /// 清理所有资源
    pub async fn cleanup(&mut self) -> Result<()> {
        info!("清理 XDP 管理器资源");

        // 卸载所有程序
        let programs: Vec<String> = self.programs.read().await.keys().cloned().collect();
        for interface in programs {
            if let Err(e) = self.unload(&interface).await {
                warn!("卸载接口 {} 程序失败: {}", interface, e);
            }
        }

        // 清理 eBPF 实例
        let mut ebpf = self.ebpf.lock().await;
        *ebpf = None;

        // 清理系统配置
        cleanup_system_config().await?;

        // 重置初始化状态
        let mut initialized = self.initialized.write().await;
        *initialized = false;

        info!("XDP 管理器清理完成");
        Ok(())
    }

    /// 获取程序元数据
    pub async fn get_metadata(&self, interface_name: &str) -> Option<ProgramMetadata> {
        let metadata = self.metadata.read().await;
        metadata.get(interface_name).cloned()
    }

    /// 获取所有已加载的程序
    pub async fn list_programs(&self) -> Vec<String> {
        let programs = self.programs.read().await;
        programs.keys().cloned().collect()
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> crate::xdp::XdpProgramStats {
        self.stats.get_overall_stats().await
    }

    /// 获取特定接口的统计信息
    pub async fn get_interface_stats(&self, interface_name: &str) -> Option<crate::xdp::XdpProgramStats> {
        self.stats.get_interface_stats(interface_name).await
    }

    /// 检查程序是否正在运行
    pub async fn is_running(&self, interface_name: &str) -> bool {
        let programs = self.programs.read().await;
        programs.contains_key(interface_name)
    }

    /// 确保管理器已初始化
    async fn ensure_initialized(&self) -> Result<()> {
        let initialized = self.initialized.read().await;
        if !*initialized {
            return Err(anyhow!("XDP 管理器未初始化"));
        }
        Ok(())
    }

    /// 直接读取统计数据
    pub async fn read_stats(&self) -> Result<super::XdpProgramStats> {
        let ebpf = self.ebpf.lock().await;
        if let Some(ebpf_ref) = ebpf.as_ref() {
            let maps = XdpMaps::new(ebpf_ref);
            maps.get_stats()
        } else {
            Ok(super::XdpProgramStats::default())
        }
    }
}

impl Drop for XdpManager {
    fn drop(&mut self) {
        // 注意：这里不能使用 async，只能清理同步资源
        info!("Xdp 管理器正在销毁");
    }
}