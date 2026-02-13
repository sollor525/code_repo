/**
 * @file mod.rs
 * @brief 统一的注入管理模块
 * @author sollor525@hotmail.com
 * @version 1.0.0
 * @date 2023-11-05
 */

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, debug, warn};
use anyhow::Result;

use crate::common::error::TlsKeyAgentError;
use crate::config::Config;
pub use seamless_injection::{SeamlessInjector, InjectionStats};

pub mod preload;
pub mod ebpf;
pub mod detector;
pub mod seamless_injection;
pub mod multi_ssl_injector;

// 重新导出eBPF相关的类型以保持兼容性
pub use ebpf::{EbpfSslHook, EbpfSslEvent, EbpfSslHookStats};
pub use multi_ssl_injector::{MultiSslInjector, SslLibraryType, MultiSslEvent, SslLibraryConfig, MultiSslStats};

/// 注入方式枚举
#[derive(Debug, Clone, PartialEq)]
pub enum InjectionMethod {
    /// LD_PRELOAD注入（传统方式，兼容性好）
    LdPreload,
    /// eBPF注入（现代方式，性能好）
    Ebpf,
    /// 自动选择最佳方式
    Auto,
}

/// 注入状态
#[derive(Debug, Clone)]
pub struct InjectionStatus {
    pub method: InjectionMethod,
    pub is_active: bool,
    pub target_processes: Vec<TargetProcess>,
    pub injected_processes: Vec<TargetProcess>,
    pub last_update: std::time::SystemTime,
}

/// 目标进程信息
#[derive(Debug, Clone)]
pub struct TargetProcess {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub uses_tls: bool,
    pub ssl_lib_path: Option<String>,
    pub is_injected: bool,
    pub injection_time: Option<std::time::SystemTime>,
}

/// 统一的注入管理器
pub struct InjectionManager {
    config: Arc<Config>,
    preload_injector: Arc<RwLock<preload::PreloadInjector>>,
    ebpf_hook: Arc<RwLock<ebpf::EbpfSslHook>>,
    detector: Arc<detector::ProcessDetector>,
    status: Arc<RwLock<InjectionStatus>>,
    seamless_injector: Option<Arc<SeamlessInjector>>,
}

impl InjectionManager {
    /// 创建新的注入管理器
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        info!("初始化注入管理器");

        let preload_injector = Arc::new(RwLock::new(preload::PreloadInjector::new(config.clone())));
        let ebpf_hook = Arc::new(RwLock::new(ebpf::EbpfSslHook::new(config.clone())));
        let detector = Arc::new(detector::ProcessDetector::new());

        let status = Arc::new(RwLock::new(InjectionStatus {
            method: InjectionMethod::Auto,
            is_active: false,
            target_processes: Vec::new(),
            injected_processes: Vec::new(),
            last_update: std::time::SystemTime::now(),
        }));

        Ok(Self {
            config,
            preload_injector,
            ebpf_hook,
            detector,
            status,
            seamless_injector: None,
        })
    }

    /// 启动注入管理器
    pub async fn start(&self) -> Result<()> {
        info!("启动注入管理器");

        // 检测系统支持的注入方式
        let supported_methods = self.detect_supported_methods().await?;
        debug!("支持的注入方式: {:?}", supported_methods);

        // 选择最佳注入方式
        let method = self.select_best_method(&supported_methods);
        info!("选择的注入方式: {:?}", method);

        // 启动对应的注入器
        match method {
            InjectionMethod::LdPreload => {
                self.start_preload_injection().await?;
            }
            InjectionMethod::Ebpf => {
                self.start_ebpf_injection().await?;
            }
            InjectionMethod::Auto => {
                // 先尝试eBPF，失败则使用LD_PRELOAD
                if let Err(e) = self.start_ebpf_injection().await {
                    warn!("eBPF注入启动失败，切换到LD_PRELOAD: {}", e);
                    self.start_preload_injection().await?;
                }
            }
        }

        // 更新状态
        let mut status = self.status.write().await;
        status.method = method;
        status.is_active = true;
        status.last_update = std::time::SystemTime::now();

        info!("注入管理器启动成功");
        Ok(())
    }

    /// 停止注入管理器
    pub async fn stop(&self) -> Result<()> {
        info!("停止注入管理器");

        // 停止所有注入器
        let preload_injector = self.preload_injector.read().await;
        let ebpf_injector = self.ebpf_hook.read().await;

        if let Err(e) = preload_injector.stop().await {
            warn!("LD_PRELOAD注入器停止失败: {}", e);
        }

        if let Err(e) = ebpf_injector.stop().await {
            warn!("eBPF注入器停止失败: {}", e);
        }

        // 更新状态
        let mut status = self.status.write().await;
        status.is_active = false;
        status.last_update = std::time::SystemTime::now();

        info!("注入管理器已停止");
        Ok(())
    }

    /// 发现TLS进程
    pub async fn discover_tls_processes(&self) -> Result<Vec<TargetProcess>> {
        debug!("发现TLS进程");
        self.detector.discover_tls_processes().await
    }

    /// 注入到指定进程
    pub async fn inject_process(&self, pid: u32) -> Result<()> {
        info!("注入到进程 {}", pid);

        // 发现进程信息
        let processes = self.discover_tls_processes().await?;
        let target_process = processes.iter().find(|p| p.pid == pid);

        if let Some(process) = target_process {
            let method = {
                let status = self.status.read().await;
                status.method.clone()
            };

            match method {
                InjectionMethod::LdPreload => {
                    let injector = self.preload_injector.read().await;
                    injector.inject_process(process).await
                }
                InjectionMethod::Ebpf => {
                    // eBPF是系统级Hook，自动监控所有进程
                    info!("eBPF Hook已启用，进程 {} 将被自动监控", process.pid);
                    Ok(())
                }
                InjectionMethod::Auto => {
                    // 检查eBPF是否运行
                    let ebpf_injector = self.ebpf_hook.read().await;
                    if ebpf_injector.is_running() {
                        info!("eBPF Hook已启用，进程 {} 将被自动监控", process.pid);
                        Ok(())
                    } else {
                        warn!("eBPF Hook未运行，切换到LD_PRELOAD");
                        self.preload_injector.read().await.inject_process(process).await
                    }
                }
            }
        } else {
            Err(TlsKeyAgentError::Injection(format!("进程 {} 未找到或不支持TLS", pid)).into())
        }
    }

    /// 批量注入所有TLS进程
    pub async fn inject_all_tls_processes(&self) -> Result<usize> {
        info!("批量注入所有TLS进程");

        let processes = self.discover_tls_processes().await?;
        let mut injected_count = 0;

        for process in &processes {
            if !process.is_injected && process.uses_tls {
                match self.inject_process(process.pid).await {
                    Ok(_) => {
                        injected_count += 1;
                        info!("成功注入进程 {}: {}", process.pid, process.name);
                    }
                    Err(e) => {
                        error!("注入进程 {} 失败: {}", process.pid, e);
                    }
                }
            }
        }

        info!("批量注入完成，成功注入 {} 个进程", injected_count);
        Ok(injected_count)
    }

    /// 获取注入状态
    pub async fn get_status(&self) -> InjectionStatus {
        let status = self.status.read().await;
        status.clone()
    }

    /// 检测系统支持的注入方式
    async fn detect_supported_methods(&self) -> Result<Vec<InjectionMethod>> {
        let mut methods = Vec::new();

        // LD_PRELOAD总是支持的
        methods.push(InjectionMethod::LdPreload);

        // 检查eBPF支持
        let ebpf_injector = self.ebpf_hook.read().await;
        if ebpf_injector.is_supported().await {
            methods.push(InjectionMethod::Ebpf);
        }

        Ok(methods)
    }

    /// 选择最佳注入方式
    fn select_best_method(&self, supported_methods: &[InjectionMethod]) -> InjectionMethod {
        if supported_methods.contains(&InjectionMethod::Ebpf) {
            InjectionMethod::Ebpf
        } else if supported_methods.contains(&InjectionMethod::LdPreload) {
            InjectionMethod::LdPreload
        } else {
            InjectionMethod::LdPreload // 默认回退
        }
    }

    /// 启动LD_PRELOAD注入
    async fn start_preload_injection(&self) -> Result<()> {
        info!("启动LD_PRELOAD注入");
        let injector = self.preload_injector.read().await;
        injector.start().await
    }

    /// 启动eBPF注入
    async fn start_ebpf_injection(&self) -> Result<()> {
        info!("启动eBPF注入");
        let injector = self.ebpf_hook.read().await;
        injector.start().await
    }

    /// 启动无感注入
    pub async fn start_seamless_injection(&self) -> Result<()> {
        info!("启动无感注入");

        // 获取当前注入方法
        let current_method = {
            let status = self.status.read().await;
            status.method.clone()
        };

        let seamless_injector = SeamlessInjector::new(
            self.config.clone(),
            self.preload_injector.clone(),
            self.ebpf_hook.clone(),
            self.detector.clone(),
            current_method,
        ).await?;

        // 启动无感注入
        seamless_injector.start().await?;

        // 将无感注入器添加到管理器（这里需要重新设计结构）
        info!("无感注入启动成功");
        Ok(())
    }

    /// 停止无感注入
    pub async fn stop_seamless_injection(&self) -> Result<()> {
        info!("停止无感注入");

        if let Some(seamless_injector) = &self.seamless_injector {
            seamless_injector.stop().await?;
        }

        info!("无感注入已停止");
        Ok(())
    }

    /// 获取无感注入统计信息
    pub async fn get_seamless_stats(&self) -> Option<InjectionStats> {
        if let Some(seamless_injector) = &self.seamless_injector {
            Some(seamless_injector.get_injection_stats().await)
        } else {
            None
        }
    }

    /// 清理过期的注入记录
    pub async fn cleanup_injection_records(&self) -> Result<()> {
        if let Some(seamless_injector) = &self.seamless_injector {
            seamless_injector.cleanup_expired_records().await;
        }
        Ok(())
    }

    /// 完整启动注入管理器（包括无感注入）
    pub async fn start_with_seamless(&mut self) -> Result<()> {
        info!("启动注入管理器（包含无感注入）");

        // 启动基础注入管理器
        self.start().await?;

        // 如果配置中启用了自动注入，则启动无感注入
        if self.config.injection.auto_inject {
            self.start_seamless_injection().await?;
        }

        info!("注入管理器（包含无感注入）启动成功");
        Ok(())
    }

  }

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_injection_method_selection() {
        let config = Arc::new(Config::default());
        let manager = InjectionManager::new(config).await.unwrap();

        // 测试方法选择
        let methods = vec![InjectionMethod::LdPreload, InjectionMethod::Ebpf];
        let selected = manager.select_best_method(&methods);
        assert_eq!(selected, InjectionMethod::Ebpf);

        let methods = vec![InjectionMethod::LdPreload];
        let selected = manager.select_best_method(&methods);
        assert_eq!(selected, InjectionMethod::LdPreload);
    }

    #[tokio::test]
    async fn test_injection_manager_lifecycle() {
        let config = Arc::new(Config::default());
        let manager = InjectionManager::new(config).await.unwrap();

        assert!(!manager.get_status().await.is_active);

        // 注意：实际启动测试需要模拟环境
        // manager.start().await.unwrap();
        // assert!(manager.get_status().await.is_active);
        // manager.stop().await.unwrap();
        // assert!(!manager.get_status().await.is_active);
    }
}