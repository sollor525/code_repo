//! XDP 程序封装

use aya::programs::Xdp;
use std::fmt;

/// XDP 程序
pub struct XdpProgram {
    // 使用 Option 因为 Xdp 不能直接复制
    program_name: String,
    mode: crate::xdp::XdpMode,
}

impl XdpProgram {
    /// 创建新的 XDP 程序实例
    pub fn new(_program: &Xdp, mode: crate::xdp::XdpMode) -> Self {
        Self {
            program_name: "xdp_scanner_xdp".to_string(),
            mode,
        }
    }

    /// 获取程序名称
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// 获取 XDP 模式
    pub fn mode(&self) -> crate::xdp::XdpMode {
        self.mode
    }
}

impl fmt::Debug for XdpProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XdpProgram")
            .field("program_name", &self.program_name)
            .field("mode", &self.mode)
            .finish()
    }
}