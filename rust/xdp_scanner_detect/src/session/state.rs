//! TCP 会话状态管理

/// TCP 会话状态
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpSessionState {
    /// 未知状态
    Unknown,
    /// SYN 已发送
    SynSent,
    /// SYN 已接收
    SynReceived,
    /// 连接已建立
    Established,
    /// FIN 等待
    FinWait,
    /// 连接已重置
    Reset,
}

impl TcpSessionState {
    /// 从状态值创建
    pub fn from_value(value: u32) -> Self {
        match value {
            1 => Self::SynSent,
            2 => Self::SynReceived,
            3 => Self::Established,
            4 => Self::FinWait,
            5 => Self::Reset,
            _ => Self::Unknown,
        }
    }

    /// 转换为状态值
    pub fn to_value(self) -> u32 {
        match self {
            Self::Unknown => 0,
            Self::SynSent => 1,
            Self::SynReceived => 2,
            Self::Established => 3,
            Self::FinWait => 4,
            Self::Reset => 5,
        }
    }
}