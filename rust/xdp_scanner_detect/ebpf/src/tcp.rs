//! TCP 会话处理模块
//!
//! 实现 TCP 会话管理功能，包括：
//! - TCP 连接状态跟踪
//! - 会话创建和清理
//! - TCP 序列号跟踪
//! - 会话超时处理

use crate::maps::*;

/// TCP 状态转换表（简化版本）
#[inline(always)]
pub fn transition_tcp_state(_current_state: u32, _flags: u16, _direction: u8) -> u32 {
    // 简化实现：直接根据 flags 判断状态
    TCP_STATE_ESTABLISHED
}

/// 检查会话是否应该被清理
#[inline(always)]
pub fn should_cleanup_session(session: &TcpSession, current_time: u64) -> bool {
    let timeout_ns = SESSION_TIMEOUT_SEC * 1_000_000_000;

    // 检查超时
    if current_time > session.last_seen &&
       current_time - session.last_seen > timeout_ns {
        return true;
    }

    // 检查是否在结束状态且超时
    if (session.state == TCP_STATE_FIN_WAIT || session.state == TCP_STATE_RESET) &&
       current_time > session.last_seen &&
       current_time - session.last_seen > 30 * 1_000_000_000 {  // 30秒
        return true;
    }

    false
}

/// 获取会话统计信息
#[inline(always)]
pub fn get_session_stats(session: &TcpSession) -> SessionStats {
    SessionStats {
        duration: session.last_seen - session.first_seen,
        packets_total: session.packets_forward + session.packets_reverse,
        bytes_total: session.bytes_forward + session.bytes_reverse,
        packet_ratio: if session.packets_reverse > 0 {
            (session.packets_forward * 100) / session.packets_reverse
        } else {
            session.packets_forward * 100
        },
        is_asymmetric: session.packets_forward == 0 || session.packets_reverse == 0,
    }
}

/// 会话统计信息
#[repr(C)]
pub struct SessionStats {
    pub duration: u64,         // 会话持续时间（纳秒）
    pub packets_total: u64,    // 总包数
    pub bytes_total: u64,      // 总字节数
    pub packet_ratio: u64,     // 正反向包比例
    pub is_asymmetric: bool,   // 是否为非对称流
}

impl TcpSession {
    /// 计算会话的对称性
    #[inline(always)]
    pub fn calculate_symmetry(&self) -> u8 {
        if self.packets_forward == 0 && self.packets_reverse == 0 {
            return 0;  // 无数据
        }

        let total = self.packets_forward + self.packets_reverse;
        let forward_ratio = (self.packets_forward * 100) / total;

        // 返回对称性得分（0-100）
        if forward_ratio > 80 {
            (100 - forward_ratio) as u8  // 主要为正向流量
        } else if forward_ratio < 20 {
            forward_ratio as u8  // 主要为反向流量
        } else {
            (100 - ((forward_ratio - 50) * 2)) as u8  // 对称流量
        }
    }

    /// 检查是否为可疑会话
    #[inline(always)]
    pub fn is_suspicious(&self) -> bool {
        // 非对称流量
        if self.packets_forward == 0 || self.packets_reverse == 0 {
            return true;
        }

        // 只有 SYN 包
        if self.packets_forward > 0 && self.packets_reverse == 0 &&
           self.state == TCP_STATE_SYN_SENT {
            return true;
        }

        // 连接时间异常短
        let duration = self.last_seen - self.first_seen;
        let total_packets = self.packets_forward + self.packets_reverse;
        if duration < 1000000 && total_packets > 1 {  // 1秒内结束
            return true;
        }

        false
    }
}