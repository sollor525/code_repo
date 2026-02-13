//! 扫描器检测模块
//!
//! 实现各种扫描器检测算法，包括：
//! - 端口扫描检测
//! - SYN flood 检测
//! - 连接频率分析
//! - 扫描器指纹识别

use crate::maps::*;
use crate::parser::*;
use aya_ebpf::helpers::bpf_ktime_get_ns;

/// 扫描器检测器
pub struct ScannerDetector;

/// 扫描器类型
pub const SCAN_TYPE_UNKNOWN: u8 = 0;
pub const SCAN_TYPE_TCP_CONNECT: u8 = 1;      // TCP connect 扫描
pub const SCAN_TYPE_TCP_SYN: u8 = 2;          // SYN 扫描
pub const SCAN_TYPE_TCP_FIN: u8 = 3;          // FIN 扫描
pub const SCAN_TYPE_TCP_NULL: u8 = 4;         // NULL 扫描
pub const SCAN_TYPE_TCP_XMAS: u8 = 5;         // XMAS 扫描
pub const SCAN_TYPE_TCP_MAIMON: u8 = 6;       // Maimon 扫描
pub const SCAN_TYPE_TCP_WINDOW: u8 = 7;       // Window 扫描
pub const SCAN_TYPE_TCP_ACK: u8 = 8;          // ACK 扫描
pub const SCAN_TYPE_UDP: u8 = 9;              // UDP 扫描

/// 扫描检测参数
const SCAN_TIME_WINDOW: u64 = 60 * 1_000_000_000;  // 60秒时间窗口
const PORT_SCAN_THRESHOLD: u32 = 10;                // 端口扫描阈值
const SYN_FLOOD_THRESHOLD: u32 = 100;              // SYN flood 阈值
const CONNECTION_RATE_THRESHOLD: u32 = 50;          // 连接速率阈值

impl ScannerDetector {
    /// 检测端口扫描
    #[inline(always)]
    pub fn detect_port_scan(_state: &ScannerState) -> bool {
        // 简化实现：检查端口数量
        false
    }

    /// 检测 SYN 扫描
    #[inline(always)]
    pub fn detect_syn_scan(_state: &ScannerState, _tcp: &tcphdr) -> bool {
        // 简化实现
        false
    }

    /// 检测隐蔽扫描
    #[inline(always)]
    pub fn detect_stealth_scan(tcp: &tcphdr) -> bool {
        let flags = tcp.flags_value();

        // NULL 扫描：所有标志位都为 0
        if flags == 0 {
            return true;
        }

        // XMAS 扫描：FIN, PSH, URG 都设置
        if (flags & (tcphdr::FIN_FLAG | tcphdr::PSH_FLAG | tcphdr::URG_FLAG) as u8) ==
           (tcphdr::FIN_FLAG | tcphdr::PSH_FLAG | tcphdr::URG_FLAG) as u8 {
            return true;
        }

        // FIN 扫描：只有 FIN 标志
        if flags == tcphdr::FIN_FLAG as u8 {
            return true;
        }

        // Maimon 扫描：FIN/ACK 标志
        if flags == (tcphdr::FIN_FLAG | tcphdr::ACK_FLAG) as u8 {
            return true;
        }

        false
    }

    /// 识别隐蔽扫描类型
    #[inline(always)]
    pub fn identify_stealth_scan_type(tcp: &tcphdr) -> u8 {
        let flags = tcp.flags_value();

        match flags {
            0 => SCAN_TYPE_TCP_NULL,
            f if f == (tcphdr::FIN_FLAG | tcphdr::PSH_FLAG | tcphdr::URG_FLAG) as u8 => SCAN_TYPE_TCP_XMAS,
            f if f == tcphdr::FIN_FLAG as u8 => SCAN_TYPE_TCP_FIN,
            f if f == (tcphdr::FIN_FLAG | tcphdr::ACK_FLAG) as u8 => SCAN_TYPE_TCP_MAIMON,
            _ => SCAN_TYPE_UNKNOWN,
        }
    }

    /// 检测 SYN flood 攻击
    #[inline(always)]
    pub fn detect_syn_flood(_state: &ScannerState, _current_time: u64) -> bool {
        // 简化实现
        false
    }

    /// 计算扫描置信度
    #[inline(always)]
    pub fn calculate_scan_confidence(state: &ScannerState) -> u8 {
        let mut confidence = 0u8;

        // 基于端口数量
        if state.unique_ports >= 20 {
            confidence += 40;
        } else if state.unique_ports >= 10 {
            confidence += 25;
        } else if state.unique_ports >= 5 {
            confidence += 10;
        }

        // 基于 SYN 比例
        if state.session_count > 0 {
            let syn_ratio = (state.syn_count * 100) / state.session_count;
            if syn_ratio >= 80 {
                confidence += 30;
            } else if syn_ratio >= 60 {
                confidence += 20;
            } else if syn_ratio >= 40 {
                confidence += 10;
            }
        }

        // 基于会话与端口比例
        if state.unique_ports > 0 {
            let session_ratio = state.session_count / state.unique_ports;
            if session_ratio <= 2 {
                confidence += 30;
            } else if session_ratio <= 4 {
                confidence += 15;
            }
        }

        confidence.min(100)
    }

    /// 检测连接频率异常
    #[inline(always)]
    pub fn detect_connection_anomaly(
        _session_key: &TcpSessionKey,
        session: &TcpSession,
        _current_time: u64,
    ) -> bool {
        // 检查连接建立频率
        let session_duration = session.last_seen - session.first_seen;
        let total_packets = session.packets_forward + session.packets_reverse;

        // 异常短时间的连接
        if session_duration < 100_000_000 && total_packets > 10 {  // 100ms内超过10个包
            return true;
        }

        // 检查非对称连接
        if session.packets_forward == 0 || session.packets_reverse == 0 {
            return true;
        }

        // 检查异常的包大小模式
        if session.bytes_forward > 0 && session.packets_forward > 0 {
            let avg_packet_size = session.bytes_forward / session.packets_forward;
            // SYN 扫描通常只有小包
            if avg_packet_size < 100 && total_packets > 20 {
                return true;
            }
        }

        false
    }

    /// 检测扫描器指纹
    #[inline(always)]
    pub fn detect_scanner_fingerprint(tcp: &tcphdr) -> bool {
        // 检查窗口大小
        let window = u16::from_be(tcp.window);

        // 常见扫描工具的窗口大小特征
        match window {
            1024 | 2048 | 3072 | 4096 | 8192 | 16384 | 32768 | 65535 => {
                // 这些是常见扫描工具使用的窗口大小
                return true;
            },
            _ => {},
        }

        false
    }
}

impl ScannerState {
    /// 计算扫描速率
    #[inline(always)]
    pub fn calculate_scan_rate(&self) -> u32 {
        let duration = self.last_packet_time - self.first_packet_time;

        if duration == 0 {
            return 0;
        }

        // 计算每秒扫描端口数
        ((self.unique_ports as u64 * 1_000_000_000) / duration) as u32
    }

    /// 检查是否为活跃扫描器
    #[inline(always)]
    pub fn is_active_scanner(&self) -> bool {
        let current_time = unsafe { bpf_ktime_get_ns() };
        let last_seen_age = current_time - self.last_packet_time;

        // 60秒内有活动认为是活跃的
        last_seen_age < (60 * 1_000_000_000)
    }

    /// 获取扫描器类型
    #[inline(always)]
    pub fn get_scan_type(&self) -> u8 {
        if self.session_count > 0 && (self.syn_count * 100) / self.session_count >= 70 {
            SCAN_TYPE_TCP_SYN
        } else if self.unique_ports >= PORT_SCAN_THRESHOLD {
            SCAN_TYPE_TCP_CONNECT
        } else {
            SCAN_TYPE_UNKNOWN
        }
    }
}