//! eBPF Maps 定义
//!
//! 定义所有使用的 eBPF Maps，包括：
//! - TCP 会话表
//! - 扫描器检测表
//! - 统计计数器
//! - 配置参数表

use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruHashMap, LpmTrie, PerCpuArray},
};

// 常量定义
pub const MAX_SESSIONS: u32 = 1_000_000;
pub const MAX_SCANNERS: u32 = 100_000;
pub const SESSION_TIMEOUT_SEC: u64 = 15;
pub const SCANNER_CONFIDENCE_THRESHOLD: u8 = 80;

// 统计计数器索引
pub const STATS_TOTAL_PACKETS: u32 = 0;
pub const STATS_TCP_PACKETS: u32 = 1;
pub const STATS_NEW_SESSIONS: u32 = 2;
pub const STATS_SESSION_TIMEOUT: u32 = 3;
pub const STATS_MALFORMED_PACKETS: u32 = 4;
pub const STATS_SESSION_CREATE_FAILED: u32 = 5;
pub const STATS_SESSION_INSERT_ATTEMPT: u32 = 9;  // 新增：会话插入尝试次数
pub const STATS_SESSION_INSERT_FAILED: u32 = 10; // 新增：会话插入失败次数
pub const STATS_SYN_PACKETS: u32 = 11;          // 新增：检测到的 SYN 包数量
pub const STATS_SYN_ONLY_PACKETS: u32 = 12;      // 新增：纯 SYN 包数量（SYN=1,ACK=0）
pub const STATS_SCANNER_DETECTED: u32 = 6;
pub const STATS_MALICIOUS_SESSIONS: u32 = 7;
pub const STATS_PROCESSING_TIME_NS: u32 = 8;

// TCP 状态常量
pub const TCP_STATE_UNKNOWN: u32 = 0;
pub const TCP_STATE_SYN_SENT: u32 = 1;
pub const TCP_STATE_SYN_RECEIVED: u32 = 2;
pub const TCP_STATE_ESTABLISHED: u32 = 3;
pub const TCP_STATE_FIN_WAIT: u32 = 4;
pub const TCP_STATE_RESET: u32 = 5;

// 动作常量
pub const ACTION_PASS: u8 = 0;
pub const ACTION_DROP: u8 = 1;
pub const ACTION_REDIRECT: u8 = 2;

// 网络协议常量
pub const ETH_P_IP: u16 = 0x0800;
pub const IPPROTO_TCP: u8 = 6;

/// TCP 会话键值（5元组）
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct TcpSessionKey {
    pub src_ip: u32,        // 源 IP 地址（网络字节序）
    pub dst_ip: u32,        // 目的 IP 地址（网络字节序）
    pub src_port: u16,      // 源端口（网络字节序）
    pub dst_port: u16,      // 目的端口（网络字节序）
    pub protocol: u8,       // 协议类型
    pub direction: u8,      // 流向（0: 正向，1: 反向）
    pub _padding: u16,      // 对齐填充
}

impl TcpSessionKey {
    #[inline(always)]
    pub fn new(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            direction: 0,
            _padding: 0,
        }
    }

    /// 获取反向流的键值
    #[inline(always)]
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
            direction: 1,
            _padding: 0,
        }
    }
}

/// TCP 会话状态
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TcpSession {
    pub first_seen: u64,        // 首次 seen 时间
    pub last_seen: u64,         // 最后 seen 时间
    pub packets_forward: u64,   // 正向包数
    pub packets_reverse: u64,   // 反向包数
    pub bytes_forward: u64,     // 正向字节数
    pub bytes_reverse: u64,     // 反向字节数

    pub state: u32,             // TCP 状态
    pub seq_forward: u32,       // 正向期望 seq
    pub seq_reverse: u32,       // 反向期望 seq
    pub flags: u32,             // 会话标志

    pub is_scanner: u8,         // 扫描器标记
    pub action: u8,             // 处理动作
    pub ttl_diff: u8,           // TTL 差异
    pub syn_ratio: u8,          // SYN 包比例
    pub _padding: u32,          // 对齐填充
}

impl TcpSession {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            first_seen: 0,
            last_seen: 0,
            packets_forward: 0,
            packets_reverse: 0,
            bytes_forward: 0,
            bytes_reverse: 0,
            state: TCP_STATE_UNKNOWN,
            seq_forward: 0,
            seq_reverse: 0,
            flags: 0,
            is_scanner: 0,
            action: ACTION_PASS,
            ttl_diff: 0,
            syn_ratio: 0,
            _padding: 0,
        }
    }
}

/// 扫描器检测键值
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct ScannerKey {
    pub src_ip: u32,        // 扫描器 IP
    pub dst_network: u32,   // 目标网络（用于网段扫描检测）
    pub dst_mask: u32,      // 网络掩码
    pub _padding: u32,      // 对齐填充
}

/// 扫描器检测状态
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ScannerState {
    pub first_packet_time: u64,     // 首个包时间
    pub last_packet_time: u64,      // 最后包时间
    pub session_count: u32,         // 会话数量
    pub syn_count: u32,             // SYN 包数量
    pub unique_ports: u32,          // 唯一端口数
    pub ports: [u16; 16],           // 记录访问的端口
    pub scan_type: u8,              // 扫描类型
    pub confidence: u8,             // 置信度
    pub _padding: u16,              // 对齐填充
}

impl ScannerState {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            first_packet_time: 0,
            last_packet_time: 0,
            session_count: 0,
            syn_count: 0,
            unique_ports: 0,
            ports: [0; 16],
            scan_type: 0,
            confidence: 0,
            _padding: 0,
        }
    }

    /// 添加端口到端口列表
    #[inline(always)]
    pub fn add_port(&mut self, port: u16) {
        // 检查端口是否已存在
        for i in 0..16 {
            if self.ports[i] == port {
                return;
            }
            if self.ports[i] == 0 {
                self.ports[i] = port;
                self.unique_ports += 1;
                return;
            }
        }
    }
}

/// 扫描器检测结果
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ScannerResult {
    pub is_scanner: bool,       // 是否为扫描器
    pub scanner_ip: u32,        // 扫描器 IP
    pub scanned_port: u16,      // 被扫描的端口
    pub scan_type: u8,          // 扫描类型
    pub confidence: u8,         // 置信度 (0-100)
}

impl ScannerResult {
    #[inline(always)]
    pub fn not_scanner() -> Self {
        Self {
            is_scanner: false,
            scanner_ip: 0,
            scanned_port: 0,
            scan_type: 0,
            confidence: 0,
        }
    }
}

/// 数据包信息
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PacketInfo {
    pub src_ip: u32,            // 源 IP
    pub dst_ip: u32,            // 目的 IP
    pub src_port: u16,          // 源端口
    pub dst_port: u16,          // 目的端口
    pub ip_proto: u8,           // IP 协议
    pub ip_header_len: u8,      // IP 头部长度
    pub _padding: u8,           // 填充
    pub timestamp: u64,         // 时间戳
    pub packet_size: u32,       // 数据包大小
    pub payload_size: u16,      // 负载大小
}

impl Default for PacketInfo {
    fn default() -> Self {
        Self {
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            ip_proto: 0,
            ip_header_len: 20,  // 默认最小 IP 头部长度
            _padding: 0,
            timestamp: 0,
            packet_size: 0,
            payload_size: 0,
        }
    }
}

/// 配置参数结构
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ConfigParams {
    pub max_sessions: u32,          // 最大会话数
    pub session_timeout_sec: u32,   // 会话超时时间
    pub scan_threshold: u32,        // 扫描检测阈值
    pub scan_window_sec: u32,       // 扫描检测时间窗口
    pub enable_logging: u8,         // 启用日志
    pub debug_mode: u8,             // 调试模式
    pub _padding: u16,              // 对齐填充
}

// Per-CPU 统计计数器
#[map]
static mut STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);

// TCP 会话表
#[map]
static mut TCP_SESSIONS: HashMap<TcpSessionKey, TcpSession> = HashMap::with_max_entries(MAX_SESSIONS, 0);

// 扫描器检测表
#[map]
static mut SCANNER_DETECTIONS: HashMap<ScannerKey, ScannerState> = HashMap::with_max_entries(MAX_SCANNERS, 0);

// 会话超时队列
#[map]
static mut TIMEOUT_QUEUE: LruHashMap<u64, TcpSessionKey> = LruHashMap::with_max_entries(MAX_SESSIONS / 5, 0);

// 配置参数表
#[map]
static mut CONFIG: HashMap<u32, ConfigParams> = HashMap::with_max_entries(16, 0);

/// 增加统计计数器
#[inline(always)]
pub fn increment_stats_counter(counter_idx: u32) {
    unsafe {
        if let Some(counter) = STATS.get_ptr_mut(counter_idx) {
            *counter += 1;
        }
    }
}

/// 获取统计计数器值
#[inline(always)]
pub fn get_stats_counter(counter_idx: u32) -> u64 {
    unsafe {
        if let Some(counter) = STATS.get(counter_idx) {
            *counter
        } else {
            0
        }
    }
}

/// 更新处理时间统计
#[inline(always)]
pub fn update_processing_stats(processing_time: u64) {
    unsafe {
        if let Some(counter) = STATS.get_ptr_mut(STATS_PROCESSING_TIME_NS) {
            // 使用移动平均
            *counter = (*counter * 7 + processing_time) / 8;
        }
    }
}

/// 更新决策统计
#[inline(always)]
pub fn update_decision_stats(_action: u32) {
    // 简化实现，暂不记录具体动作
    increment_stats_counter(STATS_TOTAL_PACKETS);
}

// 公共 MAP 访问函数

/// 插入会话到 TCP 会话表
#[inline(always)]
pub fn tcp_sessions_insert(key: &TcpSessionKey, value: &TcpSession) -> Result<(), ()> {
    unsafe {
        match TCP_SESSIONS.insert(key, value, 0) {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

/// 获取 TCP 会话
#[inline(always)]
pub fn tcp_sessions_get(key: &TcpSessionKey) -> Option<&'static TcpSession> {
    unsafe {
        TCP_SESSIONS.get(key)
    }
}

/// 获取 TCP 会话的可变引用
#[inline(always)]
pub fn tcp_sessions_get_mut(key: &TcpSessionKey) -> Option<&'static mut TcpSession> {
    unsafe {
        TCP_SESSIONS.get_ptr_mut(key).map(|p| &mut *p)
    }
}

/// 插入超时队列
#[inline(always)]
pub fn timeout_queue_insert(key: &u64, value: &TcpSessionKey) -> Result<(), ()> {
    unsafe {
        match TIMEOUT_QUEUE.insert(key, value, 0) {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}