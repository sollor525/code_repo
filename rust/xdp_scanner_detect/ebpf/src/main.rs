//! xdp-scanner-detect eBPF 主程序
//!
//! 这是 eBPF 内核程序的入口点，包含：
//! - XDP 程序主要逻辑
//! - 数据包解析和处理
//! - 会话管理和扫描器检测
//! - 性能优化的数据结构

#![no_std]
#![no_main]

use aya_ebpf::{
    macros::xdp,
    programs::XdpContext,
    bindings::xdp_action::{XDP_PASS, XDP_DROP, XDP_ABORTED, XDP_REDIRECT},
};
use aya_ebpf::helpers::bpf_ktime_get_ns;

// 导入模块
mod maps;
mod tcp;
mod scanner;
mod parser;
mod helper;

use maps::*;

/// XDP 程序主入口点
///
/// 处理每个网络数据包的主要逻辑：
/// 1. 解析数据包头部
/// 2. 查找或创建 TCP 会话
/// 3. 执行扫描器检测
/// 4. 做出处理决策
#[xdp]
pub fn xdp_main(ctx: XdpContext) -> u32 {
    // 记录处理开始时间
    let start_time = unsafe { bpf_ktime_get_ns() };

    // 获取数据包指针
    let data = ctx.data() as *mut u8;
    let data_end = ctx.data_end() as *mut u8;

    // 检查数据包大小
    if data >= data_end {
        return XDP_PASS;
    }

    // 增加总包数统计
    increment_stats_counter(STATS_TOTAL_PACKETS);

    // 解析数据包
    let packet_info = match parse_packet(data, data_end) {
        Ok(pkt) => pkt,
        Err(_) => {
            // 无法解析的数据包，直接放行
            increment_stats_counter(STATS_MALFORMED_PACKETS);
            return XDP_PASS;
        }
    };

    // 只处理 TCP 流量
    if packet_info.ip_proto != IPPROTO_TCP {
        return XDP_PASS;
    }

    // 增加 TCP 包数统计
    increment_stats_counter(STATS_TCP_PACKETS);

    // 重新计算 TCP 头部位置
    let ip_header_len = packet_info.ip_header_len as usize;
    let tcp_offset = data as usize + size_of::<parser::ethhdr>() + ip_header_len;

    // 检查 TCP 头部边界
    if tcp_offset + size_of::<parser::tcphdr>() > data_end as usize {
        increment_stats_counter(STATS_MALFORMED_PACKETS);
        return XDP_ABORTED;
    }

    let tcp = unsafe { &*(tcp_offset as *const parser::tcphdr) };

    // 提取五元组信息
    let mut session_key = TcpSessionKey::new(
        packet_info.src_ip,
        packet_info.dst_ip,
        packet_info.src_port,
        packet_info.dst_port,
        packet_info.ip_proto,
    );

    // 查找或创建 TCP 会话
    let session = match lookup_or_create_session(&mut session_key, tcp, packet_info.timestamp) {
        Ok(session) => session,
        Err(_) => {
            // 会话创建失败，可能是资源不足
            increment_stats_counter(STATS_SESSION_CREATE_FAILED);
            return XDP_PASS;
        }
    };

    // 更新会话统计信息
    update_session_stats(session, &packet_info, tcp);

    // 执行扫描器检测
    let scanner_result = detect_scanner(&session_key, session, tcp, packet_info.timestamp);

    // 根据扫描器检测结果和会话状态做出决策
    let action = make_packet_decision(session, scanner_result, tcp);

    // 更新统计信息
    update_decision_stats(action);

    // 记录处理时间（用于性能监控）
    let processing_time = unsafe { bpf_ktime_get_ns() } - start_time;
    update_processing_stats(processing_time);

    // 返回相应的 XDP 动作
    action
}

/// 解析网络数据包
///
/// 从原始数据包中提取以太网、IP 和 TCP 头部信息
#[inline(always)]
fn parse_packet(data: *mut u8, data_end: *mut u8) -> Result<PacketInfo, u32> {
    let mut pkt_info = PacketInfo::default();

    // 解析以太网头部
    let eth = data as *const parser::ethhdr;
    if (data as usize + size_of::<parser::ethhdr>()) > data_end as usize {
        return Err(XDP_ABORTED);
    }

    // 检查以太网类型
    let eth_hdr = unsafe { &*eth };
    if u16::from_be(eth_hdr.h_proto) != ETH_P_IP {
        return Err(XDP_PASS);  // 只处理 IPv4
    }

    // 解析 IP 头部
    let ip = unsafe { (data as *const parser::ethhdr).add(1) as *const parser::iphdr };
    if (data as usize + size_of::<parser::ethhdr>() + size_of::<parser::iphdr>()) > data_end as usize {
        return Err(XDP_ABORTED);
    }

    // 检查 IP 协议
    let ip_hdr = unsafe { &*ip };
    if ip_hdr.protocol != IPPROTO_TCP {
        return Err(XDP_PASS);  // 只处理 TCP
    }

    // 获取 IP 头部长度
    let ip_header_len = (ip_hdr.ihl()) as usize;

    // 先检查 TCP 头部起始位置是否有效（最小 TCP 头部 20 字节）
    let tcp_offset = data as usize + size_of::<parser::ethhdr>() + ip_header_len;
    if tcp_offset + size_of::<parser::tcphdr>() > data_end as usize {
        return Err(XDP_ABORTED);
    }

    // 解析 TCP 头部
    let tcp = unsafe { &*(tcp_offset as *const parser::tcphdr) };

    // 检查完整 TCP 头部是否有效
    let tcp_header_len = (tcp.doff()) as usize;
    if tcp_offset + tcp_header_len > data_end as usize {
        return Err(XDP_ABORTED);
    }

    // 填充数据包信息（保持网络字节序用于会话 key）
    pkt_info.src_ip = ip_hdr.saddr;
    pkt_info.dst_ip = ip_hdr.daddr;
    pkt_info.src_port = tcp.source;  // 保持网络字节序
    pkt_info.dst_port = tcp.dest;    // 保持网络字节序
    pkt_info.ip_proto = ip_hdr.protocol;
    pkt_info.ip_header_len = ip_header_len as u8;  // 保存 IP 头部长度
    pkt_info.timestamp = unsafe { bpf_ktime_get_ns() };
    pkt_info.packet_size = (u16::from_be(ip_hdr.tot_len)) as u32;

    // 计算负载大小
    let total_len = u16::from_be(ip_hdr.tot_len) as u16;
    let header_len = (ip_header_len + tcp_header_len) as u16;
    if total_len > header_len {
        pkt_info.payload_size = total_len - header_len;
    }

    Ok(pkt_info)
}

/// 查找或创建 TCP 会话
///
/// 基于五元组查找现有会话，如果不存在则创建新会话
#[inline(always)]
fn lookup_or_create_session(
    session_key: &mut TcpSessionKey,
    tcp: &parser::tcphdr,
    timestamp: u64,
) -> Result<*mut TcpSession, u32> {
    // 查找现有会话
    if let Some(session) = tcp_sessions_get_mut(session_key) {
        // 更新会话的最后活跃时间
        session.last_seen = timestamp;
        return Ok(session);
    }

    // 尝试反向查找（处理响应包）
    let reverse_key = session_key.reverse();
    if let Some(session) = tcp_sessions_get_mut(&reverse_key) {
        // 找到反向会话，更新并返回
        session.last_seen = timestamp;
        return Ok(session);
    }

    // 新会话创建（只对 SYN 包）
    // 调试：检查原始标志值
    let raw_flags = tcp.flags_value();  // 获取完整的 8 位标志
    let syn_flag = tcp.syn() != 0;
    let ack_flag = tcp.ack() != 0;

    // 统计：检测到的 SYN 包
    if syn_flag {
        increment_stats_counter(STATS_SYN_PACKETS);
        // 统计：纯 SYN 包（没有 ACK）
        if !ack_flag {
            increment_stats_counter(STATS_SYN_ONLY_PACKETS);
            // 找到纯 SYN 包，尝试创建会话
            return create_new_session(session_key, timestamp);
        }
    }

    // 对于非 SYN 包且没有现有会话的情况，返回错误
    Err(XDP_PASS)
}

/// 创建新的 TCP 会话
///
/// 初始化会话状态并插入到会话表中
#[inline(always)]
fn create_new_session(
    session_key: &TcpSessionKey,
    timestamp: u64,
) -> Result<*mut TcpSession, u32> {
    // 记录插入尝试
    increment_stats_counter(STATS_SESSION_INSERT_ATTEMPT);

    // 创建新会话
    let session = TcpSession {
        first_seen: timestamp,
        last_seen: timestamp,
        state: TCP_STATE_SYN_SENT,
        ..TcpSession::new()
    };

    // 插入会话到 map
    if tcp_sessions_insert(session_key, &session).is_err() {
        increment_stats_counter(STATS_SESSION_INSERT_FAILED);
        return Err(XDP_DROP);
    }

    // 获取插入的会话指针
    if let Some(session_ptr) = tcp_sessions_get_mut(session_key) {
        // 添加到超时队列
        add_to_timeout_queue(session_key, timestamp);

        // 更新会话计数
        increment_stats_counter(STATS_NEW_SESSIONS);

        return Ok(session_ptr);
    }

    Err(XDP_DROP)
}

/// 更新会话统计信息
///
/// 更新包计数、字节数和序列号跟踪
#[inline(always)]
fn update_session_stats(session: *mut TcpSession, packet_info: &PacketInfo, tcp: &parser::tcphdr) {
    if session.is_null() {
        return;
    }

    unsafe {
        let session = &mut *session;

        // 更新时间戳
        session.last_seen = packet_info.timestamp;

        // 获取 TCP 标志
        let seq = u32::from_be(tcp.seq);
        let ack = u32::from_be(tcp.ack_seq);

        // 简单的方向判断：这里简化处理
        session.packets_forward += 1;
        session.bytes_forward += packet_info.payload_size as u64;

        // 更新连接状态
        session.state = determine_tcp_state(tcp);
    }
}

/// 确定 TCP 连接状态
///
/// 根据 TCP 标志位确定连接的当前状态
#[inline(always)]
fn determine_tcp_state(tcp: &parser::tcphdr) -> u32 {
    if tcp.syn() != 0 && tcp.ack() == 0 {
        TCP_STATE_SYN_SENT
    } else if tcp.syn() != 0 && tcp.ack() != 0 {
        TCP_STATE_SYN_RECEIVED
    } else if tcp.fin() != 0 {
        TCP_STATE_FIN_WAIT
    } else if tcp.rst() != 0 {
        TCP_STATE_RESET
    } else {
        TCP_STATE_ESTABLISHED
    }
}

/// 做出数据包处理决策
///
/// 基于会话状态和扫描器检测结果决定如何处理数据包
#[inline(always)]
fn make_packet_decision(
    session: *mut TcpSession,
    scanner_result: ScannerResult,
    _tcp: &parser::tcphdr,
) -> u32 {
    // 扫描器检测有高置信度
    if scanner_result.confidence > SCANNER_CONFIDENCE_THRESHOLD {
        increment_stats_counter(STATS_SCANNER_DETECTED);
        return XDP_DROP;  // 丢弃扫描流量
    }

    // 检查会话状态
    if !session.is_null() {
        unsafe {
            let session = &*session;

            // 如果会话被标记为恶意
            if session.is_scanner != 0 {
                increment_stats_counter(STATS_MALICIOUS_SESSIONS);
                return XDP_DROP;
            }

            // 检查会话动作
            match session.action {
                ACTION_DROP => return XDP_DROP,
                ACTION_REDIRECT => return XDP_REDIRECT,
                _ => return XDP_PASS,
            }
        }
    }

    // 默认放行
    XDP_PASS
}

/// 添加会话到超时队列
///
/// 用于会话超时清理机制
#[inline(always)]
fn add_to_timeout_queue(session_key: &TcpSessionKey, timestamp: u64) {
    let timeout_key = timestamp + (SESSION_TIMEOUT_SEC * 1_000_000_000);
    let _ = timeout_queue_insert(&timeout_key, session_key);
}

/// 扫描器检测函数（简化版本）
#[inline(always)]
fn detect_scanner(
    _session_key: &TcpSessionKey,
    _session: *mut TcpSession,
    _tcp: &parser::tcphdr,
    _timestamp: u64,
) -> ScannerResult {
    // 简化实现：暂时不进行扫描检测
    ScannerResult::not_scanner()
}

#[cfg(not(test))]
/// Panic 处理器
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}