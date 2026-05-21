//! 端到端集成测试
//!
//! 自行构造 PCAP 字节流，走完整的 `PcapReader -> PacketParser ->
//! StreamManager` 流水线，验证三次握手判定与 RST 重置判定。
//!
//! 这些用例覆盖了 `docs/BUGFIXES.md` 中修复的核心缺陷：
//! BUG-1（established_time）、BUG-2（close.reset 与日志开关解耦）、
//! BUG-3（四次挥手 FIN）、BUG-4（握手计时）、BUG-5（状态机中间态）、
//! BUG-6（报文计数）、BUG-7（PCAP 字节序）、BUG-8（乱序时间戳不 panic）。

use std::path::Path;

use pcap_steam_anylizer::pcap::{PcapReader, PacketParser};
use pcap_steam_anylizer::stream::{StreamManager, StreamManagerConfig};
use pcap_steam_anylizer::types::stream::{BlockingMode, HijackConfidence, TcpState, TcpStream};
use pcap_steam_anylizer::types::PacketInfo;
use tempfile::NamedTempFile;

// ---- TCP 标志位常量 ----
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

const CLIENT: [u8; 4] = [192, 168, 1, 100];
const SERVER: [u8; 4] = [192, 168, 1, 200];
const CLIENT_PORT: u16 = 40000;
const SERVER_PORT: u16 = 80;

/// 构造一个 以太网 + IPv4 + TCP 报文（无 IP/TCP 选项），可指定 TTL 与 IP identification。
fn build_packet_ext(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    ttl: u8,
    ip_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut p = Vec::with_capacity(54 + payload.len());

    // --- 以太网头（14 字节）---
    p.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // 目的 MAC
    p.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // 源 MAC
    p.extend_from_slice(&[0x08, 0x00]); // EtherType = IPv4

    // --- IPv4 头（20 字节）---
    let total_len = (20 + 20 + payload.len()) as u16;
    p.push(0x45); // version=4, IHL=5
    p.push(0x00); // DSCP/ECN
    p.extend_from_slice(&total_len.to_be_bytes());
    p.extend_from_slice(&ip_id.to_be_bytes()); // identification
    p.extend_from_slice(&[0x40, 0x00]); // flags=DF, fragment offset=0
    p.push(ttl); // TTL
    p.push(6); // protocol = TCP
    p.extend_from_slice(&[0x00, 0x00]); // header checksum（测试中不校验）
    p.extend_from_slice(&src_ip);
    p.extend_from_slice(&dst_ip);

    // --- TCP 头（20 字节）---
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ack.to_be_bytes());
    p.push(0x50); // data offset = 5（20 字节），保留位 0
    p.push(flags);
    p.extend_from_slice(&window.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]); // checksum
    p.extend_from_slice(&[0x00, 0x00]); // urgent pointer

    // --- 负载 ---
    p.extend_from_slice(payload);
    p
}

/// 构造一个普通报文（TTL=64，IP identification=0）。
fn build_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    build_packet_ext(
        src_ip, dst_ip, sport, dport, seq, ack, flags, window, 64, 0x0000, payload,
    )
}

/// 把若干 (时间戳微秒, 报文字节) 写成一个 PCAP 文件。
/// `big_endian` 控制 PCAP 文件本身的字节序。
fn write_pcap(path: &Path, packets: &[(u64, Vec<u8>)], big_endian: bool) {
    let mut f = Vec::new();

    let put_u32 = |f: &mut Vec<u8>, v: u32| {
        if big_endian {
            f.extend_from_slice(&v.to_be_bytes());
        } else {
            f.extend_from_slice(&v.to_le_bytes());
        }
    };
    let put_u16 = |f: &mut Vec<u8>, v: u16| {
        if big_endian {
            f.extend_from_slice(&v.to_be_bytes());
        } else {
            f.extend_from_slice(&v.to_le_bytes());
        }
    };

    // 全局头（24 字节）
    put_u32(&mut f, 0xA1B2C3D4); // 微秒精度 magic
    put_u16(&mut f, 2); // major
    put_u16(&mut f, 4); // minor
    put_u32(&mut f, 0); // thiszone
    put_u32(&mut f, 0); // sigfigs
    put_u32(&mut f, 65535); // snaplen
    put_u32(&mut f, 1); // linktype = Ethernet

    // 各报文记录
    for (ts, data) in packets {
        put_u32(&mut f, (*ts / 1_000_000) as u32); // ts_sec
        put_u32(&mut f, (*ts % 1_000_000) as u32); // ts_usec
        put_u32(&mut f, data.len() as u32); // caplen
        put_u32(&mut f, data.len() as u32); // origlen
        f.extend_from_slice(data);
    }

    std::fs::write(path, f).unwrap();
}

fn test_config() -> StreamManagerConfig {
    StreamManagerConfig::default()
}

/// 走完整流水线分析一组报文，返回所有重建出的 TCP 流。
fn analyze(packets: &[(u64, Vec<u8>)], big_endian: bool) -> Vec<TcpStream> {
    let tmp = NamedTempFile::new().unwrap();
    write_pcap(tmp.path(), packets, big_endian);

    let reader = PcapReader::open(tmp.path()).expect("PCAP 应能打开");
    let linktype = reader.global_header().linktype;
    let parser = PacketParser::new(false, false, linktype);

    let mut manager = StreamManager::new(test_config());
    for packet_result in reader {
        let raw = packet_result.expect("读取报文不应出错");
        let parsed = parser.parse(raw).expect("报文应能解析");
        let info: PacketInfo = parsed.into();
        manager.process_packet(&info);
    }

    manager.get_all_streams().cloned().collect()
}

/// 便捷构造：客户端 -> 服务器 报文。
fn c2s(seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    build_packet(
        CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, seq, ack, flags, 64240, payload,
    )
}

/// 便捷构造：服务器 -> 客户端 报文。
fn s2c(seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    build_packet(
        SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, seq, ack, flags, 64240, payload,
    )
}

/// 便捷构造：模拟 NPatch 朝客户端注入的报文。
/// 带 NPatch 签名：TCP 窗口 888、IPv4 TTL 60、identification 0x8866。
fn npatch_pkt(seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    build_packet_ext(
        SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, seq, ack, flags, 888, 60, 0x8866, payload,
    )
}

/// 用指定阻断验证模式分析一组报文。
fn analyze_verify(packets: &[(u64, Vec<u8>)], mode: BlockingMode) -> Vec<TcpStream> {
    let tmp = NamedTempFile::new().unwrap();
    write_pcap(tmp.path(), packets, false);

    let reader = PcapReader::open(tmp.path()).expect("PCAP 应能打开");
    let linktype = reader.global_header().linktype;
    let parser = PacketParser::new(false, false, linktype);

    let config = StreamManagerConfig {
        verify_blocking: Some(mode),
        ..test_config()
    };
    let mut manager = StreamManager::new(config);
    for packet_result in reader {
        let raw = packet_result.expect("读取报文不应出错");
        let parsed = parser.parse(raw).expect("报文应能解析");
        let info: PacketInfo = parsed.into();
        manager.process_packet(&info);
    }
    manager.get_all_streams().cloned().collect()
}

// =============================================================
// 测试用例
// =============================================================

/// 完整三次握手后保持 ESTABLISHED：握手完成、状态正确、建立时间与握手耗时被记录。
#[test]
fn test_full_handshake_established() {
    let packets = vec![
        (1_000_000, c2s(100, 0, SYN, &[])),       // SYN
        (1_000_200, s2c(500, 101, SYN | ACK, &[])), // SYN-ACK
        (1_000_350, c2s(101, 501, ACK, &[])),     // ACK（握手完成）
    ];
    let streams = analyze(&packets, false);
    assert_eq!(streams.len(), 1, "应只识别出一条流");
    let s = &streams[0];

    assert!(
        s.connection.handshake.is_complete(),
        "完整三次握手应判定为完成"
    );
    assert_eq!(s.state, TcpState::Established, "握手完成后状态应为 ESTABLISHED");
    assert!(
        s.connection.established_time.is_some(),
        "BUG-1：连接建立时间应被记录"
    );
    assert!(
        s.connection.handshake.duration_ms().is_some(),
        "BUG-4：握手耗时应被记录"
    );
    // 握手从 1.000000s 到 1.000350s，耗时 350µs = 0.35ms
    let dur = s.connection.handshake.duration_ms().unwrap();
    assert!((dur - 0.35).abs() < 1e-6, "握手耗时应约为 0.35ms，实际 {dur}");
    assert!(!s.connection.close.reset, "未发生 RST，close.reset 应为 false");
}

/// SYN -> SYN-ACK 之后没有第三个 ACK：握手未完成，状态停在 SYN_RECEIVED。
#[test]
fn test_handshake_incomplete_no_final_ack() {
    let packets = vec![
        (2_000_000, c2s(100, 0, SYN, &[])),
        (2_000_200, s2c(500, 101, SYN | ACK, &[])),
    ];
    let streams = analyze(&packets, false);
    let s = &streams[0];

    assert!(
        !s.connection.handshake.is_complete(),
        "缺少第三个 ACK，握手不应判定为完成"
    );
    // BUG-5：收到 SYN-ACK 不应提前跳到 ESTABLISHED
    assert_eq!(
        s.state,
        TcpState::SynReceived,
        "BUG-5：仅收到 SYN-ACK 时状态应为 SYN_RECEIVED 而非 ESTABLISHED"
    );
}

/// 只有一个 SYN：握手未完成，状态为 SYN_SENT。
#[test]
fn test_handshake_only_syn() {
    let packets = vec![(3_000_000, c2s(100, 0, SYN, &[]))];
    let streams = analyze(&packets, false);
    let s = &streams[0];

    assert!(!s.connection.handshake.is_complete());
    assert_eq!(s.state, TcpState::SynSent);
    assert!(s.connection.handshake.client_syn);
    assert!(!s.connection.handshake.server_syn_ack);
}

/// 握手未完成即被 RST 重置：握手判定为「未完成」，且能识别出异常重置。
#[test]
fn test_reset_before_handshake_complete() {
    let packets = vec![
        (4_000_000, c2s(100, 0, SYN, &[])),
        (4_000_200, s2c(500, 101, SYN | ACK, &[])),
        (4_000_300, s2c(501, 101, RST | ACK, &[])), // 服务器 RST，握手未完成
    ];
    let streams = analyze(&packets, false);
    let s = &streams[0];

    assert!(
        !s.connection.handshake.is_complete(),
        "握手未完成时被 RST，应判定握手未完成"
    );
    assert_eq!(s.state, TcpState::Reset, "应识别为 RESET 状态");
    assert!(
        s.connection.close.reset,
        "BUG-2：即便关闭事件日志，close.reset 也应被置位"
    );
    assert!(
        !s.connection.close.is_graceful(),
        "RST 重置不属于正常关闭"
    );
    assert!(s.rst_time.is_some(), "RST 时间应被记录");
}

/// 完整三次握手之后被 RST 异常重置：握手判定为「完成」，同时识别出异常重置。
#[test]
fn test_reset_after_handshake_complete() {
    let packets = vec![
        (5_000_000, c2s(100, 0, SYN, &[])),
        (5_000_200, s2c(500, 101, SYN | ACK, &[])),
        (5_000_350, c2s(101, 501, ACK, &[])),
        (5_000_500, c2s(101, 501, PSH | ACK, b"GET / HTTP/1.1\r\n\r\n")),
        (5_000_700, s2c(501, 119, RST, &[])), // 服务器异常重置
    ];
    let streams = analyze(&packets, false);
    let s = &streams[0];

    assert!(
        s.connection.handshake.is_complete(),
        "三次握手已完成，应判定为完成"
    );
    assert_eq!(s.state, TcpState::Reset);
    assert!(s.connection.close.reset, "应识别出 RST 重置");
    assert!(!s.connection.close.is_graceful());
    // 客户端发了 18 字节的请求负载
    assert_eq!(s.stats.byte_count, 18, "负载字节数应被正确统计");
}

/// 正常四次挥手关闭：close.client_fin / server_fin 都应被记录，判定为优雅关闭。
#[test]
fn test_graceful_four_way_close() {
    let packets = vec![
        (6_000_000, c2s(100, 0, SYN, &[])),
        (6_000_200, s2c(500, 101, SYN | ACK, &[])),
        (6_000_350, c2s(101, 501, ACK, &[])),
        (6_000_500, c2s(101, 501, PSH | ACK, b"hello")),
        (6_000_700, s2c(501, 106, PSH | ACK, b"hi")),
        (6_000_900, c2s(106, 503, FIN | ACK, &[])), // 客户端 FIN
        (6_001_000, s2c(503, 107, ACK, &[])),       // 服务器 ACK
        (6_001_100, s2c(503, 107, FIN | ACK, &[])), // 服务器 FIN
        (6_001_200, c2s(107, 504, ACK, &[])),       // 客户端 ACK
    ];
    let streams = analyze(&packets, false);
    let s = &streams[0];

    assert!(s.connection.handshake.is_complete());
    assert!(
        s.connection.close.client_fin,
        "BUG-3：客户端 FIN 应被记录"
    );
    assert!(
        s.connection.close.server_fin,
        "BUG-3：服务器 FIN 应被记录"
    );
    assert!(
        s.connection.close.is_graceful(),
        "双向 FIN 且无 RST，应判定为优雅关闭"
    );
    assert!(
        s.connection.close.is_complete(),
        "四次挥手完成，close 应为 complete"
    );
    assert!(!s.connection.close.reset);
    assert_eq!(s.state, TcpState::TimeWait, "正常关闭后应进入 TIME_WAIT");
}

/// 报文计数应等于流的全部报文数（BUG-6：RST 之后的报文不再被静默丢弃）。
#[test]
fn test_packet_count_includes_packets_after_rst() {
    let packets = vec![
        (7_000_000, c2s(100, 0, SYN, &[])),
        (7_000_200, s2c(500, 101, SYN | ACK, &[])),
        (7_000_350, c2s(101, 501, ACK, &[])),
        (7_000_500, s2c(501, 101, RST, &[])), // 第一个 RST
        (7_000_600, s2c(501, 101, RST, &[])), // RST 之后的报文
        (7_000_700, c2s(101, 501, RST, &[])), // RST 之后的报文
    ];
    let streams = analyze(&packets, false);
    let s = &streams[0];

    assert_eq!(
        s.stats.packet_count, 6,
        "BUG-6：流的报文总数应包含 RST 之后的全部报文"
    );
    assert_eq!(s.state, TcpState::Reset);
    assert!(s.connection.close.reset);
}

/// 大端字节序的 PCAP 文件应能被正确读取（BUG-7）。
#[test]
fn test_big_endian_pcap_is_read_correctly() {
    let packets = vec![
        (8_000_000, c2s(100, 0, SYN, &[])),
        (8_000_200, s2c(500, 101, SYN | ACK, &[])),
        (8_000_350, c2s(101, 501, ACK, &[])),
    ];
    // big_endian = true：以大端写出整个 PCAP 文件
    let streams = analyze(&packets, true);
    assert_eq!(streams.len(), 1, "BUG-7：大端 PCAP 应能被正确解析出流");
    let s = &streams[0];
    assert!(s.connection.handshake.is_complete());
    assert_eq!(s.stats.packet_count, 3);
    // 时间戳也应被正确解析（首包 8.0s）
    assert_eq!(s.stats.first_packet_time, Some(8_000_000));
}

/// 报文时间戳乱序时不应 panic（BUG-8）。
#[test]
fn test_out_of_order_timestamps_do_not_panic() {
    // 第 3、4 个报文的时间戳比前一个更早
    let packets = vec![
        (9_000_500, c2s(100, 0, SYN, &[])),
        (9_000_400, s2c(500, 101, SYN | ACK, &[])),
        (9_000_300, c2s(101, 501, ACK, &[])),
        (9_000_100, c2s(101, 501, PSH | ACK, b"data")),
    ];
    // 关键在于：处理过程不会因为 last < first 的减法而下溢 panic
    let streams = analyze(&packets, false);
    let s = &streams[0];
    assert_eq!(s.stats.packet_count, 4);
    // duration 用 saturating_sub，结果非负即可
    assert!(s.stats.duration().is_some());
}

/// 双向报文应归并到同一条流（FlowKey 方向归一化）。
#[test]
fn test_bidirectional_packets_form_single_flow() {
    let packets = vec![
        (10_000_000, c2s(100, 0, SYN, &[])),
        (10_000_200, s2c(500, 101, SYN | ACK, &[])),
        (10_000_350, c2s(101, 501, ACK, &[])),
    ];
    let streams = analyze(&packets, false);
    assert_eq!(streams.len(), 1, "同一连接的双向报文应归并为一条流");
    let s = &streams[0];
    // 客户端方向应是真正发起 SYN 的一方
    assert_eq!(s.client_port(), CLIENT_PORT);
    assert_eq!(s.server_port(), SERVER_PORT);
    assert_eq!(s.stats.c2s_packet_count, 2);
    assert_eq!(s.stats.s2c_packet_count, 1);
}

/// 对仓库内自带的真实样本做冒烟测试：握手完成 + RST 重置。
#[test]
fn test_real_sample_ack_rest_pcap() {
    let path = Path::new("pcap_file/ack_rest.pcap");
    if !path.exists() {
        // 样本文件缺失时跳过（不影响其他用例）
        return;
    }

    let reader = PcapReader::open(path).expect("样本 PCAP 应能打开");
    let linktype = reader.global_header().linktype;
    let parser = PacketParser::new(false, false, linktype);
    let mut manager = StreamManager::new(test_config());

    for pr in reader {
        if let Ok(raw) = pr {
            if let Ok(parsed) = parser.parse(raw) {
                let info: PacketInfo = parsed.into();
                manager.process_packet(&info);
            }
        }
    }

    let streams: Vec<_> = manager.get_all_streams().collect();
    assert_eq!(streams.len(), 1, "ack_rest.pcap 应只含一条流");
    let s = streams[0];
    assert!(
        s.connection.handshake.is_complete(),
        "ack_rest.pcap 的连接完成了三次握手"
    );
    assert_eq!(s.state, TcpState::Reset, "ack_rest.pcap 的连接被 RST 重置");
    assert!(s.connection.close.reset);
    assert_eq!(s.stats.packet_count, 6, "ack_rest.pcap 共有 6 个报文");
}

// =============================================================
// NPatch 阻断验证模式测试
// =============================================================

/// SYN 阻断成功：握手完成前收到 NPatch RST(win888)。
#[test]
fn test_verify_syn_blocked() {
    let packets = vec![
        (20_000_000, c2s(100, 0, SYN, &[])),
        (20_000_200, s2c(500, 101, SYN | ACK, &[])),
        (20_000_300, npatch_pkt(501, 101, RST | ACK, &[])), // NPatch 注入 RST
    ];
    let streams = analyze_verify(&packets, BlockingMode::Syn);
    let s = &streams[0];
    assert!(s.verification.blocked, "SYN 阻断应判定为已阻断");
    assert!(s.verification.reason.contains("SYN 阻断"));
    assert_eq!(s.verification.matched_window, Some(888));
    assert_eq!(s.verification.matched_to_client, Some(true));
    assert!(!s.connection.handshake.is_complete(), "SYN 阻断时握手不应完成");
}

/// SYN 阻断未生效：连接正常完成三次握手。
#[test]
fn test_verify_syn_not_blocked() {
    let packets = vec![
        (21_000_000, c2s(100, 0, SYN, &[])),
        (21_000_200, s2c(500, 101, SYN | ACK, &[])),
        (21_000_350, c2s(101, 501, ACK, &[])),
        (21_000_500, c2s(101, 501, PSH | ACK, b"hello")),
    ];
    let streams = analyze_verify(&packets, BlockingMode::Syn);
    let s = &streams[0];
    assert!(!s.verification.blocked, "握手已完成，SYN 阻断应判定为未阻断");
}

/// ACK 阻断成功：三次握手完成后收到 NPatch RST(win888)。
#[test]
fn test_verify_ack_blocked() {
    let packets = vec![
        (22_000_000, c2s(100, 0, SYN, &[])),
        (22_000_200, s2c(500, 101, SYN | ACK, &[])),
        (22_000_350, c2s(101, 501, ACK, &[])),
        (22_000_500, npatch_pkt(501, 101, RST, &[])), // NPatch 注入 RST
    ];
    let streams = analyze_verify(&packets, BlockingMode::Ack);
    let s = &streams[0];
    assert!(s.verification.blocked, "ACK 阻断应判定为已阻断");
    assert!(s.verification.reason.contains("ACK 阻断"));
    assert_eq!(s.verification.matched_window, Some(888));
    assert_eq!(s.verification.matched_ttl, Some(60));
    assert_eq!(s.verification.matched_to_client, Some(true));
    assert!(s.connection.handshake.is_complete());
}

/// ACK 阻断未生效：握手完成后服务器正常返回数据。
#[test]
fn test_verify_ack_not_blocked() {
    let packets = vec![
        (23_000_000, c2s(100, 0, SYN, &[])),
        (23_000_200, s2c(500, 101, SYN | ACK, &[])),
        (23_000_350, c2s(101, 501, ACK, &[])),
        (23_000_500, c2s(101, 501, PSH | ACK, b"GET / HTTP/1.1\r\n\r\n")),
        (23_000_700, s2c(501, 119, PSH | ACK, b"HTTP/1.1 200 OK")),
    ];
    let streams = analyze_verify(&packets, BlockingMode::Ack);
    let s = &streams[0];
    assert!(!s.verification.blocked, "服务器已正常响应，ACK 阻断应判定为未阻断");
}

/// Hijack 成功：客户端请求后收到 NPatch 伪造的 PSH/ACK(win888) 响应。
#[test]
fn test_verify_hijack_blocked() {
    let packets = vec![
        (24_000_000, c2s(100, 0, SYN, &[])),
        (24_000_200, s2c(500, 101, SYN | ACK, &[])),
        (24_000_350, c2s(101, 501, ACK, &[])),
        (24_000_500, c2s(101, 501, PSH | ACK, b"GET / HTTP/1.1\r\n\r\n")),
        // NPatch 注入伪造响应（PSH|ACK，win888，TTL60，IP-ID 0x8866）
        (24_000_700, npatch_pkt(501, 119, PSH | ACK, b"HTTP/1.1 404 Not Found\r\n\r\n")),
    ];
    let streams = analyze_verify(&packets, BlockingMode::Hijack);
    let s = &streams[0];
    assert!(s.verification.blocked, "Hijack 应判定为已阻断");
    assert!(s.verification.reason.contains("Hijack"));
    assert_eq!(s.verification.matched_ttl, Some(60));
    assert_eq!(s.verification.matched_ip_id, Some(0x8866));
    assert_eq!(
        s.verification.confidence,
        Some(HijackConfidence::High),
        "TTL 与 IP-ID 均命中，可信度应为高"
    );
}

/// Hijack 未生效：服务器返回的是真实响应（窗口非 888）。
#[test]
fn test_verify_hijack_not_blocked() {
    let packets = vec![
        (25_000_000, c2s(100, 0, SYN, &[])),
        (25_000_200, s2c(500, 101, SYN | ACK, &[])),
        (25_000_350, c2s(101, 501, ACK, &[])),
        (25_000_500, c2s(101, 501, PSH | ACK, b"GET / HTTP/1.1\r\n\r\n")),
        (25_000_700, s2c(501, 119, PSH | ACK, b"HTTP/1.1 200 OK\r\n\r\nreal")),
    ];
    let streams = analyze_verify(&packets, BlockingMode::Hijack);
    let s = &streams[0];
    assert!(!s.verification.blocked, "真实服务器响应不应判为 Hijack");
}

/// Web 扫描防护成功（RST 方式）：web 端口流在请求后收到 NPatch RST(win888)。
#[test]
fn test_verify_webscan_blocked_rst() {
    // SERVER_PORT 为 80，属于 web 端口
    let packets = vec![
        (26_000_000, c2s(100, 0, SYN, &[])),
        (26_000_200, s2c(500, 101, SYN | ACK, &[])),
        (26_000_350, c2s(101, 501, ACK, &[])),
        (26_000_500, c2s(101, 501, PSH | ACK, b"GET /admin HTTP/1.1\r\n\r\n")),
        (26_000_700, npatch_pkt(501, 124, RST, &[])),
    ];
    let streams = analyze_verify(&packets, BlockingMode::WebScan);
    let s = &streams[0];
    assert!(s.verification.blocked, "Web 扫描防护应判定为已阻断");
    assert!(s.verification.reason.contains("Web 扫描防护"));
    assert!(s.verification.reason.contains("RST"));
}

/// Web 扫描防护成功（hijack 方式）：web 端口流在请求后收到 NPatch PSH/ACK(win888)。
#[test]
fn test_verify_webscan_blocked_hijack() {
    let packets = vec![
        (27_000_000, c2s(100, 0, SYN, &[])),
        (27_000_200, s2c(500, 101, SYN | ACK, &[])),
        (27_000_350, c2s(101, 501, ACK, &[])),
        (27_000_500, c2s(101, 501, PSH | ACK, b"GET /scan HTTP/1.1\r\n\r\n")),
        (27_000_700, npatch_pkt(501, 123, PSH | ACK, b"HTTP/1.1 403 Forbidden\r\n\r\n")),
    ];
    let streams = analyze_verify(&packets, BlockingMode::WebScan);
    let s = &streams[0];
    assert!(s.verification.blocked, "Web 扫描防护(hijack)应判定为已阻断");
    assert!(s.verification.reason.contains("PSH/ACK"));
}

/// Web 扫描防护未生效：web 流被服务器正常响应。
#[test]
fn test_verify_webscan_not_blocked() {
    let packets = vec![
        (28_000_000, c2s(100, 0, SYN, &[])),
        (28_000_200, s2c(500, 101, SYN | ACK, &[])),
        (28_000_350, c2s(101, 501, ACK, &[])),
        (28_000_500, c2s(101, 501, PSH | ACK, b"GET / HTTP/1.1\r\n\r\n")),
        (28_000_700, s2c(501, 119, PSH | ACK, b"HTTP/1.1 200 OK")),
    ];
    let streams = analyze_verify(&packets, BlockingMode::WebScan);
    let s = &streams[0];
    assert!(!s.verification.blocked, "正常响应的 web 流不应判为已阻断");
}

/// 真实样本：ack_rest.pcap 是一次真实的 NPatch ACK 阻断抓包。
#[test]
fn test_real_sample_ack_block() {
    let path = Path::new("pcap_file/ack_rest.pcap");
    if !path.exists() {
        return;
    }
    let reader = PcapReader::open(path).expect("样本应能打开");
    let linktype = reader.global_header().linktype;
    let parser = PacketParser::new(false, false, linktype);
    let config = StreamManagerConfig {
        verify_blocking: Some(BlockingMode::Ack),
        ..test_config()
    };
    let mut manager = StreamManager::new(config);
    for pr in reader {
        if let Ok(raw) = pr {
            if let Ok(parsed) = parser.parse(raw) {
                let info: PacketInfo = parsed.into();
                manager.process_packet(&info);
            }
        }
    }
    let streams: Vec<_> = manager.get_all_streams().collect();
    assert_eq!(streams.len(), 1);
    let s = streams[0];
    assert!(
        s.verification.blocked,
        "ack_rest.pcap 应被判定为 ACK 阻断成功"
    );
    // 真实 NPatch 注入报文带 TTL=60、窗口=888 签名
    assert_eq!(s.verification.matched_window, Some(888));
    assert_eq!(s.verification.matched_ttl, Some(60));
}

// =============================================================
// 单向阻断（--one-way-blocking）验证测试
// =============================================================

/// 单向阻断成功（RST 方式）：握手后、服务器返回有效数据前收到 NPatch RST。
#[test]
fn test_verify_oneway_blocked_rst() {
    let packets = vec![
        (30_000_000, c2s(100, 0, SYN, &[])),
        (30_000_200, s2c(500, 101, SYN | ACK, &[])),
        (30_000_350, c2s(101, 501, ACK, &[])),
        (30_000_500, c2s(101, 501, PSH | ACK, b"GET / HTTP/1.1\r\n\r\n")),
        (30_000_700, npatch_pkt(501, 119, RST, &[])),
    ];
    let streams = analyze_verify(&packets, BlockingMode::OneWay);
    let s = &streams[0];
    assert!(s.verification.blocked, "单向阻断(RST)应判定为已阻断");
    assert!(s.verification.reason.contains("单向阻断成功"));
}

/// 单向阻断成功（hijack 方式）：服务器返回有效数据前收到 NPatch 伪造响应。
#[test]
fn test_verify_oneway_blocked_hijack() {
    let packets = vec![
        (31_000_000, c2s(100, 0, SYN, &[])),
        (31_000_200, s2c(500, 101, SYN | ACK, &[])),
        (31_000_350, c2s(101, 501, ACK, &[])),
        (31_000_500, c2s(101, 501, PSH | ACK, b"GET / HTTP/1.1\r\n\r\n")),
        (31_000_700, npatch_pkt(501, 119, PSH | ACK, b"HTTP/1.1 404 Not Found\r\n\r\n")),
    ];
    let streams = analyze_verify(&packets, BlockingMode::OneWay);
    let s = &streams[0];
    assert!(s.verification.blocked, "单向阻断(hijack)应判定为已阻断");
    assert!(s.verification.reason.contains("hijack"));
}

/// 单向阻断成功（握手阶段）：三次握手完成前即收到 NPatch RST。
#[test]
fn test_verify_oneway_blocked_at_syn() {
    let packets = vec![
        (32_000_000, c2s(100, 0, SYN, &[])),
        (32_000_200, npatch_pkt(0, 101, RST | ACK, &[])),
    ];
    let streams = analyze_verify(&packets, BlockingMode::OneWay);
    let s = &streams[0];
    assert!(s.verification.blocked, "握手阶段被 RST 也属于单向阻断成功");
}

/// 单向阻断未生效：服务器先返回了有效数据，NPatch 的 RST 来晚了。
///
/// 这是「协议栈层面」判定的关键用例：服务器的真实响应（窗口非 888）
/// 先于 NPatch 注入报文出现，即使之后出现 RST(win888) 也不算阻断成功。
#[test]
fn test_verify_oneway_not_blocked_server_replied_first() {
    let packets = vec![
        (33_000_000, c2s(100, 0, SYN, &[])),
        (33_000_200, s2c(500, 101, SYN | ACK, &[])),
        (33_000_350, c2s(101, 501, ACK, &[])),
        (33_000_500, c2s(101, 501, PSH | ACK, b"GET / HTTP/1.1\r\n\r\n")),
        // 服务器先返回了真实数据（窗口 64240，非 NPatch 注入）
        (33_000_700, s2c(501, 119, PSH | ACK, b"HTTP/1.1 200 OK\r\n\r\nreal data")),
        // NPatch 的 RST 来得太晚
        (33_000_900, npatch_pkt(520, 119, RST, &[])),
    ];
    let streams = analyze_verify(&packets, BlockingMode::OneWay);
    let s = &streams[0];
    assert!(
        !s.verification.blocked,
        "服务器已先返回有效数据，单向阻断应判定为未生效"
    );
}

/// 单向阻断未生效：连接全程正常，无任何 NPatch 注入。
#[test]
fn test_verify_oneway_not_blocked_normal() {
    let packets = vec![
        (34_000_000, c2s(100, 0, SYN, &[])),
        (34_000_200, s2c(500, 101, SYN | ACK, &[])),
        (34_000_350, c2s(101, 501, ACK, &[])),
        (34_000_500, c2s(101, 501, PSH | ACK, b"hello")),
        (34_000_700, s2c(501, 106, PSH | ACK, b"hi there")),
    ];
    let streams = analyze_verify(&packets, BlockingMode::OneWay);
    let s = &streams[0];
    assert!(!s.verification.blocked, "正常连接不应判为单向阻断");
}
