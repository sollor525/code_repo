//! PCAP 流量生成：基于移植自 `rust/gen_pcap` 的 `genpcap` 生成核心，按参数
//! 构造 TCP / HTTP 会话（可选 VLAN / QinQ），并在内存中序列化为 PCAP 字节。
//!
//! 纯逻辑，不触碰文件系统：报文由 `genpcap` 生成，再用 `pcap_file` 写入内存缓冲。

use std::borrow::Cow;
use std::time::Duration;

use genpcap::{
    build_vlan_ethernet_header, IpRange, PortRange, TcpSession, TcpSessionConfig, VlanConfig,
    VlanTag,
};
use pcap_file::pcap::{PcapPacket, PcapWriter};

/// 生成参数（对应 gen_pcap 的命令行配置 + VLAN）
#[derive(Debug, Clone)]
pub struct PcapGenParams {
    pub session_count: u32,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: String,
    pub dst_port: String,
    pub include_http: bool,
    pub http_host: String,
    pub http_uris: Vec<String>,
    // VLAN（单层）
    pub vlan_id: Option<u16>,
    pub vlan_priority: u8,
    pub vlan_dei: bool,
    // QinQ（双层）
    pub qinq: bool,
    pub outer_vlan: Option<u16>,
    pub inner_vlan: Option<u16>,
    pub outer_priority: u8,
    pub inner_priority: u8,
}

/// 生成结果
pub struct PcapGenResult {
    pub pcap: Vec<u8>,
    pub session_count: usize,
    pub packet_count: usize,
    pub flow: String,
}

/// 上限，避免极端输入耗尽内存
const MAX_SESSIONS: u32 = 10_000;

/// 按参数生成 PCAP（内存字节）
pub fn generate_pcap(params: &PcapGenParams) -> Result<PcapGenResult, String> {
    if params.session_count == 0 {
        return Err("会话数量必须大于 0".to_string());
    }
    if params.session_count > MAX_SESSIONS {
        return Err(format!("会话数量过大（最多 {MAX_SESSIONS}）"));
    }

    let src_ip_range = IpRange::from_string(params.src_ip.trim())
        .map_err(|e| format!("无效的源 IP 范围: {e}"))?;
    let dst_ip_range = IpRange::from_string(params.dst_ip.trim())
        .map_err(|e| format!("无效的目标 IP 范围: {e}"))?;
    let src_port_range = PortRange::from_string(params.src_port.trim())
        .map_err(|e| format!("无效的源端口范围: {e}"))?;
    let dst_port_range = PortRange::from_string(params.dst_port.trim())
        .map_err(|e| format!("无效的目标端口范围: {e}"))?;

    let mut config = TcpSessionConfig::new()
        .with_session_count(params.session_count)
        .with_src_ip_range(src_ip_range)
        .with_dst_ip_range(dst_ip_range)
        .with_src_port_range(src_port_range)
        .with_dst_port_range(dst_port_range);

    if params.include_http {
        let mut uris: Vec<String> = params
            .http_uris
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if uris.is_empty() {
            uris.push("/".to_string());
        }
        let host = {
            let h = params.http_host.trim();
            if h.is_empty() { "example.com".to_string() } else { h.to_string() }
        };
        config = config.with_http(uris, host);
    }

    let vlan_config = build_vlan_config(params)?;

    let sessions = config.generate_sessions();
    let flow = if params.include_http { "HTTP" } else { "TCP_ONLY" }.to_string();

    // 在内存中序列化为 PCAP
    let mut buffer: Vec<u8> = Vec::new();
    let mut packet_count = 0usize;
    {
        let mut writer = PcapWriter::new(&mut buffer)
            .map_err(|e| format!("创建 PCAP 失败: {e}"))?;

        for (i, session) in sessions.iter().enumerate() {
            let packets = session.generate_packets(&config.application_flow);
            let packets = apply_vlan(packets, session, &vlan_config);

            for (j, data) in packets.iter().enumerate() {
                let pkt = PcapPacket {
                    timestamp: Duration::from_secs(i as u64) + Duration::from_micros(j as u64),
                    orig_len: data.len() as u32,
                    data: Cow::Borrowed(data),
                };
                writer
                    .write_packet(&pkt)
                    .map_err(|e| format!("写入数据包失败: {e}"))?;
                packet_count += 1;
            }
        }
    }

    if packet_count == 0 {
        return Err("未生成任何数据包，请检查参数".to_string());
    }

    Ok(PcapGenResult {
        pcap: buffer,
        session_count: sessions.len(),
        packet_count,
        flow,
    })
}

/// 由参数构造 VLAN 配置（移植自 gen_pcap 的 parse_vlan_config，去除 process::exit）
fn build_vlan_config(p: &PcapGenParams) -> Result<Option<VlanConfig>, String> {
    let has_vlan = p.vlan_id.is_some()
        || p.outer_vlan.is_some()
        || p.inner_vlan.is_some()
        || p.vlan_dei
        || p.qinq;
    if !has_vlan {
        return Ok(None);
    }

    let mut cfg = VlanConfig::new();

    if p.qinq {
        cfg.is_qinq = true;
        if let Some(outer) = p.outer_vlan {
            cfg.outer_tag = Some(VlanTag::new(outer, p.outer_priority, false));
        }
        if let Some(inner) = p.inner_vlan {
            cfg.inner_tag = Some(VlanTag::new(inner, p.inner_priority, false));
        }
        // 未指定内层时，用普通 VLAN 参数作为内层
        if cfg.inner_tag.is_none() {
            if let Some(vid) = p.vlan_id {
                cfg.inner_tag = Some(VlanTag::new(vid, p.vlan_priority, p.vlan_dei));
            }
        }
    } else if let Some(vid) = p.vlan_id {
        cfg.outer_tag = Some(VlanTag::new(vid, p.vlan_priority, p.vlan_dei));
    }

    if let Some(ref t) = cfg.outer_tag {
        if t.vlan_id == 0 || t.vlan_id > 4094 {
            return Err(format!("无效的外层 VLAN ID: {} (有效范围 1-4094)", t.vlan_id));
        }
    }
    if let Some(ref t) = cfg.inner_tag {
        if t.vlan_id == 0 || t.vlan_id > 4094 {
            return Err(format!("无效的内层 VLAN ID: {} (有效范围 1-4094)", t.vlan_id));
        }
    }

    Ok(Some(cfg))
}

/// 为数据包应用 VLAN 标签（移植自 gen_pcap 的 apply_vlan_to_packets）
fn apply_vlan(
    packets: Vec<Vec<u8>>,
    session: &TcpSession,
    vlan_config: &Option<VlanConfig>,
) -> Vec<Vec<u8>> {
    let Some(cfg) = vlan_config else {
        return packets;
    };
    if !(cfg.is_qinq || cfg.outer_tag.is_some()) {
        return packets;
    }

    let ip_version = session.connection.ip_version();
    packets
        .into_iter()
        .map(|packet| {
            let vlan_header = build_vlan_ethernet_header(
                session.connection.src_mac,
                session.connection.dst_mac,
                cfg,
                ip_version,
            );
            let mut new_packet = packet;
            if new_packet.len() >= 14 {
                new_packet.splice(0..14, vlan_header);
            }
            new_packet
        })
        .collect()
}
