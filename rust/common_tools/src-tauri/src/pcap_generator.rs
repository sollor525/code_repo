//! PCAP 流量生成：基于移植自 `rust/gen_pcap` 的 `genpcap` 生成核心，按参数
//! 构造 TCP / HTTP 会话（可选 VLAN / QinQ），并在内存中序列化为 PCAP 字节。
//!
//! 纯逻辑，不触碰文件系统：报文由 `genpcap` 生成，再用 `pcap_file` 写入内存缓冲。

use std::borrow::Cow;
use std::time::Duration;

use genpcap::{
    build_vlan_ethernet_header, ApplicationFlow, ApplicationFlowType, FtpMode, GenOptions,
    HttpConfig, IcmpConfig, IpRange, PortRange, TcpMode, TcpSession, TcpSessionConfig, UdpConfig,
    VlanConfig, VlanTag,
};
use pcap_file::pcap::{PcapPacket, PcapWriter};

/// 生成参数：寻址 + 协议（及各自子选项）+ VLAN
#[derive(Debug, Clone)]
pub struct PcapGenParams {
    pub session_count: u32,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: String,
    pub dst_port: String,
    /// 协议：tcp | http | icmp | udp | ftp | ssh | mysql
    pub protocol: String,
    /// TCP 模式：syn_only | handshake | handshake_close | handshake_reset
    pub tcp_mode: String,
    pub http_host: String,
    pub http_uris: Vec<String>,
    pub http_request: Option<String>,
    pub http_response: Option<String>,
    pub icmp_count: u32,
    pub udp_payload: String,
    pub udp_response: bool,
    /// FTP 模式：active | passive
    pub ftp_mode: String,
    /// 链路 MTU；超过则 TCP 分段或 IP 分片。0 = 不限制
    pub mtu: u32,
    /// 自动填充载荷字节数（用户未指定内容时生效）。0 = 协议默认
    pub payload_size: u32,
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

/// 由参数构造应用流量类型
fn build_flow(p: &PcapGenParams) -> Result<ApplicationFlowType, String> {
    let proto = p.protocol.trim().to_ascii_lowercase();
    let flow = match proto.as_str() {
        "tcp" | "" => {
            let mode = match p.tcp_mode.trim() {
                "syn_only" => TcpMode::SynOnly,
                "handshake_close" => TcpMode::HandshakeClose,
                "handshake_reset" => TcpMode::HandshakeReset,
                _ => TcpMode::Handshake,
            };
            ApplicationFlowType::Tcp(mode)
        }
        "http" => {
            let uris: Vec<String> = p
                .http_uris
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let uris = if uris.is_empty() { vec!["/".to_string()] } else { uris };
            let host = {
                let h = p.http_host.trim();
                if h.is_empty() { "example.com".to_string() } else { h.to_string() }
            };
            let clean = |o: &Option<String>| {
                o.as_ref()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            };
            ApplicationFlowType::Http(HttpConfig {
                uris,
                host,
                request_content: clean(&p.http_request),
                response_content: clean(&p.http_response),
            })
        }
        "icmp" => ApplicationFlowType::Icmp(IcmpConfig { count: p.icmp_count.clamp(1, 1000) }),
        "udp" => ApplicationFlowType::Udp(UdpConfig {
            payload: p.udp_payload.clone().into_bytes(),
            with_response: p.udp_response,
        }),
        "ftp" => {
            let mode = if p.ftp_mode.trim() == "active" {
                FtpMode::Active
            } else {
                FtpMode::Passive
            };
            ApplicationFlowType::Ftp(mode)
        }
        "ssh" => ApplicationFlowType::Ssh,
        "mysql" => ApplicationFlowType::Mysql,
        other => return Err(format!("未知协议: {other}")),
    };
    Ok(flow)
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

    // 源/目标 IP 版本必须一致（否则底层 TCP 构造会 panic）
    let src_v4 = matches!(src_ip_range, IpRange::V4 { .. });
    let dst_v4 = matches!(dst_ip_range, IpRange::V4 { .. });
    if src_v4 != dst_v4 {
        return Err("源 IP 与目标 IP 必须同为 IPv4 或同为 IPv6".to_string());
    }

    let app_flow = build_flow(params)?;
    let flow = app_flow.name().to_string();
    let opts = GenOptions {
        mtu: params.mtu as usize,
        payload_size: (params.payload_size as usize).min(2_000_000), // 上限 2MB，避免内存过大
    };

    let config = TcpSessionConfig::new()
        .with_session_count(params.session_count)
        .with_src_ip_range(src_ip_range)
        .with_dst_ip_range(dst_ip_range)
        .with_src_port_range(src_port_range)
        .with_dst_port_range(dst_port_range)
        .with_application_flow(app_flow);

    let vlan_config = build_vlan_config(params)?;

    let sessions = config.generate_sessions();

    // 在内存中序列化为 PCAP
    let mut buffer: Vec<u8> = Vec::new();
    let mut packet_count = 0usize;
    {
        let mut writer = PcapWriter::new(&mut buffer)
            .map_err(|e| format!("创建 PCAP 失败: {e}"))?;

        for (i, session) in sessions.iter().enumerate() {
            let packets = session.generate_packets(&config.application_flow, &opts);
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

/// 保存结果
pub struct SavedPcap {
    pub filename: String,
    pub path: String,
    pub session_count: usize,
    pub packet_count: usize,
    pub flow: String,
    pub size: usize,
}

fn default_filename() -> String {
    let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
    format!("generated_{ts}.pcap")
}

/// 去除 Windows `canonicalize()` 产生的扩展长度前缀 `\\?\`
/// （UNC 形式 `\\?\UNC\server\share` 还原为 `\\server\share`）。其他平台原样返回。
fn strip_extended_prefix(p: &str) -> String {
    if let Some(rest) = p.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = p.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        p.to_string()
    }
}

/// 生成 PCAP 并写入磁盘目录。
///
/// `output_dir` 为空时使用进程当前工作目录（即 exe 启动所在目录）；目录不存在则创建。
/// `filename` 仅取文件名部分（防目录穿越），缺省自动按时间命名，并确保 `.pcap` 后缀。
pub fn save_pcap(
    params: &PcapGenParams,
    output_dir: Option<&str>,
    filename: Option<&str>,
) -> Result<SavedPcap, String> {
    use std::path::{Path, PathBuf};

    let result = generate_pcap(params)?;

    // 输出目录：空 → 当前工作目录
    let dir: PathBuf = match output_dir.map(str::trim).filter(|s| !s.is_empty()) {
        Some(d) => PathBuf::from(d),
        None => std::env::current_dir().map_err(|e| format!("无法获取当前目录: {e}"))?,
    };
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建输出目录失败: {e}"))?;

    // 文件名：仅取末段，确保 .pcap 后缀
    let mut name = filename
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| Path::new(s).file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(default_filename);
    if !name.to_ascii_lowercase().ends_with(".pcap") {
        name.push_str(".pcap");
    }

    let full = dir.join(&name);
    std::fs::write(&full, &result.pcap).map_err(|e| format!("写入文件失败: {e}"))?;

    // 展示绝对路径（canonicalize 失败则退回拼接路径），并去除 Windows 扩展长度前缀 \\?\
    let shown = std::fs::canonicalize(&full).unwrap_or(full);
    let path = strip_extended_prefix(&shown.to_string_lossy());
    Ok(SavedPcap {
        filename: name,
        path,
        session_count: result.session_count,
        packet_count: result.packet_count,
        flow: result.flow,
        size: result.pcap.len(),
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

#[cfg(test)]
mod tests {
    use super::strip_extended_prefix;

    #[test]
    fn strips_windows_extended_length_prefix() {
        assert_eq!(
            strip_extended_prefix(r"\\?\D:\personal_work\code_repo\generated.pcap"),
            r"D:\personal_work\code_repo\generated.pcap"
        );
        // UNC 形式还原为 \\server\share
        assert_eq!(
            strip_extended_prefix(r"\\?\UNC\server\share\out.pcap"),
            r"\\server\share\out.pcap"
        );
        // 无前缀（含类 Unix 路径）原样返回
        assert_eq!(strip_extended_prefix(r"D:\dir\out.pcap"), r"D:\dir\out.pcap");
        assert_eq!(strip_extended_prefix("/home/user/out.pcap"), "/home/user/out.pcap");
    }
}
