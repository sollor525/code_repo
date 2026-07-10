//! PCAP 修改：按五元组（源 IP / 目的 IP / 源端口 / 目的端口 / 协议）匹配 TCP/UDP
//! 报文，把其中的源/目的 IP 与源/目的 MAC 改写为指定值。五元组各字段可为「any」。
//!
//! **方向感知**是关键：改写值以「客户端 → 服务端」（正向 ctos）方向定义 ——
//! 新源 = 客户端的新地址，新目的 = 服务端的新地址。对反向（stoc）报文，同一端点
//! 出现在相反的字段里，因此源/目的映射自动交换，从而保证整条会话首尾一致。
//!
//! 纯逻辑：用 `pcap_file` 读入传统 pcap，逐包用固定偏移解析
//! 以太网（含可选 VLAN 标签）→ IPv4/IPv6 → TCP/UDP，改写地址后重算 IP / L4 校验和，
//! 再写回内存 pcap（保留原链路类型、时间戳、非匹配报文）。仅处理 TCP/UDP 报文。

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pcap_file::pcap::{PcapPacket, PcapReader, PcapWriter};
use pcap_file::DataLink;
use serde::Serialize;

use crate::pcap_generator::write_pcap_to_dir;

/// 样例最多展示的匹配报文数
const SAMPLE_LIMIT: usize = 20;

// =============================  DTO  =============================

/// 请求参数（全部为字符串，便于与前端 / 查询串对接；空或 "any" 表示通配 / 不改写）
#[derive(Debug, Clone, Default)]
pub struct EditRequest {
    // 五元组过滤（相对客户端 → 服务端方向）
    pub f_src_ip: String,
    pub f_dst_ip: String,
    pub f_src_port: String,
    pub f_dst_port: String,
    pub protocol: String, // tcp | udp | any
    // 改写目标（相对客户端 → 服务端方向；空 = 保持不变）
    pub new_src_ip: String,
    pub new_dst_ip: String,
    pub new_src_mac: String,
    pub new_dst_mac: String,
}

#[derive(Serialize, Debug)]
pub struct FlowSample {
    /// 报文序号（1 起）
    pub index: usize,
    /// ctos | stoc
    pub direction: String,
    pub before: String,
    pub after: String,
    pub changed: bool,
}

#[derive(Serialize, Debug)]
pub struct EditReport {
    pub total_packets: usize,
    pub matched_ctos: usize,
    pub matched_stoc: usize,
    pub modified_packets: usize,
    pub skipped_non_ip: usize,
    pub skipped_non_tcpudp: usize,
    pub unsupported: usize,
    pub link_type: String,
    pub filter_desc: String,
    pub rewrite_desc: String,
    pub notes: Vec<String>,
    pub samples: Vec<FlowSample>,
}

// =============================  参数解析  =============================

fn is_any(s: &str) -> bool {
    let t = s.trim();
    t.is_empty() || t.eq_ignore_ascii_case("any") || t == "*"
}

fn parse_ip_opt(s: &str, label: &str) -> Result<Option<IpAddr>, String> {
    if is_any(s) {
        return Ok(None);
    }
    s.trim()
        .parse::<IpAddr>()
        .map(Some)
        .map_err(|_| format!("{label}「{}」不是合法的 IP 地址", s.trim()))
}

fn parse_port_opt(s: &str, label: &str) -> Result<Option<u16>, String> {
    if is_any(s) {
        return Ok(None);
    }
    s.trim()
        .parse::<u16>()
        .map(Some)
        .map_err(|_| format!("{label}「{}」不是合法的端口（0-65535）", s.trim()))
}

fn parse_proto(s: &str) -> Result<Option<u8>, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "" | "any" | "*" => Ok(None),
        "tcp" | "6" => Ok(Some(6)),
        "udp" | "17" => Ok(Some(17)),
        other => Err(format!("协议「{other}」无效（仅支持 tcp / udp / any）")),
    }
}

fn parse_mac_opt(s: &str, label: &str) -> Result<Option<[u8; 6]>, String> {
    if s.trim().is_empty() {
        return Ok(None);
    }
    let parts: Vec<&str> = s.trim().split(|c| c == ':' || c == '-').collect();
    if parts.len() != 6 {
        return Err(format!("{label}「{}」需为 6 组十六进制（如 aa:bb:cc:dd:ee:ff）", s.trim()));
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p.trim(), 16)
            .map_err(|_| format!("{label}「{}」含非法十六进制段「{p}」", s.trim()))?;
    }
    Ok(Some(mac))
}

struct Filter {
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    proto: Option<u8>,
}

struct Rewrite {
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_mac: Option<[u8; 6]>,
    dst_mac: Option<[u8; 6]>,
}

impl Rewrite {
    fn is_empty(&self) -> bool {
        self.src_ip.is_none() && self.dst_ip.is_none() && self.src_mac.is_none() && self.dst_mac.is_none()
    }
}

fn describe_filter(f: &Filter) -> String {
    let ip = |o: &Option<IpAddr>| o.map(|v| v.to_string()).unwrap_or_else(|| "any".into());
    let pt = |o: &Option<u16>| o.map(|v| v.to_string()).unwrap_or_else(|| "any".into());
    let pr = match f.proto {
        Some(6) => "tcp",
        Some(17) => "udp",
        _ => "any",
    };
    format!(
        "{} : {}  →  {} : {}  ({})",
        ip(&f.src_ip), pt(&f.src_port), ip(&f.dst_ip), pt(&f.dst_port), pr
    )
}

fn describe_rewrite(r: &Rewrite) -> String {
    let mut parts = Vec::new();
    if let Some(ip) = r.src_ip { parts.push(format!("新源 IP={ip}")); }
    if let Some(ip) = r.dst_ip { parts.push(format!("新目的 IP={ip}")); }
    if let Some(m) = r.src_mac { parts.push(format!("新源 MAC={}", fmt_mac(&m))); }
    if let Some(m) = r.dst_mac { parts.push(format!("新目的 MAC={}", fmt_mac(&m))); }
    if parts.is_empty() {
        "（未指定改写目标）".to_string()
    } else {
        parts.join("，")
    }
}

// =============================  报文解析  =============================

/// 跳过 non-IP / non-TCPUDP / 无法解析的原因
#[derive(Debug)]
enum Skip {
    NonIp,
    NonTcpUdp,
    Unsupported,
}

/// 定位到的三/四层信息（地址为拷贝，不借用缓冲区）
struct Dissected {
    l3: usize,
    ip_ver: u8, // 4 | 6
    ihl: usize, // IPv4 头长；IPv6 固定 40
    l4: usize,
    proto: u8, // 6 | 17
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    /// IP 报文总长（v4 total_len；v6 = 40 + payload_len）
    ip_total: usize,
}

fn dissect(buf: &[u8]) -> Result<Dissected, Skip> {
    if buf.len() < 14 {
        return Err(Skip::Unsupported);
    }
    // MAC 之后是 EtherType；跳过任意层 VLAN 标签
    let mut off = 12;
    let mut eth = u16::from_be_bytes([buf[off], buf[off + 1]]);
    off += 2;
    let mut guard = 0;
    while matches!(eth, 0x8100 | 0x88A8 | 0x9100) {
        if buf.len() < off + 4 {
            return Err(Skip::Unsupported);
        }
        eth = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
        off += 4;
        guard += 1;
        if guard > 4 {
            return Err(Skip::Unsupported);
        }
    }
    match eth {
        0x0800 => dissect_v4(buf, off),
        0x86DD => dissect_v6(buf, off),
        _ => Err(Skip::NonIp),
    }
}

fn dissect_v4(buf: &[u8], l3: usize) -> Result<Dissected, Skip> {
    if buf.len() < l3 + 20 || (buf[l3] >> 4) != 4 {
        return Err(Skip::Unsupported);
    }
    let ihl = ((buf[l3] & 0x0f) as usize) * 4;
    if ihl < 20 || buf.len() < l3 + ihl {
        return Err(Skip::Unsupported);
    }
    let ip_total = u16::from_be_bytes([buf[l3 + 2], buf[l3 + 3]]) as usize;
    let proto = buf[l3 + 9];
    if proto != 6 && proto != 17 {
        return Err(Skip::NonTcpUdp);
    }
    let src = Ipv4Addr::new(buf[l3 + 12], buf[l3 + 13], buf[l3 + 14], buf[l3 + 15]);
    let dst = Ipv4Addr::new(buf[l3 + 16], buf[l3 + 17], buf[l3 + 18], buf[l3 + 19]);
    let l4 = l3 + ihl;
    if buf.len() < l4 + 4 {
        return Err(Skip::Unsupported);
    }
    Ok(Dissected {
        l3,
        ip_ver: 4,
        ihl,
        l4,
        proto,
        src_ip: src.into(),
        dst_ip: dst.into(),
        src_port: u16::from_be_bytes([buf[l4], buf[l4 + 1]]),
        dst_port: u16::from_be_bytes([buf[l4 + 2], buf[l4 + 3]]),
        ip_total,
    })
}

fn dissect_v6(buf: &[u8], l3: usize) -> Result<Dissected, Skip> {
    if buf.len() < l3 + 40 || (buf[l3] >> 4) != 6 {
        return Err(Skip::Unsupported);
    }
    let payload = u16::from_be_bytes([buf[l3 + 4], buf[l3 + 5]]) as usize;
    let next_header = buf[l3 + 6];
    // 仅直接承载 TCP/UDP 的情形；扩展头（分片 / 逐跳等）不处理
    if next_header != 6 && next_header != 17 {
        return Err(Skip::NonTcpUdp);
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&buf[l3 + 8..l3 + 24]);
    dst.copy_from_slice(&buf[l3 + 24..l3 + 40]);
    let l4 = l3 + 40;
    if buf.len() < l4 + 4 {
        return Err(Skip::Unsupported);
    }
    Ok(Dissected {
        l3,
        ip_ver: 6,
        ihl: 40,
        l4,
        proto: next_header,
        src_ip: Ipv6Addr::from(src).into(),
        dst_ip: Ipv6Addr::from(dst).into(),
        src_port: u16::from_be_bytes([buf[l4], buf[l4 + 1]]),
        dst_port: u16::from_be_bytes([buf[l4 + 2], buf[l4 + 3]]),
        ip_total: 40 + payload,
    })
}

// =============================  方向匹配  =============================

#[derive(Clone, Copy, PartialEq)]
enum Dir {
    Ctos,
    Stoc,
}

fn ip_ok(f: Option<IpAddr>, a: IpAddr) -> bool {
    f.is_none_or(|v| v == a)
}
fn port_ok(f: Option<u16>, a: u16) -> bool {
    f.is_none_or(|v| v == a)
}

/// 判定报文相对过滤器的方向：优先正向（ctos），否则尝试反向（stoc）
fn direction(f: &Filter, d: &Dissected) -> Option<Dir> {
    if f.proto.is_some_and(|p| p != d.proto) {
        return None;
    }
    let fwd = ip_ok(f.src_ip, d.src_ip)
        && ip_ok(f.dst_ip, d.dst_ip)
        && port_ok(f.src_port, d.src_port)
        && port_ok(f.dst_port, d.dst_port);
    if fwd {
        return Some(Dir::Ctos);
    }
    let rev = ip_ok(f.src_ip, d.dst_ip)
        && ip_ok(f.dst_ip, d.src_ip)
        && port_ok(f.src_port, d.dst_port)
        && port_ok(f.dst_port, d.src_port);
    if rev {
        return Some(Dir::Stoc);
    }
    None
}

// =============================  改写与校验和  =============================

/// 把改写值按方向映射到「作用于报文源字段 / 目的字段」的具体值。
/// ctos：源字段=客户端新值、目的字段=服务端新值；stoc：两者交换。
fn resolve(
    r: &Rewrite,
    dir: Dir,
) -> (Option<IpAddr>, Option<IpAddr>, Option<[u8; 6]>, Option<[u8; 6]>) {
    match dir {
        Dir::Ctos => (r.src_ip, r.dst_ip, r.src_mac, r.dst_mac),
        Dir::Stoc => (r.dst_ip, r.src_ip, r.dst_mac, r.src_mac),
    }
}

struct ApplyOutcome {
    changed: bool,
    version_mismatch: bool,
}

/// 就地改写一个报文的源/目的 IP、MAC，并在 IP 变动时重算校验和。
fn apply(
    buf: &mut [u8],
    d: &Dissected,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_mac: Option<[u8; 6]>,
    dst_mac: Option<[u8; 6]>,
) -> ApplyOutcome {
    let mut changed = false;
    let mut version_mismatch = false;

    // 以太网：目的 MAC 在 [0..6]，源 MAC 在 [6..12]
    if let Some(m) = dst_mac {
        if buf[0..6] != m {
            buf[0..6].copy_from_slice(&m);
            changed = true;
        }
    }
    if let Some(m) = src_mac {
        if buf[6..12] != m {
            buf[6..12].copy_from_slice(&m);
            changed = true;
        }
    }

    let mut ip_changed = false;
    if let Some(ip) = src_ip {
        match write_ip(buf, d, true, ip) {
            Some(true) => ip_changed = true,
            Some(false) => {}
            None => version_mismatch = true,
        }
    }
    if let Some(ip) = dst_ip {
        match write_ip(buf, d, false, ip) {
            Some(true) => ip_changed = true,
            Some(false) => {}
            None => version_mismatch = true,
        }
    }

    if ip_changed {
        changed = true;
        recompute_checksums(buf, d);
    }

    ApplyOutcome { changed, version_mismatch }
}

/// 写入源(is_src=true)或目的 IP。返回 Some(true)=已改动、Some(false)=值相同、None=版本不符。
fn write_ip(buf: &mut [u8], d: &Dissected, is_src: bool, ip: IpAddr) -> Option<bool> {
    match (d.ip_ver, ip) {
        (4, IpAddr::V4(v4)) => {
            let off = if is_src { d.l3 + 12 } else { d.l3 + 16 };
            let oct = v4.octets();
            let same = buf[off..off + 4] == oct;
            buf[off..off + 4].copy_from_slice(&oct);
            Some(!same)
        }
        (6, IpAddr::V6(v6)) => {
            let off = if is_src { d.l3 + 8 } else { d.l3 + 24 };
            let oct = v6.octets();
            let same = buf[off..off + 16] == oct;
            buf[off..off + 16].copy_from_slice(&oct);
            Some(!same)
        }
        _ => None, // v4 报文配 v6 新地址（或反之）—— 无法写入
    }
}

/// 标准 16 位 Internet 校验和（RFC 1071）
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut it = data.chunks_exact(2);
    for c in it.by_ref() {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    let rem = it.remainder();
    if !rem.is_empty() {
        sum += (rem[0] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// IP 变动后重算 IPv4 头校验和与 TCP/UDP 校验和（含 IP 伪首部）。
fn recompute_checksums(buf: &mut [u8], d: &Dissected) {
    // L4 长度：以 IP 头声明为准，并被实际抓包长度截断（应对截断包）
    let l4_len_full = d.ip_total.saturating_sub(d.ihl);
    let avail = buf.len().saturating_sub(d.l4);
    let l4_len = l4_len_full.min(avail);

    // IPv4 头校验和
    if d.ip_ver == 4 {
        buf[d.l3 + 10] = 0;
        buf[d.l3 + 11] = 0;
        let c = internet_checksum(&buf[d.l3..d.l3 + d.ihl]);
        buf[d.l3 + 10..d.l3 + 12].copy_from_slice(&c.to_be_bytes());
    }

    // L4 校验和字段：TCP 在 l4+16，UDP 在 l4+6
    let ck_off = match d.proto {
        6 => d.l4 + 16,
        17 => d.l4 + 6,
        _ => return,
    };
    if ck_off + 2 > buf.len() {
        return;
    }
    // UDP over IPv4 且原校验和为 0 表示「未启用」，保持 0
    if d.proto == 17 && d.ip_ver == 4 {
        let orig = u16::from_be_bytes([buf[ck_off], buf[ck_off + 1]]);
        if orig == 0 {
            return;
        }
    }
    buf[ck_off] = 0;
    buf[ck_off + 1] = 0;

    // 伪首部 + L4 段
    let mut data = Vec::with_capacity(40 + l4_len);
    if d.ip_ver == 4 {
        data.extend_from_slice(&buf[d.l3 + 12..d.l3 + 16]); // 源 IP
        data.extend_from_slice(&buf[d.l3 + 16..d.l3 + 20]); // 目的 IP
        data.push(0);
        data.push(d.proto);
        data.extend_from_slice(&(l4_len as u16).to_be_bytes());
    } else {
        data.extend_from_slice(&buf[d.l3 + 8..d.l3 + 24]); // 源 IP
        data.extend_from_slice(&buf[d.l3 + 24..d.l3 + 40]); // 目的 IP
        data.extend_from_slice(&(l4_len as u32).to_be_bytes());
        data.extend_from_slice(&[0, 0, 0, d.proto]);
    }
    data.extend_from_slice(&buf[d.l4..d.l4 + l4_len]);

    let mut c = internet_checksum(&data);
    if c == 0 {
        // 校验和 0 在线路上用 0xffff 表示（UDP 的 0 另有「未启用」之意）
        c = 0xffff;
    }
    buf[ck_off..ck_off + 2].copy_from_slice(&c.to_be_bytes());
}

// =============================  展示辅助  =============================

fn fmt_mac(mac: &[u8]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn read_ip(buf: &[u8], d: &Dissected, is_src: bool) -> IpAddr {
    if d.ip_ver == 4 {
        let off = if is_src { d.l3 + 12 } else { d.l3 + 16 };
        Ipv4Addr::new(buf[off], buf[off + 1], buf[off + 2], buf[off + 3]).into()
    } else {
        let off = if is_src { d.l3 + 8 } else { d.l3 + 24 };
        let mut o = [0u8; 16];
        o.copy_from_slice(&buf[off..off + 16]);
        Ipv6Addr::from(o).into()
    }
}

fn fmt_endpoint(mac: &[u8], ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V6(_) => format!("{} [{ip}]:{port}", fmt_mac(mac)),
        IpAddr::V4(_) => format!("{} {ip}:{port}", fmt_mac(mac)),
    }
}

/// 从当前缓冲区按偏移读出「源端点 → 目的端点」文本
fn endpoints(buf: &[u8], d: &Dissected) -> String {
    let dst_mac = &buf[0..6];
    let src_mac = &buf[6..12];
    let src_ip = read_ip(buf, d, true);
    let dst_ip = read_ip(buf, d, false);
    let sp = u16::from_be_bytes([buf[d.l4], buf[d.l4 + 1]]);
    let dp = u16::from_be_bytes([buf[d.l4 + 2], buf[d.l4 + 3]]);
    format!("{}  →  {}", fmt_endpoint(src_mac, src_ip, sp), fmt_endpoint(dst_mac, dst_ip, dp))
}

// =============================  核心处理  =============================

/// 探测是否为 pcapng（区分传统 pcap，给出更友好的错误）
fn looks_like_pcapng(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0..4] == [0x0a, 0x0d, 0x0d, 0x0a]
}

/// 处理 pcap：匹配 + 改写。`produce=true` 时返回改写后的 pcap 字节。
pub fn process(pcap: &[u8], req: &EditRequest, produce: bool) -> Result<(EditReport, Option<Vec<u8>>), String> {
    let filter = Filter {
        src_ip: parse_ip_opt(&req.f_src_ip, "源 IP")?,
        dst_ip: parse_ip_opt(&req.f_dst_ip, "目的 IP")?,
        src_port: parse_port_opt(&req.f_src_port, "源端口")?,
        dst_port: parse_port_opt(&req.f_dst_port, "目的端口")?,
        proto: parse_proto(&req.protocol)?,
    };
    let rewrite = Rewrite {
        src_ip: parse_ip_opt(&req.new_src_ip, "新源 IP")?,
        dst_ip: parse_ip_opt(&req.new_dst_ip, "新目的 IP")?,
        src_mac: parse_mac_opt(&req.new_src_mac, "新源 MAC")?,
        dst_mac: parse_mac_opt(&req.new_dst_mac, "新目的 MAC")?,
    };

    if pcap.is_empty() {
        return Err("未收到 pcap 内容".to_string());
    }
    if looks_like_pcapng(pcap) {
        return Err("这是 pcapng 格式，当前仅支持传统 pcap（.pcap）。请用 Wireshark 另存为 tcpdump/libpcap 格式后再试".to_string());
    }

    let mut reader = PcapReader::new(pcap).map_err(|e| format!("无法解析 pcap：{e}"))?;
    let header = reader.header();
    if header.datalink != DataLink::ETHERNET {
        return Err(format!("仅支持以太网（Ethernet）链路层，当前为 {:?}", header.datalink));
    }

    let mut report = EditReport {
        total_packets: 0,
        matched_ctos: 0,
        matched_stoc: 0,
        modified_packets: 0,
        skipped_non_ip: 0,
        skipped_non_tcpudp: 0,
        unsupported: 0,
        link_type: format!("{:?}", header.datalink),
        filter_desc: describe_filter(&filter),
        rewrite_desc: describe_rewrite(&rewrite),
        notes: Vec::new(),
        samples: Vec::new(),
    };
    let mut version_mismatch = 0usize;

    // 输出缓冲（produce 时）保留原始文件头
    let mut out: Vec<u8> = Vec::new();
    let mut writer = if produce {
        Some(PcapWriter::with_header(&mut out, header).map_err(|e| format!("创建输出 pcap 失败：{e}"))?)
    } else {
        None
    };

    while let Some(res) = reader.next_packet() {
        let pkt = res.map_err(|e| format!("读取数据包失败：{e}"))?;
        report.total_packets += 1;

        let timestamp = pkt.timestamp;
        let orig_len = pkt.orig_len;
        let mut data = pkt.data.into_owned();

        // 解析 + 分类；无论是否匹配，都要把报文写回输出（保持文件完整）
        match dissect(&data) {
            Ok(d) => {
                if let Some(dir) = direction(&filter, &d) {
                    match dir {
                        Dir::Ctos => report.matched_ctos += 1,
                        Dir::Stoc => report.matched_stoc += 1,
                    }
                    let before = endpoints(&data, &d);
                    let (s_ip, dd_ip, s_mac, d_mac) = resolve(&rewrite, dir);
                    let outcome = apply(&mut data, &d, s_ip, dd_ip, s_mac, d_mac);
                    if outcome.changed {
                        report.modified_packets += 1;
                    }
                    if outcome.version_mismatch {
                        version_mismatch += 1;
                    }
                    if report.samples.len() < SAMPLE_LIMIT {
                        report.samples.push(FlowSample {
                            index: report.total_packets,
                            direction: if dir == Dir::Ctos { "ctos" } else { "stoc" }.to_string(),
                            after: endpoints(&data, &d),
                            before,
                            changed: outcome.changed,
                        });
                    }
                }
            }
            Err(Skip::NonIp) => report.skipped_non_ip += 1,
            Err(Skip::NonTcpUdp) => report.skipped_non_tcpudp += 1,
            Err(Skip::Unsupported) => report.unsupported += 1,
        }

        if let Some(w) = writer.as_mut() {
            let out_pkt = PcapPacket {
                timestamp,
                orig_len,
                data: Cow::Owned(data),
            };
            w.write_packet(&out_pkt).map_err(|e| format!("写入数据包失败：{e}"))?;
        }
    }

    // 备注
    if rewrite.is_empty() {
        report.notes.push("未指定任何改写目标，本次仅统计匹配情况（输出与输入一致）".to_string());
    }
    if report.matched_ctos + report.matched_stoc == 0 {
        report.notes.push("没有报文匹配该五元组，请检查过滤条件（注意方向与 any 设置）".to_string());
    }
    if version_mismatch > 0 {
        report.notes.push(format!(
            "有 {version_mismatch} 个报文因 IP 版本与新地址不一致而未改写对应 IP（如对 IPv4 报文指定了 IPv6 新地址）"
        ));
    }
    if report.unsupported > 0 {
        report.notes.push(format!(
            "有 {} 个报文无法解析（截断 / IPv6 扩展头 / 异常），已原样保留",
            report.unsupported
        ));
    }

    drop(writer);
    Ok((report, if produce { Some(out) } else { None }))
}

// =============================  保存到磁盘  =============================

pub struct SavedEdit {
    pub filename: String,
    pub path: String,
    pub size: usize,
}

/// 把改写后的 pcap 字节写入目录（空 → 进程当前目录），返回文件名与绝对路径。
pub fn save(bytes: &[u8], output_dir: Option<&str>, filename: Option<&str>) -> Result<SavedEdit, String> {
    let (filename, path, size) = write_pcap_to_dir(bytes, output_dir, filename, "modified")?;
    Ok(SavedEdit { filename, path, size })
}

// =============================  测试  =============================

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::time::Duration;

    // ---- 构造测试用 pcap ----

    /// 组一个 Ethernet + IPv4 + TCP/UDP 报文，带正确校验和；payload 可选
    fn build_v4(
        dst_mac: [u8; 6],
        src_mac: [u8; 6],
        proto: u8,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&dst_mac);
        pkt.extend_from_slice(&src_mac);
        pkt.extend_from_slice(&[0x08, 0x00]); // IPv4

        let l4_len = if proto == 6 { 20 + payload.len() } else { 8 + payload.len() };
        let total = 20 + l4_len;

        let mut ip = vec![
            0x45, 0x00,
            (total >> 8) as u8, (total & 0xff) as u8,
            0x00, 0x01, 0x40, 0x00, 0x40, proto, 0x00, 0x00,
        ];
        ip.extend_from_slice(&src_ip);
        ip.extend_from_slice(&dst_ip);
        let c = internet_checksum(&ip);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        pkt.extend_from_slice(&ip);

        let l4_start = pkt.len();
        if proto == 6 {
            let mut tcp = vec![
                (src_port >> 8) as u8, (src_port & 0xff) as u8,
                (dst_port >> 8) as u8, (dst_port & 0xff) as u8,
                0, 0, 0, 1, 0, 0, 0, 0,
                0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            tcp.extend_from_slice(payload);
            pkt.extend_from_slice(&tcp);
        } else {
            let ulen = 8 + payload.len();
            let mut udp = vec![
                (src_port >> 8) as u8, (src_port & 0xff) as u8,
                (dst_port >> 8) as u8, (dst_port & 0xff) as u8,
                (ulen >> 8) as u8, (ulen & 0xff) as u8, 0x00, 0x00,
            ];
            udp.extend_from_slice(payload);
            pkt.extend_from_slice(&udp);
        }

        // 用被测代码本身算 L4 校验和，保证测试基线正确
        let d = dissect(&pkt).ok().unwrap();
        // 触发 L4 校验和计算：临时把 UDP 的 0 视为需要计算
        let _ = l4_start;
        recompute_l4_for_test(&mut pkt, &d);
        pkt
    }

    /// 测试辅助：无条件重算 L4 校验和（含 UDP 为 0 的情形）
    fn recompute_l4_for_test(buf: &mut [u8], d: &Dissected) {
        let ck_off = if d.proto == 6 { d.l4 + 16 } else { d.l4 + 6 };
        buf[ck_off] = 0;
        buf[ck_off + 1] = 0;
        let l4_len = d.ip_total - d.ihl;
        let mut data = Vec::new();
        data.extend_from_slice(&buf[d.l3 + 12..d.l3 + 16]);
        data.extend_from_slice(&buf[d.l3 + 16..d.l3 + 20]);
        data.push(0);
        data.push(d.proto);
        data.extend_from_slice(&(l4_len as u16).to_be_bytes());
        data.extend_from_slice(&buf[d.l4..d.l4 + l4_len]);
        let mut c = internet_checksum(&data);
        if c == 0 {
            c = 0xffff;
        }
        buf[ck_off..ck_off + 2].copy_from_slice(&c.to_be_bytes());
    }

    fn to_pcap(packets: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = PcapWriter::new(&mut buf).unwrap();
            for (i, p) in packets.iter().enumerate() {
                w.write_packet(&PcapPacket {
                    timestamp: Duration::from_secs(i as u64),
                    orig_len: p.len() as u32,
                    data: Cow::Borrowed(p),
                })
                .unwrap();
            }
        }
        buf
    }

    fn first_packet(pcap: &[u8]) -> Vec<u8> {
        let mut r = PcapReader::new(pcap).unwrap();
        r.next_packet().unwrap().unwrap().data.into_owned()
    }

    fn all_packets(pcap: &[u8]) -> Vec<Vec<u8>> {
        let mut r = PcapReader::new(pcap).unwrap();
        let mut v = Vec::new();
        while let Some(p) = r.next_packet() {
            v.push(p.unwrap().data.into_owned());
        }
        v
    }

    /// 校验一个 v4 TCP/UDP 报文的 IP 头与 L4 校验和是否自洽（重算后应为 0）
    fn checksums_valid(pkt: &[u8]) -> bool {
        let d = match dissect(pkt) {
            Ok(d) => d,
            Err(_) => return false,
        };
        // IP 头校验和
        if internet_checksum(&pkt[d.l3..d.l3 + d.ihl]) != 0 {
            return false;
        }
        // L4：UDP 校验和为 0 视为未启用，跳过
        let ck_off = if d.proto == 6 { d.l4 + 16 } else { d.l4 + 6 };
        let cur = u16::from_be_bytes([pkt[ck_off], pkt[ck_off + 1]]);
        if d.proto == 17 && cur == 0 {
            return true;
        }
        let l4_len = d.ip_total - d.ihl;
        let mut data = Vec::new();
        data.extend_from_slice(&pkt[d.l3 + 12..d.l3 + 16]);
        data.extend_from_slice(&pkt[d.l3 + 16..d.l3 + 20]);
        data.push(0);
        data.push(d.proto);
        data.extend_from_slice(&(l4_len as u16).to_be_bytes());
        data.extend_from_slice(&pkt[d.l4..d.l4 + l4_len]);
        internet_checksum(&data) == 0
    }

    const CLI_MAC: [u8; 6] = [0x00, 0x11, 0x11, 0x11, 0x11, 0x11];
    const SRV_MAC: [u8; 6] = [0x00, 0x22, 0x22, 0x22, 0x22, 0x22];
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];

    fn req(new_src_ip: &str, new_dst_ip: &str, new_src_mac: &str, new_dst_mac: &str) -> EditRequest {
        EditRequest {
            f_src_ip: "10.0.0.1".into(),
            f_dst_ip: "10.0.0.2".into(),
            f_src_port: "any".into(),
            f_dst_port: "80".into(),
            protocol: "tcp".into(),
            new_src_ip: new_src_ip.into(),
            new_dst_ip: new_dst_ip.into(),
            new_src_mac: new_src_mac.into(),
            new_dst_mac: new_dst_mac.into(),
        }
    }

    #[test]
    fn baseline_builder_makes_valid_checksums() {
        let p = build_v4(SRV_MAC, CLI_MAC, 6, A, B, 12345, 80, b"hello");
        assert!(checksums_valid(&p));
        let u = build_v4(SRV_MAC, CLI_MAC, 17, A, B, 12345, 53, b"dns");
        assert!(checksums_valid(&u));
    }

    #[test]
    fn rewrites_both_directions_consistently() {
        // 一条双向 TCP 流：ctos A->B，stoc B->A
        let ctos = build_v4(SRV_MAC, CLI_MAC, 6, A, B, 40000, 80, b"GET /");
        let stoc = build_v4(CLI_MAC, SRV_MAC, 6, B, A, 80, 40000, b"200 OK");
        let pcap = to_pcap(&[ctos, stoc]);

        // 改写：客户端 A/CLI_MAC → 1.1.1.1 / aa..，服务端 B/SRV_MAC → 2.2.2.2 / bb..
        let r = req("1.1.1.1", "2.2.2.2", "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb");
        let (report, out) = process(&pcap, &r, true).unwrap();
        assert_eq!(report.matched_ctos, 1);
        assert_eq!(report.matched_stoc, 1);
        assert_eq!(report.modified_packets, 2);

        let pkts = all_packets(&out.unwrap());

        // ctos：eth 源=aa 目的=bb，ip 源=1.1.1.1 目的=2.2.2.2
        let c = &pkts[0];
        assert_eq!(&c[0..6], &[0xbb; 6]); // 目的 MAC
        assert_eq!(&c[6..12], &[0xaa; 6]); // 源 MAC
        assert_eq!(&c[26..30], &[1, 1, 1, 1]); // 源 IP (l3=14, +12)
        assert_eq!(&c[30..34], &[2, 2, 2, 2]); // 目的 IP
        assert!(checksums_valid(c));

        // stoc：方向相反 —— eth 源=bb(服务端) 目的=aa(客户端)，ip 源=2.2.2.2 目的=1.1.1.1
        let s = &pkts[1];
        assert_eq!(&s[0..6], &[0xaa; 6]); // 目的 MAC = 客户端新 MAC
        assert_eq!(&s[6..12], &[0xbb; 6]); // 源 MAC = 服务端新 MAC
        assert_eq!(&s[26..30], &[2, 2, 2, 2]); // 源 IP = 服务端新 IP
        assert_eq!(&s[30..34], &[1, 1, 1, 1]); // 目的 IP = 客户端新 IP
        assert!(checksums_valid(s));
    }

    #[test]
    fn payload_is_preserved_and_checksum_follows_ip() {
        let ctos = build_v4(SRV_MAC, CLI_MAC, 6, A, B, 40000, 80, b"PAYLOAD-1234");
        let pcap = to_pcap(&[ctos]);
        let r = req("9.9.9.9", "", "", "");
        let (_rep, out) = process(&pcap, &r, true).unwrap();
        let p = first_packet(&out.unwrap());
        let d = dissect(&p).unwrap();
        // payload 原样
        assert_eq!(&p[d.l4 + 20..], b"PAYLOAD-1234");
        // IP 改了，校验和自洽
        assert_eq!(&p[26..30], &[9, 9, 9, 9]);
        assert!(checksums_valid(&p));
    }

    #[test]
    fn udp_and_mac_only_change_leaves_l4_checksum_untouched() {
        // 仅改 MAC 不应触碰 L4/IP 校验和
        let ctos = build_v4(SRV_MAC, CLI_MAC, 17, A, B, 5000, 53, b"query");
        let pcap = to_pcap(&[ctos.clone()]);
        let mut r = req("", "", "ff:ff:ff:ff:ff:ff", "");
        r.protocol = "udp".into();
        r.f_dst_port = "53".into();
        let (rep, out) = process(&pcap, &r, true).unwrap();
        assert_eq!(rep.modified_packets, 1);
        let p = first_packet(&out.unwrap());
        assert_eq!(&p[6..12], &[0xff; 6]);
        // L4 校验和与原包一致（IP 未变）
        let d = dissect(&p).unwrap();
        assert_eq!(&p[d.l4 + 6..d.l4 + 8], &ctos[dissect(&ctos).unwrap().l4 + 6..dissect(&ctos).unwrap().l4 + 8]);
        assert!(checksums_valid(&p));
    }

    #[test]
    fn any_filter_matches_all_as_forward() {
        let p1 = build_v4(SRV_MAC, CLI_MAC, 6, A, B, 1, 2, b"x");
        let p2 = build_v4(CLI_MAC, SRV_MAC, 6, B, A, 2, 1, b"y");
        let pcap = to_pcap(&[p1, p2]);
        let r = EditRequest {
            protocol: "any".into(),
            new_src_mac: "de:ad:be:ef:00:01".into(),
            ..Default::default()
        };
        let (rep, _out) = process(&pcap, &r, false).unwrap();
        // 全 any → 每个 TCP 包都按正向匹配
        assert_eq!(rep.matched_ctos, 2);
        assert_eq!(rep.matched_stoc, 0);
        assert_eq!(rep.modified_packets, 2);
    }

    #[test]
    fn non_matching_and_non_tcpudp_are_left_alone() {
        // ICMP（proto=1）应计入 non-tcpudp，且原样保留
        let mut icmp = build_v4(SRV_MAC, CLI_MAC, 6, A, B, 1, 2, b"z");
        icmp[23] = 1; // 把 IP proto 改成 ICMP（破坏校验和无妨，只测分类）
        let tcp = build_v4(SRV_MAC, CLI_MAC, 6, [9, 9, 9, 9], B, 1, 2, b"z"); // 源 IP 不匹配
        let pcap = to_pcap(&[icmp, tcp]);
        let r = req("1.2.3.4", "", "", ""); // filter src=10.0.0.1
        let (rep, out) = process(&pcap, &r, true).unwrap();
        assert_eq!(rep.skipped_non_tcpudp, 1);
        assert_eq!(rep.matched_ctos, 0); // tcp 包源 IP 9.9.9.9 不匹配 10.0.0.1
        // 输出包数与输入一致
        assert_eq!(all_packets(&out.unwrap()).len(), 2);
    }

    #[test]
    fn ip_version_mismatch_is_reported_not_applied() {
        let ctos = build_v4(SRV_MAC, CLI_MAC, 6, A, B, 40000, 80, b"x");
        let pcap = to_pcap(&[ctos]);
        // 对 IPv4 报文指定 IPv6 新地址 → 不改 IP，但可改 MAC
        let r = req("::1", "", "aa:bb:cc:dd:ee:ff", "");
        let (rep, out) = process(&pcap, &r, true).unwrap();
        assert!(rep.notes.iter().any(|n| n.contains("IP 版本")));
        let p = first_packet(&out.unwrap());
        assert_eq!(&p[6..12], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // MAC 改了
        assert_eq!(&p[26..30], &A); // IP 未改
        assert!(checksums_valid(&p));
    }

    #[test]
    fn vlan_tagged_packet_is_parsed() {
        // 在以太类型前插入一个 802.1Q 标签
        let mut ctos = build_v4(SRV_MAC, CLI_MAC, 6, A, B, 40000, 80, b"v");
        let mut tagged = Vec::new();
        tagged.extend_from_slice(&ctos[0..12]);
        tagged.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]); // VLAN 100
        tagged.extend_from_slice(&ctos[12..]); // 原 ethertype + IP...
        std::mem::swap(&mut ctos, &mut tagged);
        let pcap = to_pcap(&[ctos]);
        let r = req("7.7.7.7", "", "", "");
        let (rep, out) = process(&pcap, &r, true).unwrap();
        assert_eq!(rep.matched_ctos, 1);
        let p = first_packet(&out.unwrap());
        // l3 现在从 18 开始，源 IP 在 +12 = 30
        assert_eq!(&p[30..34], &[7, 7, 7, 7]);
        assert!(checksums_valid(&p));
    }

    #[test]
    fn preview_does_not_produce_output() {
        let ctos = build_v4(SRV_MAC, CLI_MAC, 6, A, B, 40000, 80, b"x");
        let pcap = to_pcap(&[ctos]);
        let r = req("1.1.1.1", "", "", "");
        let (rep, out) = process(&pcap, &r, false).unwrap();
        assert!(out.is_none());
        assert_eq!(rep.matched_ctos, 1);
        assert_eq!(rep.samples.len(), 1);
        assert!(rep.samples[0].before.contains("10.0.0.1"));
        assert!(rep.samples[0].after.contains("1.1.1.1"));
    }

    #[test]
    fn rejects_bad_params_and_pcapng() {
        let ctos = build_v4(SRV_MAC, CLI_MAC, 6, A, B, 1, 2, b"x");
        let pcap = to_pcap(&[ctos]);
        let mut r = req("", "", "", "");
        r.f_src_ip = "999.1.1.1".into();
        assert!(process(&pcap, &r, false).is_err());

        let mut r = req("", "", "zz:zz:zz:zz:zz:zz", "");
        r.f_src_ip = "10.0.0.1".into();
        assert!(process(&pcap, &r, false).is_err());

        // pcapng 魔数
        let ng = vec![0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0];
        assert!(process(&ng, &req("1.1.1.1", "", "", ""), false).unwrap_err().contains("pcapng"));
    }

    #[test]
    fn empty_rewrite_counts_matches_only() {
        let ctos = build_v4(SRV_MAC, CLI_MAC, 6, A, B, 40000, 80, b"x");
        let pcap = to_pcap(&[ctos]);
        let r = req("", "", "", "");
        let (rep, _out) = process(&pcap, &r, false).unwrap();
        assert_eq!(rep.matched_ctos, 1);
        assert_eq!(rep.modified_packets, 0);
        assert!(rep.notes.iter().any(|n| n.contains("未指定")));
    }
}
