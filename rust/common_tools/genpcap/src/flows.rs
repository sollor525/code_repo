//! 各协议的报文序列生成。
//!
//! TCP 类（TCP 模式 / HTTP / FTP / SSH / MySQL）经 [`TcpConversation`] 构造，seq/ack
//! 自洽；ICMP / UDP 经 [`crate::l4`] 直接构造（IPv4）。应用层协议（FTP/SSH/MySQL）使用
//! **代表性载荷**，足以让 Wireshark 按对应解析器识别，并非完整协议状态机。

use std::net::IpAddr;

use crate::conversation::TcpConversation;
use crate::core::session::{
    FtpMode, HttpConfig, IcmpConfig, TcpMode, TcpSession, UdpConfig,
};
use crate::l4;

const SERVER_ISN_OFFSET: u32 = 0x9E3779B9;

fn conv(session: &TcpSession, src_port: u16, dst_port: u16, salt: u32) -> TcpConversation {
    let c = &session.connection;
    TcpConversation::new(
        c.src_mac,
        c.dst_mac,
        c.src_ip,
        c.dst_ip,
        src_port,
        dst_port,
        session.isn.wrapping_add(salt),
        session.isn.wrapping_add(SERVER_ISN_OFFSET).wrapping_add(salt),
    )
}

/// CRLF 规范化：把单独的 \n 也补成 \r\n（便于用户直接粘贴文本）。
fn normalize_crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

// ============================== TCP 模式 ==============================

pub fn tcp_mode(session: &TcpSession, mode: TcpMode) -> Vec<Vec<u8>> {
    let c = &session.connection;
    let mut tc = conv(session, c.src_port, c.dst_port, 0);
    match mode {
        TcpMode::SynOnly => tc.syn_only(),
        TcpMode::Handshake => tc.handshake(),
        TcpMode::HandshakeClose => {
            tc.handshake();
            tc.close_graceful();
        }
        TcpMode::HandshakeReset => {
            tc.handshake();
            tc.reset();
        }
    }
    tc.into_packets()
}

// ================================ HTTP ================================

fn default_http_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nServer: ByteBench\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

pub fn http(session: &TcpSession, cfg: &HttpConfig) -> Vec<Vec<u8>> {
    let c = &session.connection;
    let mut tc = conv(session, c.src_port, c.dst_port, 0);
    tc.handshake();

    let custom_resp = cfg.response_content.as_ref().map(|r| normalize_crlf(r).into_bytes());

    if let Some(req) = cfg.request_content.as_ref() {
        // 自定义请求内容（原样发送），仅一次往返
        tc.client_data(normalize_crlf(req).as_bytes());
        let resp = custom_resp.unwrap_or_else(|| default_http_response("{\"ok\":true}"));
        tc.server_data(&resp);
    } else {
        let uris = if cfg.uris.is_empty() {
            vec!["/".to_string()]
        } else {
            cfg.uris.clone()
        };
        for uri in &uris {
            let req = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ByteBench/0.1\r\n\
                 Accept: */*\r\nConnection: keep-alive\r\n\r\n",
                uri, cfg.host
            );
            tc.client_data(req.as_bytes());
            let resp = custom_resp
                .clone()
                .unwrap_or_else(|| default_http_response(&format!("{{\"uri\":\"{}\",\"ok\":true}}", uri)));
            tc.server_data(&resp);
        }
    }

    tc.close_graceful();
    tc.into_packets()
}

// ============================== ICMP / UDP ==============================

fn as_v4(ip: IpAddr) -> Option<std::net::Ipv4Addr> {
    match ip {
        IpAddr::V4(a) => Some(a),
        IpAddr::V6(_) => None,
    }
}

pub fn icmp(session: &TcpSession, cfg: &IcmpConfig) -> Vec<Vec<u8>> {
    let c = &session.connection;
    let (Some(src), Some(dst)) = (as_v4(c.src_ip), as_v4(c.dst_ip)) else {
        return Vec::new(); // 非 IPv4：由 pcap_generator 上游拦截
    };
    let payload: &[u8] = b"abcdefghijklmnopqrstuvwabcdefghi"; // 32 字节，典型 ping 载荷
    let n = cfg.count.max(1);
    let mut out = Vec::with_capacity((n * 2) as usize);
    for seq in 0..n as u16 {
        out.push(l4::build_icmp_echo(c.src_mac, c.dst_mac, src, dst, 0x1234, seq, payload, true));
        out.push(l4::build_icmp_echo(c.dst_mac, c.src_mac, dst, src, 0x1234, seq, payload, false));
    }
    out
}

pub fn udp(session: &TcpSession, cfg: &UdpConfig) -> Vec<Vec<u8>> {
    let c = &session.connection;
    let (Some(src), Some(dst)) = (as_v4(c.src_ip), as_v4(c.dst_ip)) else {
        return Vec::new();
    };
    let payload = if cfg.payload.is_empty() {
        b"ByteBench UDP payload".to_vec()
    } else {
        cfg.payload.clone()
    };
    let mut out = Vec::new();
    out.push(l4::build_udp(c.src_mac, c.dst_mac, src, dst, c.src_port, c.dst_port, &payload));
    if cfg.with_response {
        out.push(l4::build_udp(
            c.dst_mac, c.src_mac, dst, src, c.dst_port, c.src_port,
            b"ByteBench UDP response",
        ));
    }
    out
}

// ================================ FTP ================================

/// FTP PORT / PASV 的 h1,h2,h3,h4,p1,p2 形式
fn host_port_tuple(ip: IpAddr, port: u16) -> String {
    let o = match ip {
        IpAddr::V4(a) => a.octets(),
        IpAddr::V6(_) => [127, 0, 0, 1],
    };
    format!("{},{},{},{},{},{}", o[0], o[1], o[2], o[3], port >> 8, port & 0xff)
}

pub fn ftp(session: &TcpSession, mode: FtpMode) -> Vec<Vec<u8>> {
    let c = &session.connection;
    let mut out: Vec<Vec<u8>> = Vec::new();

    // 控制连接（默认 dst_port 21）
    let mut ctrl = conv(session, c.src_port, c.dst_port, 0);
    ctrl.handshake();
    ctrl.server_data(b"220 (ByteBench FTP)\r\n");
    ctrl.client_data(b"USER anonymous\r\n");
    ctrl.server_data(b"331 Please specify the password.\r\n");
    ctrl.client_data(b"PASS guest@example.com\r\n");
    ctrl.server_data(b"230 Login successful.\r\n");
    ctrl.client_data(b"TYPE I\r\n");
    ctrl.server_data(b"200 Switching to Binary mode.\r\n");

    let data_port: u16 = 50_000;
    let file_payload: &[u8] = b"ByteBench FTP demo file contents.\nLine 2.\n";

    match mode {
        FtpMode::Passive => {
            ctrl.client_data(b"PASV\r\n");
            let line = format!(
                "227 Entering Passive Mode ({}).\r\n",
                host_port_tuple(c.dst_ip, data_port)
            );
            ctrl.server_data(line.as_bytes());
            ctrl.client_data(b"RETR demo.txt\r\n");
            ctrl.server_data(b"150 Opening BINARY mode data connection for demo.txt.\r\n");
            out.extend(ctrl.take());

            // 数据连接：客户端 -> 服务器被动端口
            let mut dc = TcpConversation::new(
                c.src_mac, c.dst_mac, c.src_ip, c.dst_ip,
                c.src_port.wrapping_add(1), data_port,
                session.isn.wrapping_add(0x100),
                session.isn.wrapping_add(SERVER_ISN_OFFSET).wrapping_add(0x100),
            );
            dc.handshake();
            dc.server_data(file_payload);
            dc.close_graceful();
            out.extend(dc.into_packets());

            ctrl.server_data(b"226 Transfer complete.\r\n");
        }
        FtpMode::Active => {
            let port_line = format!("PORT {}\r\n", host_port_tuple(c.src_ip, data_port));
            ctrl.client_data(port_line.as_bytes());
            ctrl.server_data(b"200 PORT command successful. Consider using PASV.\r\n");
            ctrl.client_data(b"RETR demo.txt\r\n");
            ctrl.server_data(b"150 Opening BINARY mode data connection for demo.txt.\r\n");
            out.extend(ctrl.take());

            // 数据连接：服务器(20) 主动连客户端(data_port)，故服务器为发起方
            let mut dc = TcpConversation::new(
                c.dst_mac, c.src_mac, c.dst_ip, c.src_ip,
                20, data_port,
                session.isn.wrapping_add(SERVER_ISN_OFFSET).wrapping_add(0x200),
                session.isn.wrapping_add(0x200),
            );
            dc.handshake();
            dc.client_data(file_payload); // 此处 "client" 即服务器(20)，向客户端发数据
            dc.close_graceful();
            out.extend(dc.into_packets());

            ctrl.server_data(b"226 Transfer complete.\r\n");
        }
    }

    ctrl.client_data(b"QUIT\r\n");
    ctrl.server_data(b"221 Goodbye.\r\n");
    ctrl.close_graceful();
    out.extend(ctrl.into_packets());
    out
}

// ================================ SSH ================================

/// 构造一个代表性的 SSH KEXINIT 二进制包（含真实算法名列表）。
fn ssh_kexinit() -> Vec<u8> {
    let cookie: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    ];
    let name_lists = [
        "curve25519-sha256",
        "ssh-ed25519",
        "aes128-ctr",
        "aes128-ctr",
        "hmac-sha2-256",
        "hmac-sha2-256",
        "none",
        "none",
        "",
        "",
    ];
    let mut payload = Vec::new();
    payload.push(20u8); // SSH_MSG_KEXINIT
    payload.extend_from_slice(&cookie);
    for nl in name_lists {
        payload.extend_from_slice(&(nl.len() as u32).to_be_bytes());
        payload.extend_from_slice(nl.as_bytes());
    }
    payload.push(0); // first_kex_packet_follows
    payload.extend_from_slice(&[0, 0, 0, 0]); // reserved

    // SSH 二进制分组：packet_length(4) + padding_length(1) + payload + padding
    let mut padding_len = 8 - ((1 + payload.len() + 4) % 8);
    if padding_len < 4 {
        padding_len += 8;
    }
    let packet_len = 1 + payload.len() + padding_len;
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&(packet_len as u32).to_be_bytes());
    pkt.push(padding_len as u8);
    pkt.extend_from_slice(&payload);
    pkt.extend(std::iter::repeat(0u8).take(padding_len));
    pkt
}

pub fn ssh(session: &TcpSession) -> Vec<Vec<u8>> {
    let c = &session.connection;
    let mut tc = conv(session, c.src_port, c.dst_port, 0);
    tc.handshake();
    // 版本交换（Wireshark 据此识别 SSH 协议）
    tc.client_data(b"SSH-2.0-OpenSSH_8.9p1 ByteBench\r\n");
    tc.server_data(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n");
    // 密钥交换初始化
    let kex = ssh_kexinit();
    tc.client_data(&kex);
    tc.server_data(&kex);
    tc.close_graceful();
    tc.into_packets()
}

// ================================ MySQL ===============================

/// MySQL 分组：3 字节小端长度 + 1 字节序号 + 负载
fn mysql_packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut p = Vec::with_capacity(4 + len);
    p.push((len & 0xff) as u8);
    p.push(((len >> 8) & 0xff) as u8);
    p.push(((len >> 16) & 0xff) as u8);
    p.push(seq);
    p.extend_from_slice(payload);
    p
}

/// 服务器握手包（protocol 10 / HandshakeV10），代表性字段
fn mysql_server_greeting() -> Vec<u8> {
    let mut b = Vec::new();
    b.push(10); // protocol version
    b.extend_from_slice(b"8.0.34-ByteBench\0"); // server version (NUL 结尾)
    b.extend_from_slice(&0x0000_002au32.to_le_bytes()); // thread id
    b.extend_from_slice(b"\x01\x02\x03\x04\x05\x06\x07\x08"); // auth-plugin-data-part-1 (8)
    b.push(0); // filler
    b.extend_from_slice(&0xffffu16.to_le_bytes()); // capability flags (lower)
    b.push(0x21); // character set (utf8)
    b.extend_from_slice(&0x0002u16.to_le_bytes()); // status flags
    b.extend_from_slice(&0xc0ffu16.to_le_bytes()); // capability flags (upper)
    b.push(21); // length of auth-plugin-data
    b.extend_from_slice(&[0u8; 10]); // reserved
    b.extend_from_slice(b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\0"); // auth-plugin-data-part-2 (12, NUL)
    b.extend_from_slice(b"mysql_native_password\0");
    mysql_packet(0, &b)
}

/// 客户端登录请求（HandshakeResponse41，代表性）
fn mysql_login_request() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0x000a_a685u32.to_le_bytes()); // client capabilities
    b.extend_from_slice(&0x0100_0000u32.to_le_bytes()); // max packet size
    b.push(0x21); // charset
    b.extend_from_slice(&[0u8; 23]); // reserved
    b.extend_from_slice(b"root\0"); // username
    b.push(20); // auth-response length
    b.extend_from_slice(&[0xab; 20]); // auth-response
    b.extend_from_slice(b"mysql_native_password\0");
    mysql_packet(1, &b)
}

fn mysql_ok(seq: u8) -> Vec<u8> {
    // OK: header 0x00, affected_rows 0, last_insert_id 0, status_flags, warnings
    mysql_packet(seq, &[0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
}

fn mysql_com_query(sql: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(1 + sql.len());
    b.push(0x03); // COM_QUERY
    b.extend_from_slice(sql.as_bytes());
    mysql_packet(0, &b)
}

/// `SELECT 1` 的结果集（列数 / 列定义 / EOF / 行 / EOF，拼接为一个 TCP 段）
fn mysql_select1_result() -> Vec<u8> {
    let mut out = Vec::new();
    // 列数 = 1
    out.extend_from_slice(&mysql_packet(1, &[0x01]));
    // 列定义（catalog "def" + 多个空字符串 + 列名 "1"）
    let mut col = Vec::new();
    for s in ["def", "", "", "", "1", ""] {
        col.push(s.len() as u8);
        col.extend_from_slice(s.as_bytes());
    }
    col.extend_from_slice(&[0x0c]); // length of fixed fields
    col.extend_from_slice(&0x3fu16.to_le_bytes()); // charset
    col.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // column length
    col.push(0x03); // type = LONG
    col.extend_from_slice(&0x0000u16.to_le_bytes()); // flags
    col.push(0x00); // decimals
    col.extend_from_slice(&[0x00, 0x00]); // filler
    out.extend_from_slice(&mysql_packet(2, &col));
    // EOF
    out.extend_from_slice(&mysql_packet(3, &[0xfe, 0x00, 0x00, 0x02, 0x00]));
    // 行：一个字段 "1"
    out.extend_from_slice(&mysql_packet(4, &[0x01, b'1']));
    // EOF
    out.extend_from_slice(&mysql_packet(5, &[0xfe, 0x00, 0x00, 0x02, 0x00]));
    out
}

pub fn mysql(session: &TcpSession) -> Vec<Vec<u8>> {
    let c = &session.connection;
    let mut tc = conv(session, c.src_port, c.dst_port, 0);
    tc.handshake();
    tc.server_data(&mysql_server_greeting());
    tc.client_data(&mysql_login_request());
    tc.server_data(&mysql_ok(2));
    tc.client_data(&mysql_com_query("SELECT 1"));
    tc.server_data(&mysql_select1_result());
    tc.client_data(&mysql_packet(0, &[0x01])); // COM_QUIT
    tc.close_graceful();
    tc.into_packets()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::network::NetworkConnection;
    use std::net::{IpAddr, Ipv4Addr};

    fn sess() -> TcpSession {
        let conn = NetworkConnection::new(
            [0, 1, 2, 3, 4, 5],
            [6, 7, 8, 9, 10, 11],
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1234,
            80,
        );
        TcpSession::new(conn, 1000)
    }

    /// TCP 标志位（offset 47 = eth14 + ip20 + tcp 第 13 字节）
    fn flags(frame: &[u8]) -> u8 {
        frame[47]
    }

    #[test]
    fn tcp_mode_packet_counts_and_flags() {
        const SYN: u8 = 0x02;
        const RST: u8 = 0x04;
        const FIN: u8 = 0x01;

        let syn = tcp_mode(&sess(), TcpMode::SynOnly);
        assert_eq!(syn.len(), 1);
        assert_eq!(flags(&syn[0]) & SYN, SYN);

        assert_eq!(tcp_mode(&sess(), TcpMode::Handshake).len(), 3);

        let close = tcp_mode(&sess(), TcpMode::HandshakeClose);
        assert_eq!(close.len(), 7);
        assert!(close.iter().any(|p| flags(p) & FIN == FIN));

        let reset = tcp_mode(&sess(), TcpMode::HandshakeReset);
        assert_eq!(reset.len(), 4);
        assert_eq!(flags(&reset[3]) & RST, RST);
    }

    #[test]
    fn icmp_and_udp_counts() {
        assert_eq!(icmp(&sess(), &IcmpConfig { count: 2 }).len(), 4);
        // ICMP echo: 第一个为请求(type 8)，第二个为应答(type 0)
        let ic = icmp(&sess(), &IcmpConfig { count: 1 });
        assert_eq!(ic[0][34], 8);
        assert_eq!(ic[1][34], 0);

        let u = udp(&sess(), &UdpConfig { payload: vec![], with_response: true });
        assert_eq!(u.len(), 2);
        assert_eq!(u[0][23], 17); // IP proto = UDP
    }

    #[test]
    fn app_protocols_nonempty() {
        assert!(!ssh(&sess()).is_empty());
        assert!(!mysql(&sess()).is_empty());
        assert!(!ftp(&sess(), FtpMode::Passive).is_empty());
        assert!(!ftp(&sess(), FtpMode::Active).is_empty());
        let h = http(&sess(), &HttpConfig {
            uris: vec!["/".into()],
            host: "x".into(),
            request_content: None,
            response_content: None,
        });
        assert_eq!(h.len(), 11);
    }
}
