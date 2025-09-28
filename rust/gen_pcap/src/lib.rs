
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::MutablePacket;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use pnet::packet::tcp;
use pnet::packet::ipv4;
use std::collections::HashMap;

// HTTP方法枚举
#[derive(Debug, Clone)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::PUT => "PUT",
            HttpMethod::DELETE => "DELETE",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::OPTIONS => "OPTIONS",
            HttpMethod::PATCH => "PATCH",
        }
    }
}

// HTTP版本枚举
#[derive(Debug, Clone)]
pub enum HttpVersion {
    Http1_0,
    Http1_1,
    Http2_0,
}

impl HttpVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpVersion::Http1_0 => "HTTP/1.0",
            HttpVersion::Http1_1 => "HTTP/1.1",
            HttpVersion::Http2_0 => "HTTP/2.0",
        }
    }
}

// HTTP状态码枚举
#[derive(Debug, Clone)]
pub enum HttpStatusCode {
    Ok,
    NotFound,
    InternalServerError,
    BadRequest,
    Unauthorized,
    Forbidden,
    Custom(u16),
}

impl HttpStatusCode {
    pub fn code(&self) -> u16 {
        match self {
            HttpStatusCode::Ok => 200,
            HttpStatusCode::NotFound => 404,
            HttpStatusCode::InternalServerError => 500,
            HttpStatusCode::BadRequest => 400,
            HttpStatusCode::Unauthorized => 401,
            HttpStatusCode::Forbidden => 403,
            HttpStatusCode::Custom(code) => *code,
        }
    }

    pub fn reason_phrase(&self) -> &'static str {
        match self {
            HttpStatusCode::Ok => "OK",
            HttpStatusCode::NotFound => "Not Found",
            HttpStatusCode::InternalServerError => "Internal Server Error",
            HttpStatusCode::BadRequest => "Bad Request",
            HttpStatusCode::Unauthorized => "Unauthorized",
            HttpStatusCode::Forbidden => "Forbidden",
            HttpStatusCode::Custom(_) => "Custom",
        }
    }
}

// HTTP请求结构体
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub uri: String,
    pub version: HttpVersion,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

// HTTP响应结构体
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: HttpVersion,
    pub status_code: HttpStatusCode,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    pub fn new(method: HttpMethod, uri: String) -> Self {
        Self {
            method,
            uri,
            version: HttpVersion::Http1_1,
            headers: HashMap::new(),
            body: None,
        }
    }

    pub fn with_version(mut self, version: HttpVersion) -> Self {
        self.version = version;
        self
    }

    pub fn add_header(mut self, key: String, value: String) -> Self {
        self.headers.insert(key, value);
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut request = String::new();
        
        // 请求行
        request.push_str(&format!("{} {} {}\r\n", 
            self.method.as_str(), 
            self.uri, 
            self.version.as_str()
        ));
        
        // 添加默认头部
        let mut headers = self.headers.clone();
        if !headers.contains_key("Host") {
            headers.insert("Host".to_string(), "localhost".to_string());
        }
        if !headers.contains_key("User-Agent") {
            headers.insert("User-Agent".to_string(), "gen_pcap/1.0".to_string());
        }
        if !headers.contains_key("Accept") {
            headers.insert("Accept".to_string(), "*/*".to_string());
        }
        if let Some(ref body) = self.body {
            headers.insert("Content-Length".to_string(), body.len().to_string());
        }
        
        // 头部
        for (key, value) in &headers {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }
        
        // 空行
        request.push_str("\r\n");
        
        let mut result = request.into_bytes();
        
        // 添加请求体
        if let Some(ref body) = self.body {
            result.extend_from_slice(body);
        }
        
        result
    }
}

impl HttpResponse {
    pub fn new(status_code: HttpStatusCode) -> Self {
        Self {
            version: HttpVersion::Http1_1,
            status_code,
            headers: HashMap::new(),
            body: None,
        }
    }

    pub fn with_version(mut self, version: HttpVersion) -> Self {
        self.version = version;
        self
    }

    pub fn add_header(mut self, key: String, value: String) -> Self {
        self.headers.insert(key, value);
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut response = String::new();
        
        // 状态行
        response.push_str(&format!("{} {} {}\r\n", 
            self.version.as_str(),
            self.status_code.code(),
            self.status_code.reason_phrase()
        ));
        
        // 添加默认头部
        let mut headers = self.headers.clone();
        if !headers.contains_key("Server") {
            headers.insert("Server".to_string(), "gen_pcap/1.0".to_string());
        }
        if let Some(ref body) = self.body {
            headers.insert("Content-Length".to_string(), body.len().to_string());
        }
        
        // 头部
        for (key, value) in &headers {
            response.push_str(&format!("{}: {}\r\n", key, value));
        }
        
        // 空行
        response.push_str("\r\n");
        
        let mut result = response.into_bytes();
        
        // 添加响应体
        if let Some(ref body) = self.body {
            result.extend_from_slice(body);
        }
        
        result
    }
}

pub fn build_tcp_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
) -> Vec<u8> {
    let mut tcp_buf = vec![0u8; 20];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(seq);
    tcp_header.set_acknowledgement(ack);
    tcp_header.set_data_offset(5);
    tcp_header.set_flags(flags);
    tcp_header.set_window(64240);
    tcp_header.set_checksum(0); // 内核会计算，这里留空即可
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
    tcp_header.set_checksum(checksum);

    let mut ip_buf = vec![0u8; 20];
    let mut ip4_header = MutableIpv4Packet::new(&mut ip_buf).unwrap();
    ip4_header.set_version(4);
    ip4_header.set_header_length(5);
    ip4_header.set_total_length((20 + tcp_buf.len()) as u16);
    ip4_header.set_identification(0xabcd);
    ip4_header.set_flags(0x02); // DF
    ip4_header.set_ttl(64);
    ip4_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip4_header.set_source(src_ip);
    ip4_header.set_destination(dst_ip);
    let checksum = ipv4::checksum(&ip4_header.to_immutable());
    ip4_header.set_checksum(checksum);

    let mut eth_buf = vec![0u8; 14 + 20 + tcp_buf.len()];
    let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_pkt.set_destination(MacAddr::from(dst_mac));
    eth_pkt.set_source(MacAddr::from(src_mac));
    eth_pkt.set_ethertype(EtherTypes::Ipv4);
    eth_pkt.payload_mut()[..20].copy_from_slice(&ip_buf);
    eth_pkt.payload_mut()[20..].copy_from_slice(&tcp_buf);
    eth_buf
}


// 构建包含HTTP请求的TCP包
pub fn build_http_request_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    http_request: &HttpRequest,
) -> Vec<u8> {
    let http_data = http_request.to_bytes();
    build_tcp_packet_with_data(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, &http_data)
}

// 构建包含HTTP响应的TCP包
pub fn build_http_response_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    http_response: &HttpResponse,
) -> Vec<u8> {
    let http_data = http_response.to_bytes();
    build_tcp_packet_with_data(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, &http_data)
}

// 构建包含数据的TCP包
pub fn build_tcp_packet_with_data(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut tcp_buf = vec![0u8; 20 + data.len()];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(seq);
    tcp_header.set_acknowledgement(ack);
    tcp_header.set_data_offset(5);
    tcp_header.set_flags(flags);
    tcp_header.set_window(64240);
    tcp_header.set_checksum(0); // 内核会计算，这里留空即可
    
    // 复制数据到TCP载荷
    tcp_header.payload_mut().copy_from_slice(data);
    
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
    tcp_header.set_checksum(checksum);

    let mut ip_buf = vec![0u8; 20];
    let mut ip4_header = MutableIpv4Packet::new(&mut ip_buf).unwrap();
    ip4_header.set_version(4);
    ip4_header.set_header_length(5);
    ip4_header.set_total_length((20 + tcp_buf.len()) as u16);
    ip4_header.set_identification(0xabcd);
    ip4_header.set_flags(0x02); // DF
    ip4_header.set_ttl(64);
    ip4_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip4_header.set_source(src_ip);
    ip4_header.set_destination(dst_ip);
    let checksum = ipv4::checksum(&ip4_header.to_immutable());
    ip4_header.set_checksum(checksum);

    let mut eth_buf = vec![0u8; 14 + 20 + tcp_buf.len()];
    let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_pkt.set_destination(MacAddr::from(dst_mac));
    eth_pkt.set_source(MacAddr::from(src_mac));
    eth_pkt.set_ethertype(EtherTypes::Ipv4);
    eth_pkt.payload_mut()[..20].copy_from_slice(&ip_buf);
    eth_pkt.payload_mut()[20..].copy_from_slice(&tcp_buf);
    eth_buf
}

// 便利函数：构建简单的HTTP GET请求包
pub fn build_http_get_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    uri: &str,
    host: &str,
) -> Vec<u8> {
    let request = HttpRequest::new(HttpMethod::GET, uri.to_string())
        .add_header("Host".to_string(), host.to_string())
        .add_header("Connection".to_string(), "close".to_string());
    
    build_http_request_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, &request)
}

// 便利函数：构建简单的HTTP POST请求包
pub fn build_http_post_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    uri: &str,
    host: &str,
    content_type: &str,
    body: &[u8],
) -> Vec<u8> {
    let request = HttpRequest::new(HttpMethod::POST, uri.to_string())
        .add_header("Host".to_string(), host.to_string())
        .add_header("Content-Type".to_string(), content_type.to_string())
        .add_header("Connection".to_string(), "close".to_string())
        .with_body(body.to_vec());
    
    build_http_request_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, &request)
}

// 便利函数：构建HTTP响应包
pub fn build_http_response_packet_simple(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    status_code: HttpStatusCode,
    content_type: &str,
    body: &[u8],
) -> Vec<u8> {
    let response = HttpResponse::new(status_code)
        .add_header("Content-Type".to_string(), content_type.to_string())
        .add_header("Connection".to_string(), "close".to_string())
        .with_body(body.to_vec());
    
    build_http_response_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, &response)
}

// 保持向后兼容的旧函数
pub fn build_http_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
) -> Vec<u8> {
    // 构建一个简单的GET请求
    build_http_get_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, "/", "localhost")
}

// TCP连接状态跟踪结构体
#[derive(Debug, Clone)]
pub struct TcpConnection {
    pub client_seq: u32,
    pub server_seq: u32,
    pub client_ack: u32,
    pub server_ack: u32,
}

impl TcpConnection {
    pub fn new(isn: u32) -> Self {
        Self {
            client_seq: isn,
            server_seq: isn,
            client_ack: isn,
            server_ack: isn,
        }
    }

    // 更新序列号（发送数据后）
    pub fn update_seq(&mut self, is_client: bool, data_len: u32) {
        if is_client {
            self.client_seq += data_len;
        } else {
            self.server_seq += data_len;
        }
    }

    // 更新确认号（接收数据后）
    pub fn update_ack(&mut self, is_client: bool, data_len: u32) {
        if is_client {
            self.client_ack += data_len;
        } else {
            self.server_ack += data_len;
        }
    }

    // 获取当前序列号和确认号
    pub fn get_seq_ack(&self, is_client: bool) -> (u32, u32) {
        if is_client {
            (self.client_seq, self.client_ack)
        } else {
            (self.server_seq, self.server_ack)
        }
    }
}

// 封装TCP三次握手
pub fn build_tcp_handshake_packets(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    isn: u32,
) -> (Vec<Vec<u8>>, TcpConnection) {
    let mut packets = Vec::new();
    let mut conn = TcpConnection::new(isn);

    // 1) SYN
    let syn = build_tcp_packet(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
        conn.client_seq, 0, pnet::packet::tcp::TcpFlags::SYN,
    );
    packets.push(syn);
    conn.update_seq(true, 1); // SYN占用1个序列号

    // 2) SYN/ACK
    let syn_ack = build_tcp_packet(
        dst_mac, src_mac, dst_ip, src_ip, dst_port, src_port,
        conn.server_seq, conn.client_seq, 
        pnet::packet::tcp::TcpFlags::SYN | pnet::packet::tcp::TcpFlags::ACK,
    );
    packets.push(syn_ack);
    conn.update_seq(false, 1); // SYN占用1个序列号
    conn.update_ack(false, 1); // 确认客户端的SYN

    // 3) ACK
    let ack = build_tcp_packet(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
        conn.client_seq, conn.server_seq,
        pnet::packet::tcp::TcpFlags::ACK,
    );
    packets.push(ack);
    conn.update_ack(true, 1); // 确认服务器的SYN

    (packets, conn)
}

// 封装HTTP GET请求和响应的完整流程
pub fn build_http_get_flow_packets(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    isn: u32,
    uri: &str,
    host: &str,
    response_body: &[u8],
) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    
    // 1. TCP三次握手
    let (handshake_packets, mut conn) = build_tcp_handshake_packets(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, isn
    );
    packets.extend(handshake_packets);

    // 2. HTTP GET请求
    let (client_seq, client_ack) = conn.get_seq_ack(true);
    let http_get = build_http_get_packet(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
        client_seq, client_ack, pnet::packet::tcp::TcpFlags::PSH,
        uri, host
    );
    let get_data_len = http_get.len() as u32 - 54; // 减去头部长度
    packets.push(http_get);
    conn.update_seq(true, get_data_len);

    // 3. HTTP GET响应
    let (server_seq, server_ack) = conn.get_seq_ack(false);
    let http_response = build_http_response_packet_simple(
        dst_mac, src_mac, dst_ip, src_ip, dst_port, src_port,
        server_seq, server_ack, 
        pnet::packet::tcp::TcpFlags::ACK | pnet::packet::tcp::TcpFlags::PSH,
        HttpStatusCode::Ok, "application/json", response_body
    );
    let response_data_len = http_response.len() as u32 - 54; // 减去头部长度
    packets.push(http_response);
    conn.update_seq(false, response_data_len);
    conn.update_ack(false, get_data_len);

    packets
}

// 封装HTTP POST请求和响应的完整流程
pub fn build_http_post_flow_packets(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    isn: u32,
    uri: &str,
    host: &str,
    content_type: &str,
    post_data: &[u8],
    response_body: &[u8],
) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    
    // 1. TCP三次握手
    let (handshake_packets, mut conn) = build_tcp_handshake_packets(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, isn
    );
    packets.extend(handshake_packets);

    // 2. HTTP POST请求
    let (client_seq, client_ack) = conn.get_seq_ack(true);
    let http_post = build_http_post_packet(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
        client_seq, client_ack, pnet::packet::tcp::TcpFlags::PSH,
        uri, host, content_type, post_data
    );
    let post_data_len = http_post.len() as u32 - 54; // 减去头部长度
    packets.push(http_post);
    conn.update_seq(true, post_data_len);

    // 3. HTTP POST响应
    let (server_seq, server_ack) = conn.get_seq_ack(false);
    let http_response = build_http_response_packet_simple(
        dst_mac, src_mac, dst_ip, src_ip, dst_port, src_port,
        server_seq, server_ack,
        pnet::packet::tcp::TcpFlags::ACK | pnet::packet::tcp::TcpFlags::PSH,
        HttpStatusCode::Ok, "application/json", response_body
    );
    let response_data_len = http_response.len() as u32 - 54; // 减去头部长度
    packets.push(http_response);
    conn.update_seq(false, response_data_len);
    conn.update_ack(false, post_data_len);

    packets
}

// 封装完整的HTTP GET和POST流程
pub fn build_http_get_post_flow_packets(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    isn: u32,
    get_uri: &str,
    post_uri: &str,
    host: &str,
    post_data: &[u8],
    get_response: &[u8],
    post_response: &[u8],
) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    
    // 1. TCP三次握手
    let (handshake_packets, mut conn) = build_tcp_handshake_packets(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, isn
    );
    packets.extend(handshake_packets);

    // 2. HTTP GET请求
    let (client_seq, client_ack) = conn.get_seq_ack(true);
    let http_get = build_http_get_packet(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
        client_seq, client_ack, pnet::packet::tcp::TcpFlags::PSH,
        get_uri, host
    );
    let get_data_len = http_get.len() as u32 - 54;
    packets.push(http_get);
    conn.update_seq(true, get_data_len);

    // 3. HTTP GET响应
    let (server_seq, server_ack) = conn.get_seq_ack(false);
    let http_get_response = build_http_response_packet_simple(
        dst_mac, src_mac, dst_ip, src_ip, dst_port, src_port,
        server_seq, server_ack,
        pnet::packet::tcp::TcpFlags::ACK | pnet::packet::tcp::TcpFlags::PSH,
        HttpStatusCode::Ok, "application/json", get_response
    );
    let get_response_data_len = http_get_response.len() as u32 - 54;
    packets.push(http_get_response);
    conn.update_seq(false, get_response_data_len);
    conn.update_ack(false, get_data_len);

    // 4. HTTP POST请求
    let (client_seq, client_ack) = conn.get_seq_ack(true);
    let http_post = build_http_post_packet(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
        client_seq, client_ack, pnet::packet::tcp::TcpFlags::PSH,
        post_uri, host, "application/json", post_data
    );
    let post_data_len = http_post.len() as u32 - 54;
    packets.push(http_post);
    conn.update_seq(true, post_data_len);

    // 5. HTTP POST响应
    let (server_seq, server_ack) = conn.get_seq_ack(false);
    let http_post_response = build_http_response_packet_simple(
        dst_mac, src_mac, dst_ip, src_ip, dst_port, src_port,
        server_seq, server_ack,
        pnet::packet::tcp::TcpFlags::ACK | pnet::packet::tcp::TcpFlags::PSH,
        HttpStatusCode::Ok, "application/json", post_response
    );
    let post_response_data_len = http_post_response.len() as u32 - 54;
    packets.push(http_post_response);
    conn.update_seq(false, post_response_data_len);
    conn.update_ack(false, post_data_len);

    packets
}   



