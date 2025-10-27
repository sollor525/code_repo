//! 简化的模板引擎实现
//!
//! 专注于基本功能，确保能够编译和运行

use std::net::Ipv4Addr;
use crate::{TcpSession, HttpStatusCode, SessionTemplate};
use crate::tcp::{build_tcp_handshake_packets, TcpConnection};
use crate::core::{NetworkConnection};
use crate::vlan::{VlanConfig, build_vlan_ethernet_header};
use super::{ TemplateConfig, TemplateError};

/// 简化的模板引擎
pub struct SimpleTemplateEngine {
    config: TemplateConfig,
}

impl SimpleTemplateEngine {
    pub fn new(config: TemplateConfig) -> Self {
        Self { config }
    }

    /// 为数据包添加VLAN标签
    fn apply_vlan_to_packet(&self, packet: Vec<u8>, session: &TcpSession) -> Vec<u8> {
        let vlan_config = self.parse_vlan_config();
        if vlan_config.is_qinq || vlan_config.outer_tag.is_some() {
            // 构建新的VLAN以太网头
            let vlan_header = build_vlan_ethernet_header(
                session.connection.src_mac,
                session.connection.dst_mac,
                &vlan_config,
            );

            // 替换原以太网头
            let mut new_packet = packet.clone();
            if packet.len() >= 14 {
                new_packet.splice(0..14, vlan_header);
            }
            new_packet
        } else {
            packet
        }
    }

    /// 从模板解析VLAN配置
    fn parse_vlan_config(&self) -> VlanConfig {
        if let Some(vlan_cfg) = &self.config.template.network.vlan {
            let mut vlan_config = VlanConfig::new();

            // 设置是否为QinQ
            vlan_config.is_qinq = vlan_cfg.qinq.unwrap_or(false);

            // 解析VLAN标签
            for tag in &vlan_cfg.tags {
                let vlan_tag = crate::vlan::VlanTag {
                    vlan_id: tag.vlan_id,
                    priority: tag.priority.unwrap_or(0),
                    dei: tag.dei.unwrap_or(false),
                };

                if let Some(tag_type) = &tag.tag_type {
                    match tag_type.as_str() {
                        "outer" => vlan_config.outer_tag = Some(vlan_tag),
                        "inner" => vlan_config.inner_tag = Some(vlan_tag),
                        _ => {
                            // 如果没有指定类型，默认为外层标签
                            if vlan_config.outer_tag.is_none() {
                                vlan_config.outer_tag = Some(vlan_tag);
                            } else if vlan_config.inner_tag.is_none() {
                                vlan_config.inner_tag = Some(vlan_tag);
                            }
                        }
                    }
                } else {
                    // 如果没有指定类型，默认为外层标签
                    if vlan_config.outer_tag.is_none() {
                        vlan_config.outer_tag = Some(vlan_tag);
                    } else if vlan_config.inner_tag.is_none() {
                        vlan_config.inner_tag = Some(vlan_tag);
                    }
                }
            }

            vlan_config
        } else {
            VlanConfig::new() // 无VLAN配置
        }
    }

    /// 生成所有会话的数据包
    pub fn generate_packets(&self) -> Result<Vec<Vec<u8>>, TemplateError> {
        let mut all_packets = Vec::new();

        for session_template in &self.config.template.sessions {
            let repeat_count = session_template.repeat.unwrap_or(1);

            for i in 0..repeat_count {
                // 简化的会话创建
                let src_ip = Ipv4Addr::new(10, 10, 1, 100 + i as u8);
                let dst_ip = Ipv4Addr::new(192, 168, 1, 100);
                let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
                let dst_mac = [0xe2, 0xc9, 0xfc, 0xf5, 0x9e, 0x3c];
                let src_port = 30000 + i as u16;
                let dst_port = 80;

                let connection = NetworkConnection::new(
                    src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port
                );
                let session = TcpSession::new(connection, 1000 + i as u32);

                let packets = self.generate_simple_session_packets(session, session_template)?;
                all_packets.extend(packets);
            }
        }

        Ok(all_packets)
    }

    /// 生成简化的会话数据包
    fn generate_simple_session_packets(&self, session: TcpSession, template: &SessionTemplate) -> Result<Vec<Vec<u8>>, TemplateError> {
        let mut packets = Vec::new();

        // 生成TCP三次握手
        let (handshake_packets, _) = build_tcp_handshake_packets(
            session.connection.src_mac,
            session.connection.dst_mac,
            session.connection.src_ip,
            session.connection.dst_ip,
            session.connection.src_port,
            session.connection.dst_port,
            session.isn
        );

        // 为握手包添加VLAN标签
        for packet in handshake_packets {
            let vlan_packet = self.apply_vlan_to_packet(packet, &session);
            packets.push(vlan_packet);
        }

        // 如果有HTTP配置，生成HTTP请求和响应
        if let Some(app_config) = &template.application {
            match app_config {
                super::ApplicationConfig::Http { requests, responses: _, timing: _ } => {
                    // 使用TcpConnection来正确跟踪序列号
                    let mut conn = TcpConnection::new(session.isn);

                    // 握手完成后，更新序列号
                    conn.update_seq(true, 1);   // 客户端SYN
                    conn.update_ack(true, 1);   // 客户端ACK服务器SYN
                    conn.update_seq(false, 1);  // 服务器SYN
                    conn.update_ack(false, 1);  // 服务器ACK客户端SYN

                    // 生成HTTP请求和响应对
                    for (i, request) in requests.iter().enumerate() {
                        let uri = request.uri.as_deref().unwrap_or("/");
                        let host = request.headers
                            .as_ref()
                            .and_then(|h| h.get("Host"))
                            .map(|s| s.as_str())
                            .unwrap_or("example.com");

                        // 生成HTTP请求
                        let (client_seq, client_ack) = conn.get_seq_ack(true);
                        let request_packet = crate::http::flow::build_http_get_packet(
                            session.connection.src_mac,
                            session.connection.dst_mac,
                            session.connection.src_ip,
                            session.connection.dst_ip,
                            session.connection.src_port,
                            session.connection.dst_port,
                            client_seq,
                            client_ack,
                            pnet::packet::tcp::TcpFlags::ACK | pnet::packet::tcp::TcpFlags::PSH,
                            uri,
                            host,
                        );

                        // 计算HTTP请求的数据长度（总包长度 - IP头20字节 - TCP头20字节 = 54字节）
                        let request_data_len = request_packet.len() as u32 - 54;

                        // 为HTTP请求添加VLAN标签
                        let vlan_request_packet = self.apply_vlan_to_packet(request_packet, &session);
                        packets.push(vlan_request_packet);

                        // 更新客户端序列号（发送了数据）
                        conn.update_seq(true, request_data_len);

                        // 生成HTTP响应
                        let status_code = 200; // 简化：固定返回200状态码
                        let status = HttpStatusCode::Custom(status_code);
                        let response_body = format!(r#"{{"request": "{}", "index": {}}}"#, uri, i);

                        let (server_seq, server_ack) = conn.get_seq_ack(false);
                        let response_packet = crate::http::flow::build_http_response_packet_simple(
                            session.connection.dst_mac,
                            session.connection.src_mac,
                            session.connection.dst_ip,
                            session.connection.src_ip,
                            session.connection.dst_port,
                            session.connection.src_port,
                            server_seq,
                            server_ack,
                            pnet::packet::tcp::TcpFlags::ACK | pnet::packet::tcp::TcpFlags::PSH,
                            status,
                            "application/json",
                            response_body.as_bytes(),
                        );

                        // 计算HTTP响应的数据长度
                        let response_data_len = response_packet.len() as u32 - 54;

                        // 为HTTP响应添加VLAN标签
                        let vlan_response_packet = self.apply_vlan_to_packet(response_packet, &session);
                        packets.push(vlan_response_packet);

                        // 更新服务器序列号（发送了数据）
                        conn.update_seq(false, response_data_len);
                        // 更新客户端确认号（接收了数据）
                        conn.update_ack(true, response_data_len);
                    }
                }
                _ => {
                    // 其他类型暂时不处理
                }
            }
        }

        Ok(packets)
    }
}