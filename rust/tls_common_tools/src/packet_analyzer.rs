use iced::{Element, Length};
use iced::widget::{button, column, container, row, text, text_input, Column, Row};
use rfd::FileDialog;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use hex;
use pcap_file::pcap::{PcapWriter, PcapHeader};
use std::fs::File;
use std::io::Write;

#[derive(Debug, Clone)]
pub enum Message {
    HexInputChanged(String),
    AnalyzeHex,
    SavePathChanged(String),
    ExportPcap,
}

pub struct PacketAnalyzer {
    hex_input: String,
    analysis_result: String,
    pcap_save_path: String,
}

impl PacketAnalyzer {
    pub fn new() -> Self {
        Self {
            hex_input: String::new(),
            analysis_result: String::new(),
            pcap_save_path: String::from("packet.pcap"),
        }
    }
    
    pub fn update(&mut self, message: Message) {
        match message {
            Message::HexInputChanged(value) => self.hex_input = value,
            Message::AnalyzeHex => self.analyze_hex(),
            Message::SavePathChanged(value) => self.pcap_save_path = value,
            Message::ExportPcap => self.export_pcap(),
        }
    }
    
    pub fn view(&self) -> Element<Message> {
        let title = text("报文分析工具").size(24);
        
        let hex_input = text_input("输入Hex数据...", &self.hex_input)
            .on_input(Message::HexInputChanged)
            .padding(10);
            
        let analyze_button = button("分析Hex数据")
            .on_press(Message::AnalyzeHex);
            
        let analysis_result = container(
            column![
                text("分析结果:").size(16),
                text(&self.analysis_result).size(14)
            ]
        ).padding(10);
        
        let pcap_path_input = text_input("保存路径...", &self.pcap_save_path)
            .on_input(Message::SavePathChanged)
            .padding(10);
            
        let export_button = button("导出为PCAP")
            .on_press(Message::ExportPcap);
            
        column![
            title,
            text("输入Hex数据:").size(16),
            hex_input,
            analyze_button,
            analysis_result,
            row![
                text("PCAP保存路径:").size(16),
                pcap_path_input
            ].spacing(10),
            export_button
        ].spacing(20).into()
    }
    
    fn analyze_hex(&mut self) {
        // 移除所有空格和换行符
        let cleaned_hex = self.hex_input.replace(|c: char| c.is_whitespace(), "");
        
        // 检查是否为有效的十六进制字符串
        if !cleaned_hex.chars().all(|c| c.is_digit(16)) {
            self.analysis_result = String::from("错误: 输入包含无效的十六进制字符");
            return;
        }
        
        // 检查长度是否为偶数
        if cleaned_hex.len() % 2 != 0 {
            self.analysis_result = String::from("错误: 十六进制字符串长度必须为偶数");
            return;
        }
        
        // 尝试解码十六进制
        match hex::decode(&cleaned_hex) {
            Ok(bytes) => {
                let mut result = String::new();
                
                // 添加基本信息
                result.push_str(&format!("数据包长度: {} 字节\n\n", bytes.len()));
                
                // 如果看起来像以太网帧，解析MAC地址
                if bytes.len() >= 14 {
                    let dst_mac = &bytes[0..6];
                    let src_mac = &bytes[6..12];
                    let ethertype = (bytes[12] as u16) << 8 | bytes[13] as u16;
                    
                    result.push_str(&format!("目标MAC: {}\n", format_mac(dst_mac)));
                    result.push_str(&format!("源MAC: {}\n", format_mac(src_mac)));
                    result.push_str(&format!("EtherType: 0x{:04X}\n\n", ethertype));
                    
                    // 如果是IPv4包 (EtherType 0x0800)
                    if ethertype == 0x0800 && bytes.len() >= 34 {
                        let ip_header_start = 14;
                        let ip_version = (bytes[ip_header_start] >> 4) & 0xF;
                        let header_len = (bytes[ip_header_start] & 0xF) * 4;
                        let total_len = (bytes[ip_header_start + 2] as u16) << 8 | bytes[ip_header_start + 3] as u16;
                        let protocol = bytes[ip_header_start + 9];
                        let src_ip = &bytes[ip_header_start + 12..ip_header_start + 16];
                        let dst_ip = &bytes[ip_header_start + 16..ip_header_start + 20];
                        
                        result.push_str(&format!("IP版本: {}\n", ip_version));
                        result.push_str(&format!("IP头部长度: {} 字节\n", header_len));
                        result.push_str(&format!("总长度: {} 字节\n", total_len));
                        result.push_str(&format!("协议: {}\n", protocol_to_string(protocol)));
                        result.push_str(&format!("源IP: {}\n", format_ipv4(src_ip)));
                        result.push_str(&format!("目标IP: {}\n", format_ipv4(dst_ip)));
                        
                        // 如果是TCP或UDP，解析端口
                        if (protocol == 6 || protocol == 17) && bytes.len() >= (ip_header_start + header_len as usize + 4) {
                            let transport_header_start = ip_header_start + header_len as usize;
                            let src_port = (bytes[transport_header_start] as u16) << 8 | bytes[transport_header_start + 1] as u16;
                            let dst_port = (bytes[transport_header_start + 2] as u16) << 8 | bytes[transport_header_start + 3] as u16;
                            
                            result.push_str(&format!("源端口: {}\n", src_port));
                            result.push_str(&format!("目标端口: {}\n", dst_port));
                        }
                    }
                }
                
                self.analysis_result = result;
            },
            Err(_) => {
                self.analysis_result = String::from("错误: 无法解码十六进制数据");
            }
        }
    }
    
    fn export_pcap(&mut self) {
        // 移除所有空格和换行符
        let cleaned_hex = self.hex_input.replace(|c: char| c.is_whitespace(), "");
        
        // 检查是否为有效的十六进制字符串
        if !cleaned_hex.chars().all(|c| c.is_digit(16)) {
            self.analysis_result = String::from("错误: 输入包含无效的十六进制字符，无法导出PCAP");
            return;
        }
        
        // 检查长度是否为偶数
        if cleaned_hex.len() % 2 != 0 {
            self.analysis_result = String::from("错误: 十六进制字符串长度必须为偶数，无法导出PCAP");
            return;
        }
        
        // 尝试解码十六进制
        match hex::decode(&cleaned_hex) {
            Ok(bytes) => {
                // 创建PCAP文件
                match File::create(&self.pcap_save_path) {
                    Ok(file) => {
                        let header = PcapHeader::default();
                        let mut writer = PcapWriter::with_header(header, file).unwrap();
                        
                        // 写入数据包
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap();
                        
                        let seconds = now.as_secs() as u32;
                        let micros = now.subsec_micros();
                        
                        match writer.write(seconds, micros, &bytes, bytes.len() as u32) {
                            Ok(_) => {
                                self.analysis_result = format!("PCAP文件已成功导出到: {}", self.pcap_save_path);
                            },
                            Err(e) => {
                                self.analysis_result = format!("写入PCAP文件时出错: {}", e);
                            }
                        }
                    },
                    Err(e) => {
                        self.analysis_result = format!("创建PCAP文件时出错: {}", e);
                    }
                }
            },
            Err(_) => {
                self.analysis_result = String::from("错误: 无法解码十六进制数据，无法导出PCAP");
            }
        }
    }
}

fn format_mac(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(":")
}

fn format_ipv4(ip: &[u8]) -> String {
    ip.iter()
        .map(|b| b.to_string())
        .collect::<Vec<String>>()
        .join(".")
}

fn protocol_to_string(protocol: u8) -> String {
    match protocol {
        1 => String::from("ICMP (1)"),
        6 => String::from("TCP (6)"),
        17 => String::from("UDP (17)"),
        _ => format!("未知 ({})", protocol),
    }
}