use hex;
use pcap_file::pcap::PcapWriter;
use std::borrow::Cow;
use std::fs::File;

pub struct PacketAnalyzer {
    hex_input: String,
    packet_length: usize,
}

impl PacketAnalyzer {
    pub fn new() -> Self {
        Self {
            hex_input: String::new(),
            packet_length: 0,
        }
    }

    pub fn set_hex_input(&mut self, hex_input: &str) {
        self.hex_input = hex_input.to_string();
    }

    pub fn get_packet_length(&self) -> usize {
        self.packet_length
    }

    pub fn analyze_hex(&mut self) -> String {
        // 移除所有空格和换行符
        let cleaned_hex = self.hex_input.replace(|c: char| c.is_whitespace(), "");

        // 检查是否为有效的十六进制字符串
        if !cleaned_hex.chars().all(|c| c.is_digit(16)) {
            return String::from("错误: 输入包含无效的十六进制字符");
        }

        // 检查长度是否为偶数
        if cleaned_hex.len() % 2 != 0 {
            return String::from("错误: 十六进制字符串长度必须为偶数");
        }

        // 尝试解码十六进制
        match hex::decode(&cleaned_hex) {
            Ok(bytes) => {
                self.packet_length = bytes.len();
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

                result
            },
            Err(_) => {
                self.packet_length = 0;
                String::from("错误: 无法解码十六进制数据")
            }
        }
    }

    pub fn export_pcap(&self, filename: &str) -> Result<String, Box<dyn std::error::Error>> {
        // 移除所有空格和换行符
        let cleaned_hex = self.hex_input.replace(|c: char| c.is_whitespace(), "");

        // 检查是否为有效的十六进制字符串
        if !cleaned_hex.chars().all(|c| c.is_digit(16)) {
            return Err("输入包含无效的十六进制字符，无法导出PCAP".into());
        }

        // 检查长度是否为偶数
        if cleaned_hex.len() % 2 != 0 {
            return Err("十六进制字符串长度必须为偶数，无法导出PCAP".into());
        }

        // 尝试解码十六进制
        match hex::decode(&cleaned_hex) {
            Ok(bytes) => {
                // 创建PCAP文件
                match File::create(filename) {
                    Ok(file) => {
                        let mut writer = PcapWriter::new(file).unwrap();

                        // 写入数据包
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap();

                        let seconds = now.as_secs() as u32;
                        let micros = now.subsec_micros();

                        use pcap_file::pcap::PcapPacket;
                        use std::time::Duration;

                        let packet = PcapPacket {
                            timestamp: Duration::from_secs(seconds as u64) + Duration::from_micros(micros as u64),
                            data: Cow::Borrowed(&bytes),
                            orig_len: bytes.len() as u32,
                        };

                        match writer.write_packet(&packet) {
                            Ok(_) => {
                                Ok(format!("PCAP文件已成功导出到: {}", filename))
                            },
                            Err(e) => {
                                Err(format!("写入PCAP文件时出错: {}", e).into())
                            }
                        }
                    },
                    Err(e) => {
                        Err(format!("创建PCAP文件时出错: {}", e).into())
                    }
                }
            },
            Err(_) => {
                Err("无法解码十六进制数据，无法导出PCAP".into())
            }
        }
    }

    pub fn export_pcap_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // 移除所有空格和换行符
        let cleaned_hex = self.hex_input.replace(|c: char| c.is_whitespace(), "");

        // 检查是否为有效的十六进制字符串
        if !cleaned_hex.chars().all(|c| c.is_digit(16)) {
            return Err("输入包含无效的十六进制字符，无法导出PCAP".into());
        }

        // 检查长度是否为偶数
        if cleaned_hex.len() % 2 != 0 {
            return Err("十六进制字符串长度必须为偶数，无法导出PCAP".into());
        }

        // 尝试解码十六进制
        match hex::decode(&cleaned_hex) {
            Ok(bytes) => {
                // 创建内存中的PCAP数据
                use std::io::Cursor;
                let mut buffer = Vec::new();
                {
                    let mut cursor = Cursor::new(&mut buffer);
                    let mut writer = PcapWriter::new(&mut cursor).unwrap();

                    // 写入数据包
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap();

                    let seconds = now.as_secs() as u32;
                    let micros = now.subsec_micros();

                    use pcap_file::pcap::PcapPacket;
                    use std::time::Duration;

                    let packet = PcapPacket {
                        timestamp: Duration::from_secs(seconds as u64) + Duration::from_micros(micros as u64),
                        data: Cow::Borrowed(&bytes),
                        orig_len: bytes.len() as u32,
                    };

                    writer.write_packet(&packet)?;
                }
                Ok(buffer)
            },
            Err(_) => {
                Err("无法解码十六进制数据，无法导出PCAP".into())
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