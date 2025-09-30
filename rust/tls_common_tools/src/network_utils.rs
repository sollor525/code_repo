use iced::{Element, Length};
use iced::widget::{button, column, container, row, text, text_input, Column, Row};
use byteorder::{BigEndian, LittleEndian, ByteOrder};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub enum Message {
    IpInputChanged(String),
    PortInputChanged(String),
    IntInputChanged(String),
    ConvertIpToNetwork,
    ConvertIpToHost,
    ConvertPortToNetwork,
    ConvertPortToHost,
    ConvertIntToNetwork,
    ConvertIntToHost,
}

pub struct NetworkUtils {
    ip_input: String,
    port_input: String,
    int_input: String,
    ip_result: String,
    port_result: String,
    int_result: String,
}

impl NetworkUtils {
    pub fn new() -> Self {
        Self {
            ip_input: String::new(),
            port_input: String::new(),
            int_input: String::new(),
            ip_result: String::new(),
            port_result: String::new(),
            int_result: String::new(),
        }
    }
    
    pub fn update(&mut self, message: Message) {
        match message {
            Message::IpInputChanged(value) => self.ip_input = value,
            Message::PortInputChanged(value) => self.port_input = value,
            Message::IntInputChanged(value) => self.int_input = value,
            Message::ConvertIpToNetwork => self.ip_result = self.ip_to_network_order(&self.ip_input),
            Message::ConvertIpToHost => self.ip_result = self.ip_to_host_order(&self.ip_input),
            Message::ConvertPortToNetwork => self.port_result = self.port_to_network_order(&self.port_input),
            Message::ConvertPortToHost => self.port_result = self.port_to_host_order(&self.port_input),
            Message::ConvertIntToNetwork => self.int_result = self.int_to_network_order(&self.int_input),
            Message::ConvertIntToHost => self.int_result = self.int_to_host_order(&self.int_input),
        }
    }
    
    pub fn view(&self) -> Element<Message> {
        let title = text("网络序转换工具").size(24);
        
        // IP地址转换
        let ip_input = text_input("输入IP地址...", &self.ip_input)
            .on_input(Message::IpInputChanged)
            .padding(10);
            
        let ip_buttons = row![
            button("转换为网络序").on_press(Message::ConvertIpToNetwork),
            button("转换为主机序").on_press(Message::ConvertIpToHost)
        ].spacing(10);
        
        let ip_result = row![
            text("结果:").size(16),
            text(&self.ip_result).size(16)
        ].spacing(10);
        
        let ip_section = container(
            column![
                text("IP地址转换").size(20),
                row![text("IP地址:").size(16), ip_input].spacing(10),
                ip_buttons,
                ip_result
            ].spacing(10)
        ).padding(10);
        
        // 端口转换
        let port_input = text_input("输入端口...", &self.port_input)
            .on_input(Message::PortInputChanged)
            .padding(10);
            
        let port_buttons = row![
            button("转换为网络序").on_press(Message::ConvertPortToNetwork),
            button("转换为主机序").on_press(Message::ConvertPortToHost)
        ].spacing(10);
        
        let port_result = row![
            text("结果:").size(16),
            text(&self.port_result).size(16)
        ].spacing(10);
        
        let port_section = container(
            column![
                text("端口转换").size(20),
                row![text("端口:").size(16), port_input].spacing(10),
                port_buttons,
                port_result
            ].spacing(10)
        ).padding(10);
        
        // 整数转换
        let int_input = text_input("输入整数...", &self.int_input)
            .on_input(Message::IntInputChanged)
            .padding(10);
            
        let int_buttons = row![
            button("转换为网络序").on_press(Message::ConvertIntToNetwork),
            button("转换为主机序").on_press(Message::ConvertIntToHost)
        ].spacing(10);
        
        let int_result = row![
            text("结果:").size(16),
            text(&self.int_result).size(16)
        ].spacing(10);
        
        let int_section = container(
            column![
                text("整数转换").size(20),
                row![text("整数:").size(16), int_input].spacing(10),
                int_buttons,
                int_result
            ].spacing(10)
        ).padding(10);
        
        column![
            title,
            ip_section,
            port_section,
            int_section
        ].spacing(20).into()
    }
    
    // IP地址转换函数
    fn ip_to_network_order(&self, ip_str: &str) -> String {
        if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
            let octets = ipv4.octets();
            return format!("0x{:02X}{:02X}{:02X}{:02X}", octets[0], octets[1], octets[2], octets[3]);
        } else if let Ok(ipv6) = ip_str.parse::<Ipv6Addr>() {
            let segments = ipv6.segments();
            return format!("0x{:04X}{:04X}{:04X}{:04X}{:04X}{:04X}{:04X}{:04X}", 
                segments[0], segments[1], segments[2], segments[3], 
                segments[4], segments[5], segments[6], segments[7]);
        }
        "无效的IP地址格式".to_string()
    }
    
    fn ip_to_host_order(&self, ip_str: &str) -> String {
        // 处理十六进制格式
        if ip_str.starts_with("0x") || ip_str.starts_with("0X") {
            let hex_str = ip_str.trim_start_matches("0x").trim_start_matches("0X");
            
            // IPv4 (8个十六进制字符)
            if hex_str.len() == 8 {
                if let Ok(bytes) = hex::decode(hex_str) {
                    if bytes.len() == 4 {
                        return Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string();
                    }
                }
            } 
            // IPv6 (32个十六进制字符)
            else if hex_str.len() == 32 {
                if let Ok(bytes) = hex::decode(hex_str) {
                    if bytes.len() == 16 {
                        let mut segments = [0u16; 8];
                        for i in 0..8 {
                            segments[i] = ((bytes[i*2] as u16) << 8) | (bytes[i*2+1] as u16);
                        }
                        return Ipv6Addr::new(
                            segments[0], segments[1], segments[2], segments[3],
                            segments[4], segments[5], segments[6], segments[7]
                        ).to_string();
                    }
                }
            }
            return "无效的十六进制IP格式".to_string();
        }
        "无效的IP地址格式".to_string()
    }
    
    // 端口转换函数
    fn port_host_to_network(&self, port_str: &str) -> String {
        if let Ok(port) = port_str.parse::<u16>() {
            let network_order = port.to_be();
            return format!("0x{:04X} ({})", network_order, network_order);
        }
        "无效的端口格式".to_string()
    }
    
    fn port_network_to_host(&self, port_str: &str) -> String {
        // 处理十进制格式
        if let Ok(port) = port_str.parse::<u16>() {
            let host_order = u16::from_be(port);
            return format!("{} (0x{:04X})", host_order, host_order);
        }
        // 处理十六进制格式
        else if port_str.starts_with("0x") || port_str.starts_with("0X") {
            if let Ok(port) = u16::from_str_radix(port_str.trim_start_matches("0x").trim_start_matches("0X"), 16) {
                let host_order = u16::from_be(port);
                return format!("{} (0x{:04X})", host_order, host_order);
            }
        }
        "无效的端口格式".to_string()
    }
    
    // 整数转换函数
    fn int32_host_to_network(&self, int_str: &str) -> String {
        if let Ok(value) = int_str.parse::<u32>() {
            let network_order = value.to_be();
            return format!("0x{:08X} ({})", network_order, network_order);
        } else if int_str.starts_with("0x") || int_str.starts_with("0X") {
            if let Ok(value) = u32::from_str_radix(int_str.trim_start_matches("0x").trim_start_matches("0X"), 16) {
                let network_order = value.to_be();
                return format!("0x{:08X} ({})", network_order, network_order);
            }
        }
        "无效的整数格式".to_string()
    }
    
    fn int32_network_to_host(&self, int_str: &str) -> String {
        if let Ok(value) = int_str.parse::<u32>() {
            let host_order = u32::from_be(value);
            return format!("{} (0x{:08X})", host_order, host_order);
        } else if int_str.starts_with("0x") || int_str.starts_with("0X") {
            if let Ok(value) = u32::from_str_radix(int_str.trim_start_matches("0x").trim_start_matches("0X"), 16) {
                let host_order = u32::from_be(value);
                return format!("{} (0x{:08X})", host_order, host_order);
            }
        }
        "无效的整数格式".to_string()
    }
    
    fn int64_host_to_network(&self, int_str: &str) -> String {
        if let Ok(value) = int_str.parse::<u64>() {
            let network_order = value.to_be();
            return format!("0x{:016X} ({})", network_order, network_order);
        } else if int_str.starts_with("0x") || int_str.starts_with("0X") {
            if let Ok(value) = u64::from_str_radix(int_str.trim_start_matches("0x").trim_start_matches("0X"), 16) {
                let network_order = value.to_be();
                return format!("0x{:016X} ({})", network_order, network_order);
            }
        }
        "无效的整数格式".to_string()
    }
    
    fn int64_network_to_host(&self, int_str: &str) -> String {
        if let Ok(value) = int_str.parse::<u64>() {
            let host_order = u64::from_be(value);
            return format!("{} (0x{:016X})", host_order, host_order);
        } else if int_str.starts_with("0x") || int_str.starts_with("0X") {
            if let Ok(value) = u64::from_str_radix(int_str.trim_start_matches("0x").trim_start_matches("0X"), 16) {
                let host_order = u64::from_be(value);
                return format!("{} (0x{:016X})", host_order, host_order);
            }
        }
        "无效的整数格式".to_string()
    }
}