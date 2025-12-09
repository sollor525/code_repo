//! 输出格式化器
//!
//! 提供多种格式的流信息输出功能，包括文本表格和JSON格式

use std::collections::HashMap;
use std::io::{self, Write};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::types::stream::{TcpStream, TcpState};
use crate::types::flow::FlowKey;
use chrono::DateTime;
use prettytable::{Table, Row, Cell, format};

/// 输出格式类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// 文本表格格式
    Table,
    /// JSON格式
    Json,
    /// CSV格式
    Csv,
    /// 简洁文本格式
    Simple,
}

/// 流信息排序字段
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortField {
    /// 流ID
    FlowId,
    /// 源IP地址
    SrcIp,
    /// 源端口
    SrcPort,
    /// 目的IP地址
    DstIp,
    /// 目的端口
    DstPort,
    /// 协议
    Protocol,
    /// 数据包数量
    PacketCount,
    /// 字节数
    ByteCount,
    /// 持续时间
    Duration,
    /// 首包时间
    FirstPacketTime,
    /// 末包时间
    LastPacketTime,
    /// 连接状态
    State,
}

/// 排序顺序
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    /// 升序
    Ascending,
    /// 降序
    Descending,
}

/// 流过滤器
#[derive(Debug, Clone, Default)]
pub struct FlowFilter {
    /// 协议类型过滤
    pub protocol: Option<u8>,
    /// 源IP过滤
    pub src_ip: Option<String>,
    /// 目的IP过滤
    pub dst_ip: Option<String>,
    /// 源端口过滤
    pub src_port: Option<u16>,
    /// 目的端口过滤
    pub dst_port: Option<u16>,
    /// 最小数据包数量
    pub min_packets: Option<u64>,
    /// 最大数据包数量
    pub max_packets: Option<u64>,
    /// 最小字节数
    pub min_bytes: Option<u64>,
    /// 最大字节数
    pub max_bytes: Option<u64>,
    /// 状态过滤
    pub state: Option<TcpState>,
    /// 是否只显示完整流
    pub complete_only: bool,
    /// 是否只显示活动流
    pub active_only: bool,
}

impl FlowFilter {
    /// 创建新的过滤器
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置协议过滤
    pub fn protocol(mut self, protocol: u8) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// 设置源IP过滤
    pub fn src_ip(mut self, ip: impl Into<String>) -> Self {
        self.src_ip = Some(ip.into());
        self
    }

    /// 设置目的IP过滤
    pub fn dst_ip(mut self, ip: impl Into<String>) -> Self {
        self.dst_ip = Some(ip.into());
        self
    }

    /// 设置源端口过滤
    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = Some(port);
        self
    }

    /// 设置目的端口过滤
    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }

    /// 设置数据包数量范围
    pub fn packet_range(mut self, min: u64, max: u64) -> Self {
        self.min_packets = Some(min);
        self.max_packets = Some(max);
        self
    }

    /// 设置字节数范围
    pub fn byte_range(mut self, min: u64, max: u64) -> Self {
        self.min_bytes = Some(min);
        self.max_bytes = Some(max);
        self
    }

    /// 设置状态过滤
    pub fn state(mut self, state: TcpState) -> Self {
        self.state = Some(state);
        self
    }

    /// 只显示完整流
    pub fn complete_only(mut self, complete: bool) -> Self {
        self.complete_only = complete;
        self
    }

    /// 只显示活动流
    pub fn active_only(mut self, active: bool) -> Self {
        self.active_only = active;
        self
    }

    /// 检查流是否匹配过滤器
    pub fn matches(&self, stream: &TcpStream) -> bool {
        // 协议过滤
        if let Some(protocol) = self.protocol {
            if stream.flow_key.protocol() != protocol {
                return false;
            }
        }

        // 源IP过滤
        if let Some(src_ip) = &self.src_ip {
            if stream.client_ip().to_string() != *src_ip {
                return false;
            }
        }

        // 目的IP过滤
        if let Some(dst_ip) = &self.dst_ip {
            if stream.server_ip().to_string() != *dst_ip {
                return false;
            }
        }

        // 源端口过滤
        if let Some(src_port) = self.src_port {
            if stream.client_port() != src_port {
                return false;
            }
        }

        // 目的端口过滤
        if let Some(dst_port) = self.dst_port {
            if stream.server_port() != dst_port {
                return false;
            }
        }

        // 数据包数量过滤
        if let Some(min) = self.min_packets {
            if stream.stats.packet_count < min {
                return false;
            }
        }
        if let Some(max) = self.max_packets {
            if stream.stats.packet_count > max {
                return false;
            }
        }

        // 字节数过滤
        if let Some(min) = self.min_bytes {
            if stream.stats.byte_count < min {
                return false;
            }
        }
        if let Some(max) = self.max_bytes {
            if stream.stats.byte_count > max {
                return false;
            }
        }

        // 状态过滤
        if let Some(state) = self.state {
            if stream.state != state {
                return false;
            }
        }

        // 完整流过滤
        if self.complete_only && !stream.connection.handshake.is_complete() {
            return false;
        }

        // 活动流过滤
        if self.active_only && !stream.connection.is_active() {
            return false;
        }

        true
    }
}

/// 流格式化器
///
/// 负责将流信息格式化为不同格式的输出
#[derive(Debug, Clone)]
pub struct FlowFormatter {
    /// 输出格式
    format: OutputFormat,
    /// 排序字段
    sort_field: SortField,
    /// 排序顺序
    sort_order: SortOrder,
    /// 过滤器
    filter: Option<FlowFilter>,
    /// 是否显示详细信息
    verbose: bool,
    /// 是否显示颜色
    color: bool,
    /// 每页显示的行数（0表示不分页）
    page_size: usize,
}

impl FlowFormatter {
    /// 创建新的格式化器
    pub fn new(format: OutputFormat) -> Self {
        Self {
            format,
            sort_field: SortField::FlowId,
            sort_order: SortOrder::Ascending,
            filter: None,
            verbose: false,
            color: false,
            page_size: 0,
        }
    }

    /// 设置排序字段
    pub fn sort_by(mut self, field: SortField) -> Self {
        self.sort_field = field;
        self
    }

    /// 设置排序顺序
    pub fn sort_order(mut self, order: SortOrder) -> Self {
        self.sort_order = order;
        self
    }

    /// 设置过滤器
    pub fn filter(mut self, filter: FlowFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// 设置详细模式
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// 设置颜色显示
    pub fn color(mut self, color: bool) -> Self {
        self.color = color;
        self
    }

    /// 设置分页大小
    pub fn page_size(mut self, size: usize) -> Self {
        self.page_size = size;
        self
    }

    /// 格式化单个流
    pub fn format_stream(&self, stream: &TcpStream) -> Result<String, io::Error> {
        match self.format {
            OutputFormat::Table => self.format_table(&[stream]),
            OutputFormat::Json => self.format_json(&[stream]),
            OutputFormat::Csv => self.format_csv(&[stream]),
            OutputFormat::Simple => self.format_simple(&[stream]),
        }
    }

    /// 格式化多个流
    pub fn format_streams(&self, streams: &[&TcpStream]) -> Result<String, io::Error> {
        // 应用过滤器
        let mut filtered_streams: Vec<&TcpStream> = streams
            .iter()
            .copied()
            .filter(|&s| {
                if let Some(filter) = &self.filter {
                    filter.matches(s)
                } else {
                    true
                }
            })
            .collect();

        // 排序
        self.sort_streams(&mut filtered_streams);

        // 格式化输出
        match self.format {
            OutputFormat::Table => self.format_table(&filtered_streams),
            OutputFormat::Json => self.format_json(&filtered_streams),
            OutputFormat::Csv => self.format_csv(&filtered_streams),
            OutputFormat::Simple => self.format_simple(&filtered_streams),
        }
    }

    /// 排序流
    fn sort_streams(&self, streams: &mut Vec<&TcpStream>) {
        streams.sort_by(|a, b| {
            let cmp = match self.sort_field {
                SortField::FlowId => a.flow_key.to_string().cmp(&b.flow_key.to_string()),
                SortField::SrcIp => a.client_ip().cmp(b.client_ip()),
                SortField::SrcPort => a.client_port().cmp(&b.client_port()),
                SortField::DstIp => a.server_ip().cmp(b.server_ip()),
                SortField::DstPort => a.server_port().cmp(&b.server_port()),
                SortField::Protocol => a.flow_key.protocol().cmp(&b.flow_key.protocol()),
                SortField::PacketCount => a.stats.packet_count.cmp(&b.stats.packet_count),
                SortField::ByteCount => a.stats.byte_count.cmp(&b.stats.byte_count),
                SortField::Duration => a.stats.duration().cmp(&b.stats.duration()),
                SortField::FirstPacketTime => a.stats.first_packet_time.cmp(&b.stats.first_packet_time),
                SortField::LastPacketTime => a.stats.last_packet_time.cmp(&b.stats.last_packet_time),
                SortField::State => a.state.as_str().cmp(&b.state.as_str()),
            };

            match self.sort_order {
                SortOrder::Ascending => cmp,
                SortOrder::Descending => cmp.reverse(),
            }
        });
    }

    /// 格式化为表格
    fn format_table(&self, streams: &[&TcpStream]) -> Result<String, io::Error> {
        let mut table = Table::new();

        // 设置表格格式
        table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

        // 添加标题行
        if self.verbose {
            table.add_row(Row::new(vec![
                Cell::new("Flow ID"),
                Cell::new("Client IP"),
                Cell::new("C Port"),
                Cell::new("Server IP"),
                Cell::new("S Port"),
                Cell::new("Proto"),
                Cell::new("State"),
                Cell::new("Packets"),
                Cell::new("Bytes"),
                Cell::new("Duration"),
                Cell::new("Handshake"),
                Cell::new("Close"),
                Cell::new("Quality"),
                Cell::new("First Time"),
                Cell::new("Last Time"),
            ]));
        } else {
            table.add_row(Row::new(vec![
                Cell::new("Flow"),
                Cell::new("Client"),
                Cell::new("Server"),
                Cell::new("Proto"),
                Cell::new("State"),
                Cell::new("Packets"),
                Cell::new("Bytes"),
                Cell::new("Duration"),
            ]));
        }

        // 添加数据行
        for stream in streams {
            if self.verbose {
                table.add_row(Row::new(vec![
                    Cell::new(&format!("{}", stream.flow_key)),
                    Cell::new(&format!("{}", stream.client_ip())),
                    Cell::new(&format!("{}", stream.client_port())),
                    Cell::new(&format!("{}", stream.server_ip())),
                    Cell::new(&format!("{}", stream.server_port())),
                    Cell::new(stream.flow_key.protocol_name()),
                    Cell::new(stream.state.as_str()),
                    Cell::new(&format!("{}", stream.stats.packet_count)),
                    Cell::new(&format_bytes(stream.stats.byte_count)),
                    Cell::new(&format_duration(stream.stats.duration())),
                    Cell::new(&format!("{}", if stream.connection.handshake.is_complete() { "✓" } else { "✗" })),
                    Cell::new(&format!("{}", if stream.connection.close.is_complete() { "✓" } else { "✗" })),
                    Cell::new(&format!("{:.1}%", stream.connection.quality_score())),
                    Cell::new(&format_timestamp(stream.stats.first_packet_time)),
                    Cell::new(&format_timestamp(stream.stats.last_packet_time)),
                ]));
            } else {
                table.add_row(Row::new(vec![
                    Cell::new(&format!("{}", stream.flow_key)),
                    Cell::new(&format!("{}:{}", stream.client_ip(), stream.client_port())),
                    Cell::new(&format!("{}:{}", stream.server_ip(), stream.server_port())),
                    Cell::new(stream.flow_key.protocol_name()),
                    Cell::new(stream.state.as_str()),
                    Cell::new(&format!("{}", stream.stats.packet_count)),
                    Cell::new(&format_bytes(stream.stats.byte_count)),
                    Cell::new(&format_duration(stream.stats.duration())),
                ]));
            }
        }

        // 输出到字符串
        let mut output = Vec::new();
        table.print(&mut output)?;
        Ok(String::from_utf8(output).unwrap_or_default())
    }

    /// 格式化为JSON
    fn format_json(&self, streams: &[&TcpStream]) -> Result<String, io::Error> {
        let json_streams: Vec<JsonStream> = streams.iter().map(|&s| JsonStream::from(s)).collect();

        let output = if self.verbose {
            serde_json::to_string_pretty(&json_streams)?
        } else {
            serde_json::to_string(&json_streams)?
        };

        Ok(output)
    }

    /// 格式化为CSV
    fn format_csv(&self, streams: &[&TcpStream]) -> Result<String, io::Error> {
        let mut output = Vec::new();

        // CSV标题行
        if self.verbose {
            writeln!(output, "flow_id,client_ip,client_port,server_ip,server_port,protocol,state,packet_count,byte_count,duration,handshake_complete,close_complete,quality_score,first_packet_time,last_packet_time")?;
        } else {
            writeln!(output, "flow,client,server,protocol,state,packets,bytes,duration")?;
        }

        // 数据行
        for stream in streams {
            if self.verbose {
                writeln!(
                    output,
                    "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                    stream.flow_key,
                    stream.client_ip(),
                    stream.client_port(),
                    stream.server_ip(),
                    stream.server_port(),
                    stream.flow_key.protocol_name(),
                    stream.state.as_str(),
                    stream.stats.packet_count,
                    stream.stats.byte_count,
                    format_duration(stream.stats.duration()).replace(' ', ""),
                    stream.connection.handshake.is_complete(),
                    stream.connection.close.is_complete(),
                    stream.connection.quality_score(),
                    stream.stats.first_packet_time.map(|ts| format_timestamp(Some(ts))).unwrap_or("-".to_string()),
                    stream.stats.last_packet_time.map(|ts| format_timestamp(Some(ts))).unwrap_or("-".to_string())
                )?;
            } else {
                writeln!(
                    output,
                    "{},{},{},{},{},{},{},{}",
                    stream.flow_key,
                    format!("{}:{}", stream.client_ip(), stream.client_port()),
                    format!("{}:{}", stream.server_ip(), stream.server_port()),
                    stream.flow_key.protocol_name(),
                    stream.state.as_str(),
                    stream.stats.packet_count,
                    format_bytes(stream.stats.byte_count),
                    format_duration(stream.stats.duration()).replace(' ', "")
                )?;
            }
        }

        Ok(String::from_utf8(output).unwrap_or_default())
    }

    /// 格式化为简单文本
    fn format_simple(&self, streams: &[&TcpStream]) -> Result<String, io::Error> {
        let mut output = String::new();

        for stream in streams {
            output.push_str(&stream.summary());
            output.push('\n');

            if self.verbose {
                output.push_str(&format!("  Handshake: {}\n",
                    if stream.connection.handshake.is_complete() { "Complete" } else { "Incomplete" }));
                output.push_str(&format!("  Close: {}\n",
                    if stream.connection.close.is_complete() { "Graceful" } else { "Incomplete" }));
                output.push_str(&format!("  Quality: {:.1}%\n", stream.connection.quality_score()));
                output.push_str(&format!("  Client → Server: {} packets, {} bytes\n",
                    stream.stats.c2s_packet_count, stream.stats.c2s_byte_count));
                output.push_str(&format!("  Server → Client: {} packets, {} bytes\n",
                    stream.stats.s2c_packet_count, stream.stats.s2c_byte_count));
                output.push_str(&format!("  Throughput: ↑ {:.2} KB/s, ↓ {:.2} KB/s\n",
                    stream.client_throughput() / 1024.0,
                    stream.server_throughput() / 1024.0
                ));
                output.push('\n');
            }
        }

        Ok(output)
    }
}

impl Default for FlowFormatter {
    fn default() -> Self {
        Self::new(OutputFormat::Table)
    }
}

/// JSON格式的流信息
#[derive(Debug, Serialize, Deserialize)]
struct JsonStream {
    /// 流ID
    flow_id: String,
    /// 五元组信息
    five_tuple: JsonFiveTuple,
    /// 流状态
    state: String,
    /// 统计信息
    stats: JsonStats,
    /// 连接信息
    connection: JsonConnection,
    /// 元数据
    metadata: HashMap<String, String>,
}

impl From<&TcpStream> for JsonStream {
    fn from(stream: &TcpStream) -> Self {
        let mut metadata = HashMap::new();
        for (k, v) in &stream.metadata {
            metadata.insert(k.clone(), v.clone());
        }

        Self {
            flow_id: stream.flow_key.to_string(),
            five_tuple: JsonFiveTuple::from(&stream.flow_key),
            state: stream.state.as_str().to_string(),
            stats: JsonStats::from(&stream.stats),
            connection: JsonConnection::from(&stream.connection),
            metadata,
        }
    }
}

/// JSON格式的五元组
#[derive(Debug, Serialize, Deserialize)]
struct JsonFiveTuple {
    client_ip: String,
    client_port: u16,
    server_ip: String,
    server_port: u16,
    protocol: String,
    protocol_number: u8,
}

impl From<&FlowKey> for JsonFiveTuple {
    fn from(flow_key: &FlowKey) -> Self {
        Self {
            client_ip: flow_key.src_ip().to_string(),
            client_port: flow_key.src_port(),
            server_ip: flow_key.dst_ip().to_string(),
            server_port: flow_key.dst_port(),
            protocol: flow_key.protocol_name().to_string(),
            protocol_number: flow_key.protocol(),
        }
    }
}

/// JSON格式的统计信息
#[derive(Debug, Serialize, Deserialize)]
struct JsonStats {
    packet_count: u64,
    byte_count: u64,
    client_to_server: JsonDirectionStats,
    server_to_client: JsonDirectionStats,
    duration_micros: Option<u64>,
    duration_seconds: Option<f64>,
    first_packet_time: Option<String>,
    last_packet_time: Option<String>,
    avg_packet_size: f64,
    max_packet_size: u32,
    min_packet_size: u32,
}

impl From<&crate::types::flow::FlowStats> for JsonStats {
    fn from(stats: &crate::types::flow::FlowStats) -> Self {
        Self {
            packet_count: stats.packet_count,
            byte_count: stats.byte_count,
            client_to_server: JsonDirectionStats {
                packet_count: stats.c2s_packet_count,
                byte_count: stats.c2s_byte_count,
            },
            server_to_client: JsonDirectionStats {
                packet_count: stats.s2c_packet_count,
                byte_count: stats.s2c_byte_count,
            },
            duration_micros: stats.duration(),
            duration_seconds: stats.duration_seconds(),
            first_packet_time: stats.first_packet_time.map(|ts| format_timestamp(Some(ts))),
            last_packet_time: stats.last_packet_time.map(|ts| format_timestamp(Some(ts))),
            avg_packet_size: stats.avg_packet_size,
            max_packet_size: stats.max_packet_size,
            min_packet_size: if stats.min_packet_size == u32::MAX { 0 } else { stats.min_packet_size },
        }
    }
}

/// JSON格式的方向统计
#[derive(Debug, Serialize, Deserialize)]
struct JsonDirectionStats {
    packet_count: u64,
    byte_count: u64,
}

/// JSON格式的连接信息
#[derive(Debug, Serialize, Deserialize)]
struct JsonConnection {
    handshake: JsonHandshake,
    close: JsonClose,
    established_time: Option<String>,
    last_activity: Option<String>,
    quality_score: f64,
    retransmission_count: u32,
    out_of_order_count: u32,
    duplicate_ack_count: u32,
}

impl From<&crate::types::stream::ConnectionInfo> for JsonConnection {
    fn from(conn: &crate::types::stream::ConnectionInfo) -> Self {
        Self {
            handshake: JsonHandshake::from(&conn.handshake),
            close: JsonClose::from(&conn.close),
            established_time: conn.established_time.map(|ts| format_timestamp(Some(ts))),
            last_activity: conn.last_activity.map(|ts| format_timestamp(Some(ts))),
            quality_score: conn.quality_score(),
            retransmission_count: conn.retransmission_count,
            out_of_order_count: conn.out_of_order_count,
            duplicate_ack_count: conn.duplicate_ack_count,
        }
    }
}

/// JSON格式的握手信息
#[derive(Debug, Serialize, Deserialize)]
struct JsonHandshake {
    complete: bool,
    duration_ms: Option<f64>,
}

impl From<&crate::types::stream::TcpHandshake> for JsonHandshake {
    fn from(handshake: &crate::types::stream::TcpHandshake) -> Self {
        Self {
            complete: handshake.is_complete(),
            duration_ms: handshake.duration_ms(),
        }
    }
}

/// JSON格式的关闭信息
#[derive(Debug, Serialize, Deserialize)]
struct JsonClose {
    complete: bool,
    graceful: bool,
    reset: bool,
    duration_ms: Option<f64>,
}

impl From<&crate::types::stream::TcpClose> for JsonClose {
    fn from(close: &crate::types::stream::TcpClose) -> Self {
        Self {
            complete: close.is_complete(),
            graceful: close.is_graceful(),
            reset: close.reset,
            duration_ms: close.duration_ms(),
        }
    }
}

/// 格式化字节数
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

/// 格式化持续时间
fn format_duration(micros: Option<u64>) -> String {
    match micros {
        Some(0) => "0s".to_string(),
        Some(micros) => {
            let duration = Duration::from_micros(micros);
            let total_seconds = duration.as_secs();
            let total_millis = duration.as_millis();

            if total_seconds >= 60 {
                let minutes = total_seconds / 60;
                let seconds = total_seconds % 60;
                if minutes >= 60 {
                    let hours = minutes / 60;
                    let minutes = minutes % 60;
                    format!("{}h{}m", hours, minutes)
                } else {
                    format!("{}m{}s", minutes, seconds)
                }
            } else if total_seconds >= 1 {
                format!("{}s", total_seconds)
            } else if total_millis >= 1 {
                format!("{}ms", total_millis)
            } else {
                format!("{}μs", micros)
            }
        }
        None => "-".to_string(),
    }
}

/// 格式化时间戳
fn format_timestamp(timestamp: Option<u64>) -> String {
    match timestamp {
        Some(ts) => {
            let datetime = DateTime::from_timestamp(ts as i64 / 1_000_000, (ts % 1_000_000 * 1000) as u32);
            datetime
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
                .unwrap_or_else(|| format!("{}", ts))
        }
        None => "-".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::types::flow::FlowKey;
    use crate::types::stream::TcpStream;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Some(0)), "0s");
        assert_eq!(format_duration(Some(500)), "500μs");
        assert_eq!(format_duration(Some(1500)), "1ms");
        assert_eq!(format_duration(Some(1_500_000)), "1s");
        assert_eq!(format_duration(Some(90_000_000)), "1m30s");
        assert_eq!(format_duration(Some(3_600_000_000)), "1h0m");
        assert_eq!(format_duration(None), "-");
    }

    #[test]
    fn test_flow_filter() {
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let flow_key = FlowKey::new(src_ip, dst_ip, 12345, 80, 6);
        let stream = TcpStream::new(flow_key);

        // 测试协议过滤
        let filter = FlowFilter::new().protocol(6);
        assert!(filter.matches(&stream));

        let filter = FlowFilter::new().protocol(17);
        assert!(!filter.matches(&stream));

        // 测试端口过滤
        let filter = FlowFilter::new().src_port(12345);
        assert!(filter.matches(&stream));

        let filter = FlowFilter::new().dst_port(8080);
        assert!(!filter.matches(&stream));

        // 测试IP过滤
        let filter = FlowFilter::new().src_ip("192.168.1.1");
        assert!(filter.matches(&stream));

        let filter = FlowFilter::new().dst_ip("192.168.1.2");
        assert!(!filter.matches(&stream));
    }

    #[test]
    fn test_flow_formatter() {
        let formatter = FlowFormatter::new(OutputFormat::Simple);

        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let flow_key = FlowKey::new(src_ip, dst_ip, 12345, 80, 6);
        let stream = TcpStream::new(flow_key);

        let output = formatter.format_stream(&stream).unwrap();
        assert!(output.contains("TCP Stream"));
        assert!(output.contains("192.168.1.1"));
        assert!(output.contains("10.0.0.1"));
    }
}