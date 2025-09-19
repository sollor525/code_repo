use pcap::{Capture, Packet, PacketHeader};
use libc::timeval;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{TcpFlags, MutableTcpPacket};
use pnet::packet::MutablePacket;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;
use pnet::packet::tcp;
use pnet::packet::ipv4;


const PCAP_FILE: &str = "multi_tcp_handshake.pcap";
const SRC_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
//const DST_MAC: [u8; 6] = [0x00, 0x66, 0x77, 0x88, 0x99, 0xaa];
const DST_MAC: [u8; 6] = [0xe2, 0xc9, 0xfc, 0xf5, 0x9e, 0x3c];
const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 10, 1, 100);
const DST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const SRC_PORT: u16 = 23333;
const DST_PORTS: [u16; 6] = [22, 21, 25, 3306, 5672, 9200];


fn build_tcp_packet(
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

fn main() {
    // 以“死”设备方式创建 pcap 文件
    let cap = Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let mut savefile = cap.savefile(PCAP_FILE).unwrap();

    for (idx, &dst_port) in DST_PORTS.iter().enumerate() {
        let isn = 1000000 + idx as u32;

        // 1) SYN
        let syn = build_tcp_packet(
            SRC_MAC, DST_MAC,
            SRC_IP, DST_IP, SRC_PORT, dst_port,
            isn, 0,
            TcpFlags::SYN,
        );
        let header = PacketHeader {
            ts: timeval { tv_sec: 0, tv_usec: 0 },
            caplen: syn.len() as u32,
            len: syn.len() as u32,
        };
        let packet = Packet::new(&header, &syn);
        savefile.write(&packet);

        // 2) SYN/ACK (模拟对端回复)
        let syn_ack = build_tcp_packet(
            DST_MAC, SRC_MAC,
            DST_IP, SRC_IP, dst_port, SRC_PORT,
            isn + 1, isn + 1,
            TcpFlags::SYN | TcpFlags::ACK,
        );
        let header = PacketHeader {
            ts: timeval { tv_sec: 0, tv_usec: 0 },
            caplen: syn_ack.len() as u32,
            len: syn_ack.len() as u32,
        };
        let packet = Packet::new(&header, &syn_ack);
        savefile.write(&packet);

        // 3) ACK (三次握手完成)
        let ack = build_tcp_packet(
            SRC_MAC, DST_MAC,
            SRC_IP, DST_IP, SRC_PORT, dst_port,
            isn + 1, isn + 2,
            TcpFlags::ACK,
        );
        let header = PacketHeader {
            ts: timeval { tv_sec: 0, tv_usec: 0 },
            caplen: ack.len() as u32,
            len: ack.len() as u32,
        };
        let packet = Packet::new(&header, &ack);
        savefile.write(&packet);

        println!("[+] 端口 {} 三次握手完成", dst_port);
        thread::sleep(Duration::from_secs(1));
    }

    savefile.flush().unwrap();
    println!("全部完成，已写入 {}", PCAP_FILE);
}