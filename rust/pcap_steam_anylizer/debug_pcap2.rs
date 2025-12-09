use std::fs::File;
use std::io::Read;

fn main() {
    let mut file = File::open("./pcap_file/ack_rest.pcap").unwrap();
    let mut header_bytes = [0u8; 24];
    file.read_exact(&mut header_bytes).unwrap();

    let linktype = u32::from_le_bytes([header_bytes[16], header_bytes[17], header_bytes[18], header_bytes[19]]);
    println!("Link type: {}", linktype);

    // 读取第一个数据包
    let mut pkt_header = [0u8; 16];
    file.read_exact(&mut pkt_header).unwrap();

    let caplen = u32::from_le_bytes([pkt_header[8], pkt_header[9], pkt_header[10], pkt_header[11]]) as usize;

    let mut pkt_data = vec![0u8; caplen];
    file.read_exact(&mut pkt_data).unwrap();

    println!("\nPacket data length: {}", caplen);

    // Check if it's standard Ethernet
    if caplen >= 14 && pkt_data[12] == 0x08 && pkt_data[13] == 0x00 {
        println!("This looks like an Ethernet frame (type 0x0800 = IPv4)");
        println!("Dest MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            pkt_data[0], pkt_data[1], pkt_data[2], pkt_data[3], pkt_data[4], pkt_data[5]);
        println!("Src MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            pkt_data[6], pkt_data[7], pkt_data[8], pkt_data[9], pkt_data[10], pkt_data[11]);

        // Print IP header
        if caplen >= 34 {
            let ip_start = 14;
            println!("IP protocol: {}", pkt_data[ip_start + 9]);
            println!("IP header starts at offset {}", ip_start);
        }
    } else if caplen >= 16 && linktype == 65535 {
        println!("Processing as Linux Cooked Capture");
        // Try to parse as SLL
        println!("Packet type: 0x{:04x}", u16::from_be_bytes([pkt_data[0], pkt_data[1]]));
        println!("Protocol in SLL: 0x{:04x}", u16::from_be_bytes([pkt_data[14], pkt_data[15]]));
    }
}