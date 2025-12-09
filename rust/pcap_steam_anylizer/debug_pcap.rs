use std::fs::File;
use std::io::Read;

fn main() {
    let mut file = File::open("./pcap_file/ack_rest.pcap").unwrap();
    let mut header_bytes = [0u8; 24];
    file.read_exact(&mut header_bytes).unwrap();

    println!("PCAP Header:");
    for (i, b) in header_bytes.iter().enumerate() {
        println!("  {}: 0x{:02x}", i, b);
    }

    // 读取第一个数据包
    let mut pkt_header = [0u8; 16];
    file.read_exact(&mut pkt_header).unwrap();

    println!("\nFirst Packet Header:");
    for (i, b) in pkt_header.iter().enumerate() {
        println!("  {}: 0x{:02x}", i, b);
    }

    let caplen = u32::from_le_bytes([pkt_header[8], pkt_header[9], pkt_header[10], pkt_header[11]]) as usize;
    println!("\nCaptured length: {}", caplen);

    let mut pkt_data = vec![0u8; caplen];
    file.read_exact(&mut pkt_data).unwrap();

    println!("\nFirst 64 bytes of packet data:");
    for (i, b) in pkt_data.iter().enumerate().take(64) {
        if i % 16 == 0 {
            print!("\n{:04x}: ", i);
        }
        print!("{:02x} ", b);
    }
    println!();

    // 检查Linux cooked capture (SLL) 头部
    if pkt_data.len() >= 16 {
        println!("\nSLL Header:");
        println!("  Packet type: 0x{:04x}", u16::from_le_bytes([pkt_data[0], pkt_data[1]]));
        println!("  ARP type: 0x{:04x}", u16::from_le_bytes([pkt_data[2], pkt_data[3]]));
        println!("  Address length: 0x{:04x}", u16::from_le_bytes([pkt_data[4], pkt_data[5]]));
        println!("  Address count: 0x{:04x}", u16::from_le_bytes([pkt_data[6], pkt_data[7]]));
        println!("  Protocol: 0x{:04x}", u16::from_be_bytes([pkt_data[14], pkt_data[15]]));
    }

    // 查找IP头
    for i in 0..pkt_data.len() {
        if pkt_data[i] == 0x45 {
            println!("\nFound IPv4 header at offset {}", i);
            if i + 20 <= pkt_data.len() {
                println!("  IP header bytes:");
                for j in 0..20 {
                    print!("{:02x} ", pkt_data[i + j]);
                }
                println!();
                println!("  Protocol: {}", pkt_data[i + 9]);
                println!("  Source: {}.{}.{}.{}",
                    pkt_data[i + 12], pkt_data[i + 13],
                    pkt_data[i + 14], pkt_data[i + 15]);
                println!("  Dest: {}.{}.{}.{}",
                    pkt_data[i + 16], pkt_data[i + 17],
                    pkt_data[i + 18], pkt_data[i + 19]);
            }
            break;
        }
    }
}