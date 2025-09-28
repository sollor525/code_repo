use pcap::{Capture, Packet, PacketHeader};
use libc::timeval;
use std::net::Ipv4Addr;
use gen_pcap::{
    build_tcp_handshake_packets,
    build_http_post_flow_packets, 
    build_http_get_post_flow_packets
};


const PCAP_FILE: &str = "multi_tcp_handshake.pcap";
const SRC_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
//const DST_MAC: [u8; 6] = [0x00, 0x66, 0x77, 0x88, 0x99, 0xaa];
const DST_MAC: [u8; 6] = [0xe2, 0xc9, 0xfc, 0xf5, 0x9e, 0x3c];
const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 10, 1, 100);
const DST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const SRC_PORT: u16 = 23333;
const DST_PORTS: [u16; 6] = [22, 21, 25, 3306, 5672, 9200];
const HTTP_DST_PORT: u16 = 8080;


fn main() {
    // 以“死”设备方式创建 pcap 文件
    let cap = Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let mut savefile = cap.savefile(PCAP_FILE).unwrap();

    for (idx, &dst_port) in DST_PORTS.iter().enumerate() {
        let isn = 1000000 + idx as u32;

        // 使用封装的TCP三次握手函数
        let (handshake_packets, _conn) = build_tcp_handshake_packets(
            SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, dst_port, isn
        );

        // 写入所有握手包
        for packet_data in handshake_packets {
            let header = PacketHeader {
                ts: timeval { tv_sec: 0, tv_usec: 0 },
                caplen: packet_data.len() as u32,
                len: packet_data.len() as u32,
            };
            let packet = Packet::new(&header, &packet_data);
            savefile.write(&packet);
        }

        println!("[+] 端口 {} 三次握手完成", dst_port);
        //thread::sleep(Duration::from_secs(1));
    }

    // 使用封装的HTTP完整流程函数
    {
        let isn = 1000000 + 8080;
        let dst_port = HTTP_DST_PORT;
        
        // 使用封装的完整HTTP流程（包含GET和POST）
        let http_packets = build_http_get_post_flow_packets(
            SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, dst_port, isn,
            "/",           // GET URI
            "/api/users",           // POST URI
            "example.com",          // Host
            b"{\"name\": \"Bob\", \"email\": \"bob@example.com\"}", // POST数据
            b"{\"users\": [{\"id\": 1, \"name\": \"Alice\"}]}",    // GET响应
            b"{\"id\": 2, \"message\": \"User created successfully\"}", // POST响应
        );

        // 写入所有HTTP包
        for packet_data in http_packets {
            let header = PacketHeader {
                ts: timeval { tv_sec: 0, tv_usec: 0 },
                caplen: packet_data.len() as u32,
                len: packet_data.len() as u32,
            };
            let packet = Packet::new(&header, &packet_data);
            savefile.write(&packet);
        }

        println!("[+] HTTP 完整流程完成（包含三次握手、GET请求/响应、POST请求/响应）");
    }

    {
        const URI_LIST: [&str; 4] = [
            "/onvif/device_service",
            "/RPC2_Login",
            "/web_caps/webCapsConfig",
            "/System/deviceInfo",
        ];


        const HOST: &str = "192.168.1.100";
        const POST_DATA: &str = "{\"name\": \"Bob\", \"email\": \"bob@example.com\"}";
        const POST_RESPONSE: &str = "{\"id\": 2, \"message\": \"User created successfully\"}";
        
        let isn = 1000000 + 8080;
        let dst_port = HTTP_DST_PORT;
        let mut src_port = SRC_PORT;
        for uri in URI_LIST {
            src_port += 1;

            // 使用封装的完整HTTP流程
            let http_packets = build_http_post_flow_packets(
                SRC_MAC, DST_MAC, SRC_IP, DST_IP, src_port, dst_port, isn,
                &uri, 
                HOST, 
                "application/json",
                POST_DATA.as_bytes(), 
                POST_RESPONSE.as_bytes(),
            );
            for packet_data in http_packets {
                let header = PacketHeader {
                    ts: timeval { tv_sec: 0, tv_usec: 0 },
                    caplen: packet_data.len() as u32,
                    len: packet_data.len() as u32,
                };
          
                let packet = Packet::new(&header, &packet_data);
                savefile.write(&packet);
            }
        } 

        println!("[+] HTTP 四种视频协议流的流程完成（包含三次握手、POST请求/响应）");
    }


    println!("全部完成，已写入 {}", PCAP_FILE);
}

