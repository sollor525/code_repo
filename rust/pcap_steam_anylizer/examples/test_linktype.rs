use pcap_steam_anylizer::pcap::PcapReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pcap_reader = PcapReader::open("./pcap_file/ack_rest1.pcap")?;
    println!("Linktype: {}", pcap_reader.global_header().linktype);

    // 读取第一个包看看
    match pcap_reader.next_packet() {
        Ok(Some(packet)) => {
            println!("First packet read successfully");
        }
        _ => {}
    }

    Ok(())
}