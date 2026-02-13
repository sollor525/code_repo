use etherparse::{PacketSlice, TcpHeaderSlice};

fn main() {
    // Test if we can get raw window size
    let data = [0u8; 20]; // Minimal TCP header
    if let Ok(tcp) = TcpHeaderSlice::from_slice(&data) {
        println!("Window size: {}", tcp.window_size());
        
        // Check if there's a method to get raw window size
        // Try to find window scale option
        for option in tcp.options_iterator() {
            if let Ok(opt) = option {
                match opt {
                    TcpOptionElement::Unknown { kind, .. } => {
                        println!("Unknown option kind: {}", kind);
                    }
                    _ => {
                        println!("Other option");
                    }
                }
            }
        }
    }
}
