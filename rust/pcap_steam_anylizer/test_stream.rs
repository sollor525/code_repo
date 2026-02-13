// Simple test to check the one-way-blocking detection for a specific flow
use std::net::IpAddr;

fn main() {
    // Test the IP parsing
    let ip1: IpAddr = "10.105.108.253".parse().unwrap();
    let ip2: IpAddr = "10.105.108.251".parse().unwrap();

    println!("IP1: {}", ip1);
    println!("IP2: {}", ip2);

    // Check if the comparison works
    let ip1_cmp: IpAddr = "10.105.108.253".parse().unwrap();
    let ip2_cmp: IpAddr = "10.105.108.251".parse().unwrap();

    println!("IP comparison: {} == {} -> {}", ip1, ip1_cmp, ip1 == ip1_cmp);
    println!("IP comparison: {} == {} -> {}", ip2, ip2_cmp, ip2 == ip2_cmp);
}