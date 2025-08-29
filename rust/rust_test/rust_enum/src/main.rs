


fn main() {

    enum IpAddr {
        V4(String),
        V6(String),
    }

    let home = IpAddr::V4(String::from("127.0.0.1"));
    let loopback = IpAddr::V6(String::from("::1"));

    // Use the IP addresses to eliminate warnings
    match home {
        IpAddr::V4(addr) => println!("Home IP: {}", addr),
        IpAddr::V6(addr) => println!("Home IP: {}", addr),
    }

    match loopback {
        IpAddr::V4(addr) => println!("Loopback IP: {}", addr),
        IpAddr::V6(addr) => println!("Loopback IP: {}", addr),
    }


    let some_number = Some(5);
    let some_char = Some('e');
    let absent_number: Option<i32> = None;
    dbg!(some_number);
    dbg!(some_char);
    dbg!(absent_number);    
}
