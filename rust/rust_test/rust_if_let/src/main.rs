
#[derive(Debug)]
enum UsState {
    Alabama,
    Alaska,
    // --snip--
}

#[derive(Debug)]
enum Coin {
    Penny,
    Nickel,
    Dime,
    Quarter(UsState),
}

impl UsState {
    fn existed_in(&self, year: u16) -> bool {
        match self {
            UsState::Alabama => year >= 1819,
            UsState::Alaska => year >= 1959,
            // -- snip --
        }
    }
}

fn describe_state_quarter(coin: Coin) -> Option<String> {
    if let Coin::Quarter(state) = coin {
        if state.existed_in(1900) {
            Some(format!("{state:?} is pretty old, for America!"))
        } else {
            Some(format!("{state:?} is relatively new."))
        }
    } else {
        None
    }
}

fn describe_state_quarter1(coin: Coin) -> Option<String> {
    let state = if let Coin::Quarter(state) = coin {
        state
    } else {
        return None;
    };

    if state.existed_in(1900) {
        Some(format!("{state:?} is pretty old, for America!"))
    } else {
        Some(format!("{state:?} is relatively new."))
    }
}

fn describe_state_quarter2(coin: Coin) -> Option<String> {
    let Coin::Quarter(state) = coin else {
        return None;
    };

    if state.existed_in(1900) {
        Some(format!("{state:?} is pretty old, for America!"))
    } else {
        Some(format!("{state:?} is relatively new."))
    }
}

fn main() {
    let config_max = Some(3u8);
    match config_max {
        Some(max) => println!("The maximum is configured to be {max}"),
        _ => (),
    }

    println!("--------------------------------");
    if let Some(max) = config_max { 
        println!("The maximum is configured to be {max}");
    }

    println!("--------------------------------");
    let coin = Coin::Penny;
    let mut count = 0;
    if let Coin::Quarter(state) = coin {
        println!("State quarter from {state:?}!");
    } else {
        dbg!(&coin);
        println!("{:?}", coin);
        count += 1;
    }

    println!("--------------------------------");
    if let Some(desc) = describe_state_quarter(Coin::Quarter(UsState::Alabama)) {
        println!("{desc}");
    }
    if let Some(desc) = describe_state_quarter(Coin::Quarter(UsState::Alaska)) {
        println!("{desc}");
    }
    if let Some(desc) = describe_state_quarter(Coin::Penny) {
        println!("{desc}");
    }

    println!("--------------------------------");
    if let Some(desc) = describe_state_quarter1(Coin::Quarter(UsState::Alabama)) {
        println!("{desc}");
    }
    if let Some(desc) = describe_state_quarter1(Coin::Quarter(UsState::Alaska)) {
        println!("{desc}");
    }
    if let Some(desc) = describe_state_quarter1(Coin::Penny) {
        println!("{desc}");
    }

    println!("--------------------------------");
    if let Some(desc) = describe_state_quarter2(Coin::Quarter(UsState::Alabama)) {
        println!("{desc}");
    }
    if let Some(desc) = describe_state_quarter2(Coin::Quarter(UsState::Alaska)) {
        println!("{desc}");
    }
    if let Some(desc) = describe_state_quarter2(Coin::Penny) {
        println!("{desc}");
    }

}
