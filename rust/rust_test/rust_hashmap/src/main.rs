use std::collections::HashMap;



fn main() {
    let mut hashmap = HashMap::new();
    hashmap.insert("key", "value");
    println!("{:?}", hashmap);
    let mut scores = HashMap::new();
    scores.insert(String::from("Blue"), 10);
    scores.insert(String::from("Yellow"), 50);
    println!("{:?}", scores);
    let team_name = String::from("Blue");
    let score = scores.get(&team_name).copied().unwrap_or(0);
    println!("{:?}", score);

    for (key, value) in &scores {
        println!("{}: {}", key, value);
    }
    
    
    println!("\n覆盖旧值");
    let mut scores = HashMap::new();
    scores.insert(String::from("Blue"), 10);
    scores.insert(String::from("Blue"), 25);
    println!("{scores:?}");


    println!("\n只在键尚不存在时插入键值对");
    let mut scores = HashMap::new();
    scores.insert(String::from("Blue"), 10);
    scores.entry(String::from("Yellow")).or_insert(50);
    scores.entry(String::from("Blue")).or_insert(50);
    println!("{scores:?}");


    println!("\n根据旧值更新一个值");
    let text = "hello world wonderful world";
    let mut map = HashMap::new();
    for word in text.split_whitespace() {
        let count = map.entry(word).or_insert(0);
        *count += 1;
    }
    println!("{map:?}");
}
