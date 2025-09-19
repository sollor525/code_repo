fn main() {
    let mut str1 = String::new();
    str1.push_str("Hello, world!");
    println!("{}", str1);


    let data = "initial contents";
    let s = data.to_string();
    println!("{}", s);
    // 该方法也可直接用于字符串字面值：
    let s = "initial contents".to_string();
    println!("{}", s);


    let s = String::from("initial contents");
    println!("{}", s);


    println!("\n字符串是 UTF-8 编码,可以包含任何经过正确编码的数据");
    let hello = String::from("السلام عليكم");
    println!("{}", hello);
    let hello = String::from("Dobrý den");
    println!("{}", hello);
    let hello = String::from("Hello");
    println!("{}", hello);
    let hello = String::from("שלום");
    println!("{}", hello);
    let hello = String::from("नमस्ते");
    println!("{}", hello);
    let hello = String::from("こんにちは");
    println!("{}", hello);
    let hello = String::from("안녕하세요");
    println!("{}", hello);
    let hello = String::from("你好");
    println!("{}", hello);
    let hello = String::from("Olá");
    println!("{}", hello);
    let hello = String::from("Здравствуйте");
    println!("{}", hello);
    let hello = String::from("Hola");
    println!("{}", hello);


    println!("\n更新字符串");
    let mut s = String::from("foo");
    s.push_str("bar");
    println!("{}", s);

    let mut s1 = String::from("foo");
    let s2 = "bar";
    s1.push_str(s2);
    println!("s2 is {s2}");
    println!("s1 is {}", s1);


    println!("\npush 字符");
    let mut s = String::from("lo");
    s.push('l');
    println!("{}", s);

    println!("\n字符串连接");
    let s1 = String::from("Hello, ");
    let s2 = String::from("world!");
    let s3 = s1 + &s2; // 注意 s1 被移动了，不能继续使用
    println!("{}", s3);
    

    let s1 = String::from("tic");
    let s2 = String::from("tac");
    let s3 = String::from("toe");
    let s = s1 + "-" + &s2 + "-" + &s3;
    println!("{}", s);


    let s1 = String::from("tic");
    let s2 = String::from("tac");
    let s3 = String::from("toe");
    let s = format!("{s1}-{s2}-{s3}");
    println!("{}", s);


    println!("\n 字符串 slice");
    let hello = "Здравствуйте";
    let s = &hello[0..4];
    println!("{}", s);


    println!("\n 遍历字符串-字符");
    for c in "Зд".chars() {
        println!("{c}");
    }
    println!("\n 遍历字符串-原始字节");
    for b in "Зд".bytes() {
        println!("{b}");
    }


}
