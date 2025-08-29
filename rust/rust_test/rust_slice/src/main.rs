

//接收一个用空格分隔单词的字符串，并返回在该字符串中找到的第一个单词。
//如果在该字符串中并未找到空格，则整个字符串就是一个单词，所以应该返回整个字符串。


fn first_word1(s: &String) -> usize {
    let bytes = s.as_bytes();

    for (i, &item) in bytes.iter().enumerate() {
        if item == b' ' {
            return i;
        }
    }

    s.len()
}

fn first_word2(s: &String) -> usize {
    let bytes = s.as_bytes();

    for (i, &item) in bytes.iter().enumerate() {
        if item == b' ' {
            return i;
        }
    }

    s.len()
}

fn first_word3(s: &str) -> &str {
    let bytes = s.as_bytes();

    for (i, &item) in bytes.iter().enumerate() {
        if item == b' ' {
            return &s[0..i];
        }
    }

    &s[..]
}

fn main() {
    let my_string = String::from("hello world");

    let word = first_word1(&my_string);
    println!("the first word is: {}", word);    

    let word = first_word2(&my_string);
    println!("the first word is: {}", word);    

    let str = first_word3(&my_string);
    println!("the string is: {}", str); 

    // `first_word` 适用于 `String`（的 slice），部分或全部
    let _word = first_word3(&my_string[0..6]);
    let _word = first_word3(&my_string[..]);
    // `first_word` 也适用于 `String` 的引用，
    // 这等价于整个 `String` 的 slice
    let _word = first_word3(&my_string);

    let my_string_literal = "hello world";

    // `first_word` 适用于字符串字面值，部分或全部
    let _word = first_word3(&my_string_literal[0..6]);
    let _word = first_word3(&my_string_literal[..]);

    // 因为字符串字面值已经是字符串 slice 了，
    // 这也是适用的，无需 slice 语法！
    let _word = first_word3(my_string_literal);
    

    let a = [1, 2, 3, 4, 5];
    let a_slice = &a[1..3];
    assert_eq!(a_slice, &[2, 3]);

}
