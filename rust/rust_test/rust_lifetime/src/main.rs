
struct ImportantExcerpt<'a> {
    part: &'a str,
}


fn first_word(s: &str) -> &str {
    let bytes = s.as_bytes();

    for (i, &item) in bytes.iter().enumerate() {
        if item == b' ' {
            return &s[0..i];
        }
    }

    &s[..]
}


struct ImportantExcerpt1<'a> {
    part: &'a str,
}

impl<'a> ImportantExcerpt1<'a> {
    fn level(&self) -> i32 {
        3
    }
}

impl<'a> ImportantExcerpt1<'a> {
    fn announce_and_return_part(&self, announcement: &str) -> &str {
        println!("Attention please: {announcement}");
        self.part
    }
}


use std::fmt::Display;

fn longest_with_an_announcement<'a, T>(
    x: &'a str,
    y: &'a str,
    ann: T,
) -> &'a str
where
    T: Display,
{
    println!("Announcement! {ann}");
    if x.len() > y.len() { x } else { y }
}


fn main() {
    let r;
    {
        let x = 5;
        r = x;
    }
    println!("r: {}", r);


    let string1 = String::from("abcd");
    let string2 = "xyz";
    let result = longest(string1.as_str(), string2);
    println!("The longest string is {result}");


    println!("\n函数生命周期");
    let string1 = String::from("long string is long");
    {
        let string2 = String::from("xyz");
        let result = longest(string1.as_str(), string2.as_str());
        println!("The longest string is {result}");
    }


    println!("\n结构体生命周期");
    let novel = String::from("Call me Ishmael. Some years ago...");
    let mut iter = novel.split('.'); 
    let first_sentence = iter.next().unwrap();
    let i = ImportantExcerpt {
        part: first_sentence,
    };
    println!("The first sentence is {}", i.part);
    let second_sentence = iter.next().unwrap();
    let i = ImportantExcerpt {
        part: second_sentence,
    };
    println!("The second sentence is {}", i.part);


    println!("\n生命周期省略");
    let my_string = String::from("hello world");
    // first_word works on slices of `String`s
    let word = first_word(&my_string[..]);
    println!("The first word is: {word}");
    let my_string_literal = "hello world";
    // first_word works on slices of string literals
    let word = first_word(&my_string_literal[..]);
    println!("The first word is: {word}");
    // Because string literals *are* string slices already,
    // this works too, without the slice syntax!
    let word = first_word(my_string_literal);
    println!("The first word is: {word}");


    println!("\n结构体方法生命周期");
    let novel = String::from("Call me Ishmael. Some years ago...");
    let first_sentence = novel.split('.').next().unwrap();
    let i = ImportantExcerpt1 {
        part: first_sentence,
    };
    println!("The first sentence is {}", i.part);
    println!("The level is {}", i.level());
    let part = i.announce_and_return_part("Breaking news!");
    println!("The part is {part}");


    println!("\n静态生命周期");
    let s: &'static str = "I have a static lifetime.";
    println!("The static lifetime is {s}");


    println!("\n结合泛型类型参数、trait bounds 和生命周期");
    let string1 = String::from("abcd");
    let string2 = "xyz";
    let result = longest_with_an_announcement(
        string1.as_str(),
        string2,
        "Today is someone's birthday!",
    );
    println!("The longest string is {result}");

}

fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}