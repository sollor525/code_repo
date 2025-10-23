use std::ops::Deref;

struct MyBox<T>(T);

impl<T> MyBox<T> {
    fn new(x: T) -> MyBox<T> {
        MyBox(x)
    }
}

impl <T> Deref for MyBox<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}


fn hello(name: &str) {
    println!("Hello, {name}!");
}


fn main() {
    let x = 5;
    let y = MyBox::new(x);

    assert_eq!(5, x);
    assert_eq!(5, *y);

    println!("y = {}", *y);

    /*
    &m 触发了 Deref 强制转换（deref coercion）。
    编译器在需要 &str 的地方看到 &MyBox<String>，会自动 连续解引用直到拿到 &String，再进一步拿到 &str
    &MyBox<String>
    ↓ deref()
    &String
    ↓ 自动 String::deref()
    &str          ← 函数形参要求的类型
    */
    let m = MyBox::new(String::from("Rust"));
    hello(&m);

    /*
    String 本身实现了 Deref<Target = str>，因此：&String  →  &str
    同样是 一次解引用 
    */
    let m = String::from("Rust");
    hello(&m);

}
