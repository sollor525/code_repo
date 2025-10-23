

struct CustomSmartPointer {
    data: String,
}

impl Drop for CustomSmartPointer {
    fn drop(&mut self) {
        println!("Dropping CustomSmartPointer with data `{}`!", self.data);
    }
}

fn main() {
    let c = CustomSmartPointer {
        data: String::from("some data"),
    };
    println!("CustomSmartPointer created.");

    /*
    如果打开此注释会报错。
    Rust 不允许显式调用 drop，因为 Rust 会在 main 的结尾对值自动调用 drop，这会导致一个 double free 错误。
    不能禁用当值离开作用域时自动插入的 drop，并且不能显式调用 drop 方法。
    如果我们需要强制提早清理值，可以使用 std::mem::drop 函数。
    */
    //c.drop();
    drop(c);


    println!("CustomSmartPointer dropped before the end of main.");
}