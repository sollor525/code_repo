// 使用示例：演示如何使用LimitTracker和Messenger

// 导入我们定义的trait和struct
use crate::Messenger;
use crate::LimitTracker;

// 创建一个具体的消息发送器结构体
pub struct StringMessenger {
    messages: Vec<String>, // 用于存储接收到的消息
}

impl StringMessenger {
    // 创建新的StringMessenger实例
    pub fn new() -> StringMessenger {
        StringMessenger {
            messages: Vec::new(),
        }
    }

    // 获取所有消息
    pub fn get_messages(&self) -> &Vec<String> {
        &self.messages
    }
}

// 为StringMessenger实现Messenger trait
impl Messenger for StringMessenger {
    fn send(&self, msg: &str) {
        // 注意：这里我们只是打印消息，但实际上无法修改self
        // 因为send方法的签名是&self（不可变借用），不是&mut self
        println!("消息发送: {}", msg);

        // 在实际应用中，你可能需要使用RefCell或Mutex来修改内部状态
    }
}

// 另一个示例：使用可变引用的消息发送器
pub struct MutableMessenger {
    messages: Vec<String>,
}

impl MutableMessenger {
    pub fn new() -> MutableMessenger {
        MutableMessenger {
            messages: Vec::new(),
        }
    }

    pub fn get_messages(&self) -> &Vec<String> {
        &self.messages
    }

    pub fn clear_messages(&mut self) {
        self.messages.clear();
    }
}

impl Messenger for MutableMessenger {
    fn send(&self, msg: &str) {
        println!("可变消息器发送: {}", msg);
        // 同样，由于send方法的限制，我们无法直接修改messages
    }
}

// 使用示例函数
pub fn run_examples() {
    println!("=== LimitTracker 使用示例 ===\n");

    // 创建一个简单的消息发送器
    let messenger = StringMessenger::new();

    // 创建LimitTracker实例
    let mut tracker = LimitTracker::new(&messenger, 100);

    println!("1. 设置值到50 (50%使用率):");
    tracker.set_value(50); // 应该不会发送任何消息，因为50% < 75%

    println!("\n2. 设置值到80 (80%使用率):");
    tracker.set_value(80); // 应该发送警告消息，因为80% >= 75%

    println!("\n3. 设置值到95 (95%使用率):");
    tracker.set_value(95); // 应该发送紧急警告，因为95% >= 90%

    println!("\n4. 设置值到100 (100%使用率):");
    tracker.set_value(100); // 应该发送错误消息，因为100% >= 100%

    println!("\n5. 设置值到105 (105%使用率):");
    tracker.set_value(105); // 应该发送错误消息，因为105% >= 100%
}

// 这个函数展示了为什么可能需要RefCell
pub fn demonstrate_refcell_need() {
    println!("\n=== 为什么需要RefCell的示例 ===\n");

    // 如果你想要在send方法中修改内部状态，你需要使用内部可变性模式
    // 这通常使用RefCell或Mutex来实现

    println!("在当前的Messenger trait定义中，send方法使用&self，");
    println!("这意味着实现者不能在send方法中修改自己的状态。");
    println!("如果你需要在发送消息时记录历史，你需要：");
    println!("1. 使用RefCell来获得内部可变性，或者");
    println!("2. 修改trait定义，使send方法接受&mut self");
}