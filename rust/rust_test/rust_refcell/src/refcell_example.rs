// RefCell示例：展示如何使用内部可变性

use std::cell::RefCell;
use crate::Messenger;

// 使用RefCell的消息发送器 - 可以在不可变方法中修改内部状态
pub struct RefCellMessenger {
    // RefCell<T> 允许在运行时检查借用规则
    // 即使我们有&self（不可变借用），也能获得内部数据的可变引用
    messages: RefCell<Vec<String>>,
}

impl RefCellMessenger {
    pub fn new() -> RefCellMessenger {
        RefCellMessenger {
            messages: RefCell::new(Vec::new()),
        }
    }

    // 获取消息列表（需要显式借用）
    pub fn get_messages(&self) -> Vec<String> {
        // borrow() 获取不可变引用
        self.messages.borrow().clone()
    }

    // 清空消息列表（需要可变引用）
    pub fn clear_messages(&self) {
        // borrow_mut() 获取可变引用
        self.messages.borrow_mut().clear();
    }

    // 获取消息数量
    pub fn message_count(&self) -> usize {
        self.messages.borrow().len()
    }
}

impl Messenger for RefCellMessenger {
    fn send(&self, msg: &str) {
        println!("RefCell消息器接收到: {}", msg);

        // 关键：虽然send方法的签名是&self（不可变），
        // 但我们仍然可以通过RefCell修改内部数据！
        self.messages.borrow_mut().push(msg.to_string());

        println!("消息已存储，当前消息总数: {}", self.message_count());
    }
}

// 更高级的示例：带有时间戳的消息发送器
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TimestampedMessenger {
    messages: RefCell<Vec<(String, u64)>>, // (消息, 时间戳)
}

impl TimestampedMessenger {
    pub fn new() -> TimestampedMessenger {
        TimestampedMessenger {
            messages: RefCell::new(Vec::new()),
        }
    }

    // 获取当前时间戳
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    pub fn get_messages(&self) -> Vec<(String, u64)> {
        self.messages.borrow().clone()
    }

    // 获取格式化的消息列表
    pub fn get_formatted_messages(&self) -> Vec<String> {
        self.messages
            .borrow()
            .iter()
            .map(|(msg, timestamp)| {
                format!("[{}] {}", timestamp, msg)
            })
            .collect()
    }

    // 获取最后一条消息
    pub fn get_last_message(&self) -> Option<String> {
        self.messages
            .borrow()
            .last()
            .map(|(msg, timestamp)| format!("[{}] {}", timestamp, msg))
    }
}

impl Messenger for TimestampedMessenger {
    fn send(&self, msg: &str) {
        let timestamp = Self::current_timestamp();

        // 存储带有时间戳的消息
        self.messages.borrow_mut().push((msg.to_string(), timestamp));

        println!("带时间戳的消息已记录: [{}] {}", timestamp, msg);
    }
}

// 运行RefCell示例
pub fn run_refcell_examples() {
    println!("\n=== RefCell内部可变性示例 ===\n");

    // 创建RefCell消息发送器
    let refcell_messenger = RefCellMessenger::new();
    let mut tracker = crate::LimitTracker::new(&refcell_messenger, 100);

    println!("1. 使用RefCell消息器测试配额警告:");

    tracker.set_value(85); // 85% - 应该触发警告
    tracker.set_value(92); // 92% - 应该触发紧急警告

    println!("\n存储的消息:");
    for (i, message) in refcell_messenger.get_messages().iter().enumerate() {
        println!("  {}. {}", i + 1, message);
    }

    println!("\n2. 使用带时间戳的消息器:");

    let timestamped_messenger = TimestampedMessenger::new();
    let mut timestamped_tracker = crate::LimitTracker::new(&timestamped_messenger, 50);

    timestamped_tracker.set_value(45); // 90% - 应该触发紧急警告
    timestamped_tracker.set_value(55); // 110% - 应该触发错误

    println!("\n带时间戳的消息:");
    for formatted_msg in timestamped_messenger.get_formatted_messages() {
        println!("  {}", formatted_msg);
    }

    println!("\n最后一条消息:");
    if let Some(last_msg) = timestamped_messenger.get_last_message() {
        println!("  {}", last_msg);
    }
}

// 展示RefCell的借用规则检查
pub fn demonstrate_refcell_rules() {
    println!("\n=== RefCell借用规则演示 ===\n");

    let messenger = RefCellMessenger::new();

    println!("正常借用:");
    messenger.send("测试消息1");

    // 获取消息列表的不可变借用
    let messages = messenger.get_messages();
    println!("消息数量: {}", messages.len());

    println!("\n可以在同一作用域中进行多次不可变借用:");
    {
        let msg1 = messenger.get_messages();
        let msg2 = messenger.get_messages();
        println!("两次借用的消息数量: {}, {}", msg1.len(), msg2.len());
    }

    println!("\n可变借用会独占访问:");
    {
        messenger.send("测试消息2");
        messenger.clear_messages();
        println!("清空后的消息数量: {}", messenger.message_count());
    }

    println!("RefCell在运行时检查借用规则，如果违反规则会导致panic!");
}

// 演示RefCell的运行时检查
pub fn demonstrate_runtime_panic() {
    println!("\n!!! 潜在的RefCell panic示例 (注释掉以避免程序崩溃) !!!");
    println!("以下代码如果取消注释会导致panic:");
    println!("");
    println!("let messenger = RefCellMessenger::new();");
    println!("let borrow1 = messenger.messages.borrow();     // 第一次不可变借用");
    println!("let borrow2 = messenger.messages.borrow_mut(); // 尝试可变借用 -> PANIC!");
    println!("");
    println!("错误: 同时存在不可变借用和可变借用违反了Rust的借用规则");
}