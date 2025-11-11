/// 定义一个消息传递器(trait) - 类似于其他语言中的接口(interface)
/// 这是一个trait定义，定义了一个行为契约
pub trait Messenger {
    /// 发送消息的方法
    /// 参数: msg - 要发送的消息字符串
    /// 注意: &self 表示这是一个借用self的方法，不会获取所有权
    fn send(&self, msg: &str);
}

/// 限制追踪器结构体 - 用于跟踪某种配额使用情况
/// 泛型参数:
///   'a - 生命周期参数，确保引用的有效性
///   T: Messenger - 泛型类型T必须实现了Messenger trait
pub struct LimitTracker<'a, T: Messenger> {
    messenger: &'a T,     // 对实现了Messenger trait的类型的引用
    value: usize,         // 当前使用值
    max: usize,           // 最大允许值
}

/// 为LimitTracker实现方法
impl<'a, T> LimitTracker<'a, T>
where
    T: Messenger,  // 约束条件：T类型必须实现Messenger trait
{
    /// 创建新的LimitTracker实例
    /// 参数:
    ///   messenger: 实现了Messenger trait的对象的引用
    ///   max: 最大允许值
    /// 返回: 新的LimitTracker实例
    pub fn new(messenger: &'a T, max: usize) -> LimitTracker<'a, T> {
        LimitTracker {
            messenger,  // 字段初始化简写（当字段名和变量名相同时）
            value: 0,   // 初始值设为0
            max,        // 字段初始化简写
        }
    }

    /// 设置当前值并检查是否超过配额限制
    /// 参数: value - 要设置的新值
    /// 这个方法会根据使用情况发送不同的警告消息
    pub fn set_value(&mut self, value: usize) {
        // 更新当前值
        self.value = value;

        // 计算使用百分比 (使用f64浮点数进行除法)
        // as f64 将整数转换为浮点数
        let percentage_of_max = self.value as f64 / self.max as f64;

        // 根据不同的使用百分比发送不同的消息
        if percentage_of_max >= 1.0 {
            // 使用率达到或超过100%，发送错误消息
            self.messenger.send("Error: You are over your quota!");
        } else if percentage_of_max >= 0.9 {
            // 使用率达到90%以上，发送紧急警告
            self.messenger
                .send("Urgent warning: You've used up over 90% of your quota!");
        } else if percentage_of_max >= 0.75 {
            // 使用率达到75%以上，发送一般警告
            self.messenger
                .send("Warning: You've used up over 75% of your quota!");
        }
        // 注意：使用率低于75%时不发送任何消息
    }
}

// 引入示例模块
mod example;
mod refcell_example;

// 主函数 - 程序入口点
fn main() {
    println!("Rust泛型和Trait示例程序\n");

    // 运行基础示例
    example::run_examples();
    example::demonstrate_refcell_need();

    // 运行RefCell示例
    refcell_example::run_refcell_examples();
    //refcell_example::demonstrate_refcell_rules();
    //refcell_example::demonstrate_runtime_panic();
}
