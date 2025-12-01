
///! map() - 转换元素
/// !基本转换
pub fn map_basics() {
    let numbers = vec![1, 2, 3, 4, 5];
    
    // 简单数学运算
    let doubled: Vec<i32> = numbers.iter()
        .map(|x| x * 2)
        .collect();
    println!("翻倍: {:?}", doubled); // [2, 4, 6, 8, 10]
    
    // 类型转换
    let strings: Vec<String> = numbers.iter()
        .map(|x| x.to_string())
        .collect();
    println!("字符串: {:?}", strings); // ["1", "2", "3", "4", "5"]
    
    // 复杂转换
    let descriptions: Vec<String> = numbers.iter()
        .map(|x| format!("数字是: {}", x))
        .collect();
    println!("描述: {:?}", descriptions);
}

///! 使用闭包的多种方式
pub fn map_with_closures() {
    let numbers = vec![1, 2, 3, 4, 5];
    
    // 方式1: 直接内联闭包
    let result1: Vec<i32> = numbers.iter()
        .map(|x| x + 1)
        .collect();
    
    // 方式2: 预先定义闭包
    let add_one = |x: &i32| x + 1;
    let result2: Vec<i32> = numbers.iter()
        .map(add_one)
        .collect();
    
    // 方式3: 使用函数指针
    fn double(x: &i32) -> i32 { x * 2 }
    let result3: Vec<i32> = numbers.iter()
        .map(double)
        .collect();
    
    // 方式4: 捕获环境变量
    let multiplier = 3;
    let result4: Vec<i32> = numbers.iter()
        .map(|x| x * multiplier) // 捕获外部的 multiplier
        .collect();
    
    println!("结果: {:?}", result4); // [3, 6, 9, 12, 15]
}



#[derive(Debug)]
struct Person {
    name: String,
    age: u32,
}

///! 处理复杂数据结构
pub fn complex_mapping() {
    let people = vec![
        Person { name: "Alice".to_string(), age: 30 },
        Person { name: "Bob".to_string(), age: 25 },
        Person { name: "Charlie".to_string(), age: 35 },
    ];
    
    // 提取字段
    let names: Vec<String> = people.iter()
        .map(|person| person.name.clone())
        .collect();
    println!("名字: {:?}", names);
    
    // 复杂转换
    let descriptions: Vec<String> = people.iter()
        .map(|person| {
            if person.age > 30 {
                format!("{} (资深)", person.name)
            } else {
                format!("{} (年轻)", person.name)
            }
        })
        .collect();
    println!("描述: {:?}", descriptions);
    
    // 处理 Result 类型
    let string_numbers = vec!["1", "2", "three", "4"];
    let parsed: Result<Vec<i32>, _> = string_numbers.iter()
        .map(|s| s.parse::<i32>())
        .collect(); // 注意：这里需要处理错误
}

