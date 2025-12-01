
///! 基本用法
pub fn iter_basics() {
    let vec = vec![1, 2, 3, 4, 5];
    
    // iter(): 生成不可变引用的迭代器
    let iter1 = vec.iter(); // &i32
    
    // iter_mut(): 生成可变引用的迭代器  
    let mut vec2 = vec![1, 2, 3];
    let iter2 = vec2.iter_mut(); // &mut i32
    
    // into_iter(): 获取所有权的迭代器
    let iter3 = vec.into_iter(); // i32
}

///! 不同类型的迭代器对比
pub fn different_iterators() {
    let numbers = vec![1, 2, 3, 4, 5];
    
    // 1. iter() - 借用，原数据保持不变
    println!("使用 iter():");
    for num in numbers.iter() {
        print!("{} ", num); // 1 2 3 4 5
    }
    println!("\n原数组: {:?}", numbers); // [1, 2, 3, 4, 5]
    
    // 2. iter_mut() - 可变借用，可以修改原数据
    let mut numbers2 = vec![1, 2, 3];
    for num in numbers2.iter_mut() {
        *num *= 2; // 修改元素
    }
    println!("修改后: {:?}", numbers2); // [2, 4, 6]
    
    // 3. into_iter() - 获取所有权，原数据被消耗
    let numbers3 = vec![1, 2, 3];
    let sum: i32 = numbers3.into_iter().sum();
    println!("求和: {}", sum); // 6
    // println!("{:?}", numbers3); // 错误！numbers3 已被移动
}

///! 常见数据结构的迭代器
pub fn various_collections() {
    // 数组
    let array = [1, 2, 3];
    let _array_iter = array.iter();
    
    // 向量
    let vector = vec![1, 2, 3];
    let _vector_iter = vector.iter();
    
    // 字符串
    let string = String::from("hello");
    let _chars_iter = string.chars();        // 字符迭代器
    let _bytes_iter = string.bytes();        // 字节迭代器
    let _lines_iter = string.lines();        // 行迭代器
    
    // 哈希映射
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert("a", 1);
    map.insert("b", 2);
    let _keys_iter = map.keys();             // 键迭代器
    let _values_iter = map.values();         // 值迭代器
    
    // 范围
    let _range_iter = (1..=5).into_iter();   // 1到5的范围迭代器
}

