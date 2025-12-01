
use std::collections::{HashSet, HashMap};

/// ! 3. collect() - 收集结果
/// ! 基础收集
pub fn collect_basics() {
    let numbers = vec![1, 2, 3, 4, 5];
    
    // 收集为 Vec
    let doubled_vec: Vec<i32> = numbers.iter()
        .map(|x| x * 2)
        .collect();
    
    // 收集为其他集合类型
    use std::collections::{HashSet, HashMap};
    
    // 收集为 HashSet (去重)
    let unique: HashSet<i32> = vec![1, 2, 2, 3, 3, 3].into_iter().collect();
    println!("去重后: {:?}", unique); // {1, 2, 3}
    
    // 收集为 String
    let chars = vec!['h', 'e', 'l', 'l', 'o'];
    let word: String = chars.into_iter().collect();
    println!("字符串: {}", word); // hello
}

///!类型推断和显式注解
pub fn type_annotation() {
    let numbers = vec![1, 2, 3, 4, 5];
    
    // 情况1: 编译器可以推断类型
    let doubled: Vec<_> = numbers.iter().map(|x| x * 2).collect();
    // 等价于: let doubled: Vec<i32> = ...
    
    // 情况2: 需要显式类型注解
    let string_vec: Vec<String> = numbers.iter()
        .map(|x| x.to_string())
        .collect();
    
    // 情况3: turbofish 语法
    let hashset: HashSet<i32> = numbers.iter()
        .map(|x| x * 2)
        .collect();
    
    // 情况4: 复杂类型的收集
    let result_map: HashMap<String, i32> = numbers.iter()
        .map(|x| (x.to_string(), x * 10))
        .collect();
    println!("映射: {:?}", result_map);
}


///! 错误处理收集
pub fn error_handling_collect() {
    let string_numbers = vec!["1", "2", "3", "four", "5"];
    
    // 方式1: 收集 Result, 遇到第一个错误就停止
    let result: Result<Vec<i32>, _> = string_numbers.iter()
        .map(|s| s.parse::<i32>())
        .collect();
    
    match result {
        Ok(numbers) => println!("解析成功: {:?}", numbers),
        Err(e) => println!("解析失败: {}", e),
    }
    
    // 方式2: 使用 filter_map 过滤掉错误
    let successful: Vec<i32> = string_numbers.iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    println!("成功解析的: {:?}", successful); // [1, 2, 3, 5]
    
    // 方式3: 分开处理成功和失败
    let (success, errors): (Vec<_>, Vec<_>) = string_numbers.iter()
        .map(|s| (s, s.parse::<i32>()))
        .partition(|(_, result)| result.is_ok());
    
    let success_map: HashMap<&str, i32> = success.into_iter()
        .map(|(s, res)| (*s, res.unwrap()))
        .collect();
    
    println!("成功: {:?}", success_map);
    println!("错误数量: {}", errors.len());
}