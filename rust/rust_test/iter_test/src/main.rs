
mod collect_demo;
mod iter_demo;
mod map_demo;

use collect_demo::*;
use iter_demo::*;
use map_demo::*;


fn main() {

    // iter demo
    println!("\niter demo");
    iter_basics();
    different_iterators();
    various_collections();

    // map demo
    println!("\nmap demo");
    map_basics();
    map_with_closures();
    complex_mapping();

    //collect demo
    println!("\ncollect demo");
    collect_basics();
    type_annotation();
    error_handling_collect();

    println!("\n数据处理流水线");
    data_processing_pipeline();
    performance_tips();
}



/// !数据处理流水线
fn data_processing_pipeline() {
    #[derive(Debug, Clone)]
    struct Product {
        name: String,
        price: f64,
        category: String,
    }
    
    let products = vec![
        Product { name: "Laptop".to_string(), price: 999.99, category: "Electronics".to_string() },
        Product { name: "Book".to_string(), price: 19.99, category: "Education".to_string() },
        Product { name: "Phone".to_string(), price: 699.99, category: "Electronics".to_string() },
        Product { name: "Pen".to_string(), price: 1.99, category: "Office".to_string() },
    ];
    
    // 复杂的数据处理流水线
    let expensive_electronics: Vec<String> = products.iter()
        .filter(|p| p.category == "Electronics")  // 过滤：只保留电子产品
        .filter(|p| p.price > 500.0)             // 过滤：只保留高价商品
        .map(|p| {                              // 转换：创建描述字符串
            let discounted_price = p.price * 0.9; // 9折
            format!("{} - 原价: ${:.2}, 折后: ${:.2}", 
                   p.name, p.price, discounted_price)
        })
        .collect();                             // 收集：生成最终结果
    
    println!("高价电子产品:");
    for item in &expensive_electronics {
        println!("  {}", item);
    }
    
    // 另一个例子：统计信息
    use std::collections::HashMap;
    
    let category_stats: HashMap<String, (usize, f64)> = products.iter()
        .map(|p| (p.category.clone(), p))
        .fold(HashMap::new(), |mut acc, (category, product)| {
            let entry = acc.entry(category).or_insert((0, 0.0));
            entry.0 += 1;  // 计数
            entry.1 += product.price; // 总价
            acc
        });
    
    println!("\n分类统计:");
    for (category, (count, total)) in category_stats {
        println!("  {}: {}个商品, 总价: ${:.2}", category, count, total);
    }
}


/// !性能优化技巧
fn performance_tips() {
    let large_vector: Vec<i32> = (1..=1_000_000).collect();
    
    // 技巧1: 预分配容量
    let mut result = Vec::with_capacity(large_vector.len());
    for item in large_vector.iter().map(|x| x * 2) {
        result.push(item);
    }
    
    // 技巧2: 使用 collect() 通常比手动 push 更快
    let optimized: Vec<i32> = large_vector.iter()
        .map(|x| x * 2)
        .collect(); // 编译器会优化
    
    // 技巧3: 对于简单操作，考虑使用数组推导
    let simple_doubled: Vec<i32> = large_vector.iter()
        .map(|x| x * 2)
        .collect();
}