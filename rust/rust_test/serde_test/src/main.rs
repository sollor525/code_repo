
use serde::{Serialize, Deserialize};
use serde_json;
use serde_json::{Value, json};
use std::fs::File;


#[derive(Serialize, Deserialize, Debug)]
struct User {
    id: u32,
    name: String,
    active: bool,
}

fn main() {
    let user = User{id:1, name:"Alice".into(), active:true};

    // 转为紧凑 JSON
    let json_str = serde_json::to_string(&user).unwrap();
    println!("json_str: \n{}", json_str);


    // 转为漂亮的 JSON
    let pretty_json = serde_json::to_string_pretty(&user).unwrap();
    println!("pretty_json: \n{}", pretty_json);


    //JSON 反序列化到结构体
    let json_data = r#"{"id":2,"name":"Bob","active":false}"#;
    let user: User = serde_json::from_str(json_data).unwrap();
    println!("{:?}", user);


    //动态 JSON (Value) 访问。
    //适合处理未知结构 JSON、动态字段或可选字段。
    //运行时才会发现类型错误，频繁访问深层字段需要 unwrap /Option处理。
    let data: Value = json!({
        "user": { "name": "Alice", "age": 25 },
        "tags": ["rust", "serde"]
    });
    let user_name = data["user"]["name"].as_str().unwrap_or("unknown");
    let first_tag = data["tags"][0].as_str().unwrap_or_default();
    println!("Name: {}, First tag: {}", user_name, first_tag);


    //JSON 构建 (json!() 宏)
    //简洁，支持动态构造，可嵌套对象/数组，适用于快速生成测试数据、API payload、日志结构。
    let dynamic_json = json!({
        "id": 1001,
        "name": "Charlie",
        "roles": ["admin", "user"]
    });
    println!("{}", dynamic_json.to_string());


    //文件读写
    let output = File::create("output.json").unwrap();
    let user: User = User{id:1, name:"Alice".into(), active:true};
    // 直接将用户对象写入文件，而不是先转换为字符串
    serde_json::to_writer_pretty(output, &user).unwrap();

    let file = File::open("output.json").unwrap();
    let ret: Value = serde_json::from_reader(file).unwrap();
    // 从 Value 类型转换为 User 结构体
    let loaded_user: User = serde_json::from_value(ret).unwrap();
    println!("Loaded user from file: {:?}", loaded_user);


}
