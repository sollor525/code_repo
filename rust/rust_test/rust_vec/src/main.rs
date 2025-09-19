

fn main() {

    let v = vec![1, 2, 3, 4, 5];
    let mut v1 = vec![1, 2, 3, 4, 5];
    v1.push(6);
    v1.push(7);
    v1.push(8);
    v1.push(9);
    v1.push(10);
    println!("v: {:?}", v);
    println!("v1: {:?}", v1);   


    let v2 = vec![1, 2, 3, 4, 5];
    let third:&i32 = &v2[2];
    println!("The third element is {}", third);


    let third:  Option<&i32> = v.get(2);
    match third {
        Some(third) => println!("The third element is {}", third),
        None => println!("There is no third element"),
    }

    
    let v = vec![1, 2, 3, 4, 5];
    //let does_not_exist = &v[100];
    let does_not_exist: Option<&i32> = v.get(100);
    match does_not_exist {
        Some(does_not_exist) => println!("The does not exist element is {}", does_not_exist),
        None => println!("There is no does not exist element"),
    }


    let mut v: Vec<i32> = vec![1, 2, 3, 4, 5];
    let first: &i32 = &v[0];
    //v.push(6);
    println!("The first element is: {first}");


    let v = vec![100, 32, 57];
    for i in &v {
        println!("{i}");
    }


    let mut v = vec![100, 32, 57];
    for i in &mut v {
        *i += 50;
    }
    for i in &v {
        println!("{i}");
    }

    println!("*****************Pop*****************");
    let mut v = vec![100, 32, 57];
    v.pop();
    for i in &v {
        println!("{i}");
    }


    println!("*****************SpreadsheetCell*****************");
    enum SpreadsheetCell {
        Int(i32),
        Float(f64),
        Text(String),
    }
    let row = vec![
        SpreadsheetCell::Int(3),
        SpreadsheetCell::Text(String::from("blue")),
        SpreadsheetCell::Float(10.12),
    ];
    for cell in row {
        match cell {
            SpreadsheetCell::Int(i) => println!("Int: {i}"),
            SpreadsheetCell::Float(f) => println!("Float: {f}"),
            SpreadsheetCell::Text(t) => println!("Text: {t}"),
        }
    }



}
