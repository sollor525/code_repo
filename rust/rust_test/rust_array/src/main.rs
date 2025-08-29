use std::io;

fn main() {
    let a:[i32; 5] = [1,2,3,4,5];
    
    println!("please enter an array index");

    let mut index = String::new();

    io::stdin()
        .read_line(&mut index)
        .expect("Failed to read line");

    let index:usize = index.trim().parse().expect("index is not a number");

    let element = a[index];

    println!("the value of the element at index {} is: {}", index, element);

    let y = {
        let x = 3;
        x + 1
    };

    println!("The value of y is: {y}");
    
}
