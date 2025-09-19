use std::fs::File;
use std::io::{self, Read};
use std::io::ErrorKind;
use std::fs;



fn main() {

    let greeting_file_result = File::open("hello.txt");
    println!("{:?}", greeting_file_result);



    println!("\n 根据返回值处理result");
    let greeting_file_result = File::open("hello.txt");
    let greeting_file = match greeting_file_result {
        Ok(file) => file,
        Err(error) => match error.kind() {
            ErrorKind::NotFound => match File::create("hello.txt") {
                Ok(fc) => fc,
                Err(e) => panic!("Problem creating the file: {e:?}"),
            },
            _ => {
                panic!("Problem opening the file: {error:?}");
            }
        },
    };
    println!("{:?}", greeting_file);
    

    println!("\n 使用unwrap_or_else处理result");
    let greeting_file = File::open("hello.txt").unwrap_or_else(|error| {
        if error.kind() == ErrorKind::NotFound {
            File::create("hello.txt").unwrap_or_else(|error| {
                panic!("Problem creating the file: {error:?}");
            })
        } else {
            panic!("Problem opening the file: {error:?}");
        }
    });
    println!("{:?}", greeting_file);   


    println!("\n 使用unwrap处理result");
    let greeting_file = File::open("hello.txt").unwrap();
    println!("{:?}", greeting_file);


    println!("\n 使用expect处理result");
    let greeting_file = File::open("hello.txt")
                        .expect("hello.txt should be included in this project");
    println!("{:?}", greeting_file);



    println!("\n 传播错误");
    fn read_username_from_file() -> Result<String, io::Error> {
        let username_file_result = File::open("hello.txt");
    
        let mut username_file = match username_file_result {
            Ok(file) => file,
            Err(e) => return Err(e),
        };
    
        let mut username = String::new();

        match username_file.read_to_string(&mut username) {
            Ok(_) => Ok(username),
            Err(e) => Err(e),
        }
    }
    let result = read_username_from_file();
    println!("{:?}", result);

    let result = read_username_from_file().unwrap();
    println!("{:?}", result);
    let result = read_username_from_file().expect("Failed to read username from file");
    println!("{:?}", result);
    

    println!("\n 使用?传播错误");
    fn read_username_from_file1() -> Result<String, io::Error> {
        let mut username_file = File::open("hello.txt")?;
        let mut username = String::new();
        username_file.read_to_string(&mut username)?;
        Ok(username)
    }
    let result = read_username_from_file1();
    println!("{:?}", result);

    fn read_username_from_file3() -> Result<String, io::Error> {
        let mut username = String::new();
        File::open("hello.txt")?.read_to_string(&mut username)?;
    
        Ok(username)
    }
    let result = read_username_from_file3();
    println!("{:?}", result);

    fn read_username_from_file4() -> Result<String, io::Error> {
        fs::read_to_string("hello.txt")
    }
    let result = read_username_from_file4();
    println!("{:?}", result);


    println!("\n ?用于Option");
    fn last_char_of_first_line(text: &str) -> Option<char> {
        text.lines().next()?.chars().last()
    }

    assert_eq!(
        last_char_of_first_line("Hello, world\nHow are you today?"),
        Some('d')
    );
    assert_eq!(last_char_of_first_line(""), None);
    assert_eq!(last_char_of_first_line("\nhi"), None);
}

