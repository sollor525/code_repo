use std::rc::Rc;


#[derive(Debug)]
#[allow(dead_code)]
enum List {
    Cons(i32, Rc<List>),
    Nil,
}

use crate::List::{Cons, Nil};


fn main() {
    let a_1= Rc::new(Cons(10, Rc::new(Nil)));
    println!("count after creating a_1. a_1 = {}", Rc::strong_count(&a_1));
    let a = Rc::new(Cons(5, a_1));
    println!("count after creating a. = {}", Rc::strong_count(&a));

    let b = Cons(3, Rc::clone(&a));
    println!("count after creating b. a = {}", Rc::strong_count(&a));
    {
        let c = Cons(4, Rc::clone(&a));
        println!("count after creating b and c. a = {}", Rc::strong_count(&a));
        println!("c = {:?}", c);
        println!("b = {:?}", b);
    }
    println!("count after scope . a = {}", Rc::strong_count(&a));
}