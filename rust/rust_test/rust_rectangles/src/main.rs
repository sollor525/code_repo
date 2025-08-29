


#[derive(Debug)]
struct Rectangle {
    width: u32,
    height: u32,
}

impl Rectangle {
    fn area(&self) -> u32 {
        self.width * self.height
    }
}

impl Rectangle {
    fn width(&self) -> bool {
        self.width > 0
    }
}


fn main() {
    let scale = 2;
    let rect1: Rectangle = Rectangle {
         width: dbg!(30 * scale),
         height: 50,};

    println!("The area of the rectangle is {} square pixels.", area(&rect1));
    println!("Rect1 is width:{} and height:{}", rect1.width, rect1.height);
    println!("rect1 is {:?}", rect1);
    println!("rect1 is {:#?}", rect1);
    dbg!(&rect1);
    dbg!(scale);
    
    println!("----------------------------------------------------------------");
    let rect1_area = rect1.area();
    println!("The area of the rectangle is {} square pixels.", rect1_area);
    println!("rect1 is a square {}", rect1.width());
    println!("rect1 is {:?}", rect1);
    
    if rect1.width() {
        println!("The rectangle has a nonzero width; it is {}", rect1.width);
    }
    
}


fn area(dimensions: &Rectangle) -> u32 {
    dimensions.width * dimensions.height
}

