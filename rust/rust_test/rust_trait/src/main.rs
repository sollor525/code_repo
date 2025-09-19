


fn largest<T: PartialOrd>(list: &[T]) -> &T {
    let mut largest = &list[0];

    for item in list {
        if item > largest {
            largest = item;
        }
    }

    largest
}


struct Point<T> {
    x: T,
    y: T,
}

struct Point2<T, U> {
    x: T,
    y: U,
}


#[derive(Debug)]
enum MyResult<T, E> {
    Ok(T),
    Err(E),
}


impl<T: std::ops::Add<Output = T> + Copy + From<i32>> Point<T> {
    fn x(&self) -> &T {
        &self.x
    }

    fn y_plus_one(&self) -> T {
        self.y + T::from(1)
    }
}

impl Point<f32> {
    fn distance_from_origin(&self) -> f32 {
        (self.x.powi(2) + self.y.powi(2)).sqrt()
    }
}


struct Point3<X1, Y1> {
    x: X1,
    y: Y1,
}

impl<X1, Y1> Point3<X1, Y1> {
    fn mixup<X2, Y2>(self, other: Point3<X2, Y2>) -> Point3<X1, Y2> {
        Point3 {
            x: self.x,
            y: other.y,
        }
    }
}

fn main() {
    println!("泛型结构体：");
    let number_list = vec![34, 50, 25, 100, 65];
    let result = largest(&number_list);
    println!("The largest number is {}", result);

    let char_list = vec!['y', 'm', 'a', 'q'];
    let result = largest(&char_list);
    println!("The largest char is {}", result);

    println!("\n泛型结构体：");
    let integer_point = Point { x: 5, y: 10 };
    let float_point = Point { x: 1.0, y: 4.0 };
    println!("integer_point.x = {}, integer_point.y = {}", integer_point.x, integer_point.y);
    println!("float_point.x = {}, float_point.y = {}", float_point.x, float_point.y);

    println!("\n不同类型的泛型结构体：");
    let both_integer = Point2 { x: 5, y: 10 };
    let both_float = Point2 { x: 1.0, y: 4.0 };
    let integer_and_float = Point2 { x: 5, y: 4.0 };
    println!("both_integer.x = {}, both_integer.y = {}", both_integer.x, both_integer.y);
    println!("both_float.x = {:.1}, both_float.y = {:.1}", both_float.x, both_float.y);
    println!("integer_and_float.x = {:.1}, integer_and_float.y = {:.1}", integer_and_float.x, integer_and_float.y);   


    println!("\n泛型枚举：");
    let ok = MyResult::<i32, &str>::Ok(10);
    let err = MyResult::<i32, &str>::Err("error");
    println!("ok = {:?}", ok);
    println!("err = {:?}", err);


    println!("\n方法定义中的泛型：");
    let p = Point { x: 5, y: 10 };
    println!("p.x = {}", p.x());
    println!("p.y_plus_one = {}", p.y_plus_one());

    let p2 = Point { x: 1.0, y: 4.0 };
    println!("p2.distance_from_origin = {}", p2.distance_from_origin());


    let p1 = Point3 { x: 5, y: 10.4 };
    let p2 = Point3 { x: "Hello", y: 'c' };
    let p3 = p1.mixup(p2);
    println!("p3.x = {}, p3.y = {}", p3.x, p3.y);
}
