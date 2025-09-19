use rust_trait5::Pair;

fn main() {
    let pair = Pair::new(1, 2);
    pair.cmp_display();


    println!("{}", pair.to_string());

}
