use rust_trait3::notify;
use rust_trait3::NewsArticle;
use rust_trait3::SocialPost;


fn main() {

    println!("trait 作为参数");
    let article = NewsArticle {
        headline: String::from("Penguins win the Stanley Cup Championship!"),
        location: String::from("Pittsburgh, PA, USA"),
        author: String::from("Iceburgh"),
        content: String::from("The Pittsburgh Penguins once again are the best hockey team in the NHL."),
    };
    let post = SocialPost {
        username: String::from("horse_ebooks"),
        content: String::from("of course, as you probably already know, people"),
        reply: false,
        repost: false,
    };
    notify(&article);
    notify(&post);


    
}
