use rust_trait4::{Summary, NewsArticle, SocialPost, returns_summarizable};


fn main() {

    let news_article = NewsArticle {
        headline: String::from("Penguins win the Stanley Cup Championship!"),
        location: String::from("Pittsburgh, PA, USA"),
        author: String::from("Iceburgh"),
        content: String::from("The Pittsburgh Penguins once again are the best
        hockey team in the NHL."),
    };

    let social_post = SocialPost {
        username: String::from("horse_ebooks"),
        content: String::from("of course, as you probably already know, people"),
        reply: false,
        repost: false,
    };
    println!("New article available! {}", news_article.summarize());
    println!("Social post available! {}", social_post.summarize());


    let returns_summarizable = returns_summarizable();
    println!("Returns summarizable: {}", returns_summarizable.summarize());


}
