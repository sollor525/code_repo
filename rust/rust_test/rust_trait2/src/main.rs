use rust_trait2::{Summary, SocialPost, NewsArticle};

fn main() {
    let post = SocialPost {
        username: String::from("John Doe"),
        content: String::from("Hello, world!"),
        reply: false,
        repost: false,
    };

    println!("{}", post.summarize());
    println!("{}", post.summarize_author());

    let article = NewsArticle {
        headline: String::from("Hello, world!"),
        location: String::from("New York"),
        author: String::from("John Doe"),
        content: String::from("Hello, world!"),
    };

    println!("{}", article.summarize());    
    println!("{}", article.summarize_author());

}
