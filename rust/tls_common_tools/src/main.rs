mod app;
mod network_utils;
mod packet_analyzer;
mod regex_matcher;

use iced::{Application, Settings};
use log::info;

fn main() -> iced::Result {
    env_logger::init();
    info!("启动TLS通用工具集");
    
    app::TlsToolsApp::run(Settings {
        window: iced::window::Settings {
            size: (800, 600),
            ..Default::default()
        },
        ..Default::default()
    })
}