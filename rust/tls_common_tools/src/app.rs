use iced::{Application, Command, Element, Theme, Sandbox, Settings, Length};
use iced::widget::{button, column, container, row, text, scrollable, Column, Row, Container};
use rfd::FileDialog;
use std::sync::{Arc, Mutex};

use crate::network_utils::NetworkUtils;
use crate::packet_analyzer::PacketAnalyzer;
use crate::regex_matcher::RegexMatcher;

#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(Tab),
    NetworkUtilsMessage(crate::network_utils::Message),
    PacketAnalyzerMessage(crate::packet_analyzer::Message),
    RegexMatcherMessage(crate::regex_matcher::Message),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    NetworkUtils,
    PacketAnalyzer,
    RegexMatcher,
}

pub struct TlsToolsApp {
    current_tab: Tab,
    network_utils: NetworkUtils,
    packet_analyzer: PacketAnalyzer,
    regex_matcher: RegexMatcher,
}

impl Application for TlsToolsApp {
    type Message = Message;
    type Theme = Theme;
    type Executor = iced::executor::Default;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (
            Self {
                current_tab: Tab::NetworkUtils,
                network_utils: NetworkUtils::new(),
                packet_analyzer: PacketAnalyzer::new(),
                regex_matcher: RegexMatcher::new(),
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        String::from("TLS通用工具集")
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::TabSelected(tab) => {
                self.current_tab = tab;
                Command::none()
            },
            Message::NetworkUtilsMessage(msg) => {
                self.network_utils.update(msg);
                Command::none()
            },
            Message::PacketAnalyzerMessage(msg) => {
                self.packet_analyzer.update(msg);
                Command::none()
            },
            Message::RegexMatcherMessage(msg) => {
                self.regex_matcher.update(msg);
                Command::none()
            },
        }
    }

    fn view(&self) -> Element<Message> {
        let tab_buttons = row![
            button(text("网络序转换")).on_press(Message::TabSelected(Tab::NetworkUtils))
                .style(if self.current_tab == Tab::NetworkUtils { iced::theme::Button::Primary } else { iced::theme::Button::Secondary }),
            button(text("报文解析")).on_press(Message::TabSelected(Tab::PacketAnalyzer))
                .style(if self.current_tab == Tab::PacketAnalyzer { iced::theme::Button::Primary } else { iced::theme::Button::Secondary }),
            button(text("正则匹配")).on_press(Message::TabSelected(Tab::RegexMatcher))
                .style(if self.current_tab == Tab::RegexMatcher { iced::theme::Button::Primary } else { iced::theme::Button::Secondary }),
        ].spacing(10).padding(10);

        let content = match self.current_tab {
            Tab::NetworkUtils => self.network_utils.view().map(Message::NetworkUtilsMessage),
            Tab::PacketAnalyzer => self.packet_analyzer.view().map(Message::PacketAnalyzerMessage),
            Tab::RegexMatcher => self.regex_matcher.view().map(Message::RegexMatcherMessage),
        };

        let content_container = container(
            scrollable(
                column![content].spacing(20).padding(20)
            ).height(Length::Fill)
        );

        container(
            column![
                tab_buttons,
                content_container
            ]
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(10)
        .into()
    }
}