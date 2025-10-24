//! YAML模板系统
//!
//! 支持通过YAML文件定义复杂的网络流量场景

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use indexmap::IndexMap;
use crate::core::{NetworkConnection, ApplicationFlow, ApplicationFlowType};
use crate::session::TcpSessionConfig;
use crate::{TcpSession, HttpRequest, HttpResponse, HttpMethod, HttpVersion, HttpStatusCode};
use pnet::packet::tcp::TcpFlags;
use std::net::IpAddr;

pub mod parser;
pub mod engine_simple;

pub use parser::{
    YamlTemplate, TemplateConfig, TemplateError, TemplateErrorKind,
    TemplateMetadata, NetworkConfig, SessionTemplate, AddressConfig,
    SessionType, ApplicationConfig, HttpRequestConfig, HttpResponseConfig,
    DefaultSettings
};
pub use engine_simple::SimpleTemplateEngine as TemplateEngine;