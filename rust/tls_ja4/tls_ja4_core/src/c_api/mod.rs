//! C FFI接口模块
//! 
//! 提供C兼容的API接口

pub mod types;
pub mod functions;
pub mod errors;

pub use types::*;
pub use functions::*;
pub use errors::*;
