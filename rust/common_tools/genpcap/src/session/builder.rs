// 会话建造者

use crate::core::{NetworkConnection, ApplicationFlowType, BuildError, session::TcpSession};
use crate::core::session::TcpMode;
use rand::Rng;

// 会话建造者
#[derive(Debug, Clone)]
pub struct SessionBuilder {
    connection: Option<NetworkConnection>,
    application_flow: Option<ApplicationFlowType>,
    isn: Option<u32>,
}

impl SessionBuilder {
    pub fn new() -> Self {
        Self {
            connection: None,
            application_flow: None,
            isn: None,
        }
    }

    pub fn with_connection(mut self, connection: NetworkConnection) -> Self {
        self.connection = Some(connection);
        self
    }

    pub fn with_application_flow(mut self, flow: ApplicationFlowType) -> Self {
        self.application_flow = Some(flow);
        self
    }

    pub fn with_isn(mut self, isn: u32) -> Self {
        self.isn = Some(isn);
        self
    }

    pub fn build(self) -> Result<TcpSession, BuildError> {
        let connection = self.connection.ok_or(BuildError::MissingConnection)?;
        let _application_flow = self
            .application_flow
            .unwrap_or(ApplicationFlowType::Tcp(TcpMode::Handshake));
        let isn = self.isn.unwrap_or_else(|| {
            let mut rng = rand::thread_rng();
            rng.gen_range(1000000..2000000)
        });

        Ok(TcpSession {
            connection,
            isn,
        })
    }
}

impl Default for SessionBuilder {
    fn default() -> Self {
        Self::new()
    }
}