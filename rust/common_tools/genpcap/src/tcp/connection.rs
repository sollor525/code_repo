// TCP连接状态管理

// TCP连接状态跟踪结构体
#[derive(Debug, Clone)]
pub struct TcpConnection {
    pub client_seq: u32,
    pub server_seq: u32,
    pub client_ack: u32,
    pub server_ack: u32,
}

impl TcpConnection {
    pub fn new(isn: u32) -> Self {
        Self {
            client_seq: isn,
            server_seq: isn,
            client_ack: isn,
            server_ack: isn,
        }
    }

    // 更新序列号（发送数据后）
    pub fn update_seq(&mut self, is_client: bool, data_len: u32) {
        if is_client {
            self.client_seq += data_len;
        } else {
            self.server_seq += data_len;
        }
    }

    // 更新确认号（接收数据后）
    pub fn update_ack(&mut self, is_client: bool, data_len: u32) {
        if is_client {
            self.client_ack += data_len;
        } else {
            self.server_ack += data_len;
        }
    }

    // 获取当前序列号和确认号
    pub fn get_seq_ack(&self, is_client: bool) -> (u32, u32) {
        if is_client {
            (self.client_seq, self.client_ack)
        } else {
            (self.server_seq, self.server_ack)
        }
    }
}