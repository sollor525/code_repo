//! 工作线程池
//!
//! 提供并行处理数据包的工作线程池

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::thread::JoinHandle;

use crate::types::PacketInfo;

/// 工作任务
pub enum WorkItem {
    /// 处理数据包
    Packet(PacketInfo),
    /// 停止工作线程
    Shutdown,
}

/// 工作线程池
pub struct WorkerPool {
    workers: Vec<JoinHandle<()>>,
    sender: Sender<WorkItem>,
}

impl WorkerPool {
    /// 创建新的工作线程池
    ///
    /// # 参数
    /// * `num_workers` - 工作线程数量
    /// * `stream_manager` - 线程安全的流管理器
    ///
    /// # 返回值
    /// 返回工作线程池实例
    pub fn new(
        num_workers: usize,
        stream_manager: std::sync::Arc<super::ThreadSafeStreamManager>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel::<WorkItem>();
        let receiver = std::sync::Arc::new(std::sync::Mutex::new(receiver));

        let mut workers = Vec::with_capacity(num_workers);

        for _worker_id in 0..num_workers {
            let receiver = std::sync::Arc::clone(&receiver);
            let stream_manager = std::sync::Arc::clone(&stream_manager);

            let worker = thread::Builder::new()
                .name("pcap-worker".to_string())
                .spawn(move || {
                    Self::worker_loop(receiver, stream_manager);
                })
                .expect("Failed to spawn worker thread");

            workers.push(worker);
        }

        Self { workers, sender }
    }

    /// 工作线程主循环
    fn worker_loop(
        receiver: std::sync::Arc<std::sync::Mutex<Receiver<WorkItem>>>,
        stream_manager: std::sync::Arc<super::ThreadSafeStreamManager>,
    ) {
        loop {
            let work_item = {
                let rx = receiver.lock().unwrap();
                rx.recv().unwrap()
            };

            match work_item {
                WorkItem::Packet(packet_info) => {
                    // 处理数据包
                    stream_manager.process_packet(&packet_info);
                }
                WorkItem::Shutdown => {
                    // 收到停止信号，退出工作循环
                    break;
                }
            }
        }
    }

    /// 提交数据包处理任务
    pub fn submit_packet(&self, packet: PacketInfo) -> Result<(), mpsc::SendError<WorkItem>> {
        self.sender.send(WorkItem::Packet(packet))
    }

    /// 停止所有工作线程
    pub fn shutdown(mut self) {
        // 发送停止信号给所有工作线程
        for _ in 0..self.workers.len() {
            let _ = self.sender.send(WorkItem::Shutdown);
        }

        // 等待所有工作线程结束
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        // 发送停止信号
        for _ in 0..self.workers.len() {
            let _ = self.sender.send(WorkItem::Shutdown);
        }
    }
}