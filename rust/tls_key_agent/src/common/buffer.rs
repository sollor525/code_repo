use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use crate::common::error::{TlsKeyAgentError, Result};

#[derive(Debug)]
pub struct BufferPool {
    buffers: Arc<Mutex<VecDeque<Vec<u8>>>>,
    buffer_size: usize,
    max_buffers: usize,
}

impl BufferPool {
    pub fn new(buffer_size: usize, max_buffers: usize) -> Self {
        Self {
            buffers: Arc::new(Mutex::new(VecDeque::with_capacity(max_buffers))),
            buffer_size,
            max_buffers,
        }
    }

    pub fn acquire(&self) -> Result<Vec<u8>> {
        let mut buffers = self.buffers.lock();

        if let Some(buffer) = buffers.pop_front() {
            Ok(buffer)
        } else {
            Ok(vec![0u8; self.buffer_size])
        }
    }

    pub fn release(&self, mut buffer: Vec<u8>) {
        if buffer.capacity() != self.buffer_size {
            return; // 不匹配大小的buffer直接丢弃
        }

        buffer.clear();

        let mut buffers = self.buffers.lock();
        if buffers.len() < self.max_buffers {
            buffers.push_back(buffer);
        }
    }

    pub fn available_count(&self) -> usize {
        self.buffers.lock().len()
    }

    pub fn stats(&self) -> PoolStats {
        let buffers = self.buffers.lock();
        PoolStats {
            available_buffers: buffers.len(),
            max_buffers: self.max_buffers,
            buffer_size: self.buffer_size,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub available_buffers: usize,
    pub max_buffers: usize,
    pub buffer_size: usize,
}

pub struct ByteBuffer {
    data: Vec<u8>,
    len: usize,
    pool: Arc<BufferPool>,
}

impl ByteBuffer {
    pub fn new(pool: Arc<BufferPool>) -> Result<Self> {
        let data = pool.acquire()?;
        Ok(Self {
            data,
            len: 0,
            pool,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) -> Result<()> {
        if self.len + data.len() > self.data.len() {
            return Err(TlsKeyAgentError::Memory(
                "Buffer overflow".to_string()
            ));
        }

        self.data[self.len..self.len + data.len()].copy_from_slice(data);
        self.len += data.len();
        Ok(())
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl Drop for ByteBuffer {
    fn drop(&mut self) {
        self.pool.release(std::mem::take(&mut self.data));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(1024, 10);

        assert_eq!(pool.available_count(), 0);

        let buffer = pool.acquire().unwrap();
        assert_eq!(buffer.len(), 1024);

        pool.release(buffer);
        assert_eq!(pool.available_count(), 1);
    }

    #[test]
    fn test_byte_buffer() {
        let pool = Arc::new(BufferPool::new(1024, 10));
        let mut buffer = ByteBuffer::new(pool.clone()).unwrap();

        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());

        let data = b"Hello, World!";
        buffer.extend_from_slice(data).unwrap();

        assert_eq!(buffer.len(), data.len());
        assert_eq!(buffer.as_slice(), data);

        buffer.clear();
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());
    }
}