//! JA4指纹数据库匹配模块
//!
//! 本模块提供JA4指纹数据库的预加载和匹配功能，用于快速识别已知的应用程序或设备。

use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};

/// JA4数据库条目结构
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ja4DatabaseEntry {
    /// 应用程序名称（可选）
    pub application: Option<String>,
    /// 设备类型（可选）
    pub device: Option<String>,
    /// JA4指纹
    pub ja4_fingerprint: String,
}

/// JA4指纹数据库
#[derive(Debug, Clone)]
pub struct Ja4Database {
    /// 预加载的JA4指纹集合
    fingerprints: HashSet<String>,
    /// 数据库条目（用于详细信息查询）
    entries: Vec<Ja4DatabaseEntry>,
}

impl Ja4Database {
    /// 创建空的JA4数据库
    pub fn new() -> Self {
        Self {
            fingerprints: HashSet::new(),
            entries: Vec::new(),
        }
    }

    /// 从JSON文件加载JA4数据库
    pub fn load_from_file<P: AsRef<std::path::Path>>(file_path: P) -> Result<Self> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        let entries: Vec<Ja4DatabaseEntry> = serde_json::from_reader(reader)
            .map_err(|e| anyhow!("Failed to parse JA4 database JSON: {}", e))?;

        let mut fingerprints = HashSet::with_capacity(entries.len());

        for entry in &entries {
            fingerprints.insert(entry.ja4_fingerprint.clone());
        }

        Ok(Self {
            fingerprints,
            entries,
        })
    }

    /// 获取数据库中的指纹数量
    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    /// 检查数据库是否为空
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    /// 检查给定的JA4指纹是否在数据库中
    pub fn contains(&self, ja4_fingerprint: &str) -> bool {
        self.fingerprints.contains(ja4_fingerprint)
    }

    /// 查找给定JA4指纹的详细信息
    pub fn find_entry(&self, ja4_fingerprint: &str) -> Option<&Ja4DatabaseEntry> {
        self.entries.iter().find(|entry| entry.ja4_fingerprint == ja4_fingerprint)
    }

    /// 查找给定JA4指纹的所有匹配条目
    pub fn find_all_matches(&self, ja4_fingerprint: &str) -> Vec<&Ja4DatabaseEntry> {
        self.entries.iter()
            .filter(|entry| entry.ja4_fingerprint == ja4_fingerprint)
            .collect()
    }

    /// 获取所有指纹的不可变引用
    pub fn fingerprints(&self) -> &HashSet<String> {
        &self.fingerprints
    }

    /// 获取所有条目的不可变引用
    pub fn entries(&self) -> &[Ja4DatabaseEntry] {
        &self.entries
    }
}

impl Default for Ja4Database {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ja4_database_basic() {
        let db = Ja4Database::new();
        assert_eq!(db.len(), 0);
        assert!(db.is_empty());
        assert!(!db.contains("test_fingerprint"));
    }

    #[test]
    fn test_ja4_database_load() {
        // 这个测试需要实际的JSON文件，在实际环境中运行
        // let db = Ja4Database::load_from_file("config/ja4_db.json").unwrap();
        // assert!(!db.is_empty());
    }
}