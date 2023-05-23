use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Directory {
    pub entries: Vec<DirEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DirEntry {
    File {
        filename: String,
        hash: String,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DirectoryUploadResponse {
    pub merkle_root: String,
}