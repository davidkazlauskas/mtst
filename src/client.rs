use std::{error::Error, io::ErrorKind, path::Path};

use clap::{command, Parser, Subcommand, arg};
use common::data::{Directory, DirectoryUploadResponse};
use common::merkle_tree::{copy_merkle_root, MerkleProof};
use tokio::io::AsyncReadExt;

/// Program to upload and download files from server with merkle root verification
#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "mtst")]
#[command(about = "Merkle tree storage client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Merkle tree storage server url
    #[arg(long, short, default_value = "http://localhost:8080")]
    server_url: String,
    /// Upload/download parallelism
    #[arg(long, short, default_value = "10")]
    parallelism: usize,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Upload files and print merkle root to the output
    Upload {
        /// The directory to upload to remote
        #[arg(short, long, default_value = ".")]
        path: String,
    },
    /// Download files by merkle root
    Download {
        /// Directory merkle root to download
        root: String,
        /// Path to download to or current directory if not specified
        #[arg(short, long, default_value = ".")]
        path: String,

        /// Overwrite different detected files from the storage server
        #[arg(short, long, default_value = "false")]
        overwrite: bool,
    },
    /// Verify files stored at path with merkle root
    Verify {
        /// Merkle root to verify against
        root: String,
        /// Directory to verify in the local filesystem
        #[arg(short, long, default_value = ".")]
        path: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Cli::parse();
    match &args.command {
        Commands::Upload { path } => {
            upload_files_to_server(&args, path).await?;
        }
        Commands::Download { root, path, overwrite } => {
            download_files_from_server(&args, *overwrite, path, root).await?;
        }
        Commands::Verify {
            root,
            path,
        } => {
            verify_files_from_server(&args, path, root).await?;
        }
    }
    Ok(())
}

#[derive(Debug)]
pub enum ClientErrors {
    FailedBlobUpload { file: String, error: String },
    EmptyDirectory,
    ErrorDuringDirectoryUpload { error: String },
    DirectoryNotFound,
    FailedListingDirectory { error: String },
    FailedBlobDownload { error: String },
    CantGetMerkleRoots { error: String },
}

impl std::error::Error for ClientErrors {}

impl std::fmt::Display for ClientErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

async fn verify_files_from_server(
    args: &Cli,
    path: &str,
    merkle_root: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let verification_start_all = std::time::Instant::now();
    let server_url = &args.server_url;
    let root_bytes_vec = hex::decode(merkle_root)?;
    let mut root_bytes: [u8; 32] = [0; 32];
    copy_merkle_root(&root_bytes_vec, &mut root_bytes);

    let res = reqwest::Client::default()
        .get(format!(
            "{server_url}/api/v1/directory/{merkle_root}"
        ))
        .send()
        .await?;

    if res.status().as_u16() == 404 {
        return Err(Box::new(ClientErrors::DirectoryNotFound));
    }

    if !res.status().is_success() {
        return Err(Box::new(ClientErrors::FailedListingDirectory {
            error: String::from_utf8(res.bytes().await?.to_vec())?,
        }));
    }

    let body = res.bytes().await?.to_vec();
    let res = serde_json::from_slice::<Directory>(&body)?;

    let roots = reqwest::Client::default()
        .post(format!(
            "{server_url}/api/v1/directory/{merkle_root}/proofs"
        ))
        .json(&res.entries)
        .send()
        .await?;

    if !roots.status().is_success() {
        return Err(Box::new(ClientErrors::CantGetMerkleRoots {
            error: String::from_utf8(roots.bytes().await?.to_vec())?,
        }));
    }

    let body = roots.bytes().await?.to_vec();
    let proofs: Vec<Option<MerkleProof>> = serde_json::from_slice(body.as_slice())?;

    for (idx, dir) in res.entries.iter().enumerate() {
        match dir {
            common::data::DirEntry::File { filename, hash } => {
                let path = path.to_string();
                let filename = filename.clone();
                let hash = hash.clone();
                let p = Path::new(&path).join(filename.clone());
                match tokio::fs::read(&p).await {
                    Ok(fcontents) => {
                        let real_hash_u8 = hmac_sha256::Hash::hash(&fcontents);
                        let real_hash = hex::encode(real_hash_u8);
                        let entry_hash = hmac_sha256::Hash::hash(&serde_json::to_vec(&dir)?);
                        if let Some(Some(proof)) = proofs.get(idx) {
                            match proof.verify(&root_bytes, &entry_hash) {
                                Ok(()) => {
                                    println!("Merkle proof valid for file {}", filename);
                                }
                                Err(e) => {
                                    println!(
                                        "Error found when verifying merkle root for file {}: {:?}",
                                        filename, e
                                    );
                                }
                            }
                        } else {
                            println!("Merkle proof for file {filename} not found from the server.");
                        }

                        if real_hash != *hash {
                            println!("File {filename} hashes mismatch, local: {real_hash}, remote: {hash}");
                        }
                    }
                    Err(e) => {
                        if e.kind() == ErrorKind::NotFound {
                            // file doesn't exist, download
                            println!("File {filename} not found");
                        } else {
                            let err: Box<dyn Error + Send + Sync> = Box::new(e);
                            return Err(err);
                        }
                    }
                }
            }
        }
    }

    println!("Verification done in {:.3}s", verification_start_all.elapsed().as_secs_f64());

    Ok(())
}

async fn download_files_from_server(
    args: &Cli,
    overwrite: bool,
    path: &str,
    merkle_root: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let download_start_all = std::time::Instant::now();

    let server_url = args.server_url.clone();
    let res = reqwest::Client::default()
        .get(format!(
            "{server_url}/api/v1/directory/{merkle_root}"
        ))
        .send()
        .await?;

    if res.status().as_u16() == 404 {
        return Err(Box::new(ClientErrors::DirectoryNotFound));
    }

    if !res.status().is_success() {
        return Err(Box::new(ClientErrors::FailedListingDirectory {
            error: String::from_utf8(res.bytes().await?.to_vec())?,
        }));
    }

    let body = res.bytes().await?.to_vec();
    let res = serde_json::from_slice::<Directory>(&body)?;

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(args.parallelism));
    let mut join_handles = Vec::new();
    for dir in &res.entries {
        match dir {
            common::data::DirEntry::File { filename, hash } => {
                let path = path.to_string();
                let filename = filename.clone();
                let hash = hash.clone();
                let semaphore = semaphore.clone();
                let server_url = server_url.clone();
                join_handles.push(tokio::spawn(async move {
                    // check if file exists already and hash is good?
                    let p = Path::new(&path).join(filename.clone());
                    let mut download_file = false;
                    match tokio::fs::read(&p).await {
                        Ok(fcontents) => {
                            let real_hash = hex::encode(hmac_sha256::Hash::hash(&fcontents));
                            if real_hash != *hash {
                                if overwrite {
                                    println!("File {filename} hashes mismatch, will be overwritten, local: {hash}, remote: {hash}");
                                    download_file = true;
                                } else {
                                    println!("File {filename} hashes mismatch, local: {hash}, remote: {hash}");
                                }
                            }
                        }
                        Err(e) => {
                            if e.kind() == ErrorKind::NotFound {
                                // file doesn't exist, download
                                download_file = true;
                            } else {
                                let err: Box<dyn Error + Send + Sync> = Box::new(e);
                                return Err(err);
                            }
                        }
                    }

                    if download_file {
                        let _ = semaphore.acquire_owned().await?;

                        let resp = reqwest::Client::default()
                            .get(format!("{server_url}/api/v1/blob/{hash}"))
                            .send()
                            .await?;

                        if resp.status().is_success() {
                            let download_start_file = std::time::Instant::now();

                            let body = resp.bytes().await?.to_vec();
                            let size = body.len();
                            let downloaded_hash = hex::encode(hmac_sha256::Hash::hash(&body));
                            if downloaded_hash != hash {
                                println!("File {filename} has wrong hash on the server, expected: {hash}, got: {downloaded_hash}");
                            }
                            tokio::fs::write(&p, body).await?;
                            println!("Downloaded {} of size {} in {:.3}s", filename, size, download_start_file.elapsed().as_secs_f64());
                        } else {
                            let err_message = String::from_utf8(resp.bytes().await?.to_vec())?;
                            return Err(Box::new(ClientErrors::FailedBlobDownload {
                                error: err_message,
                            }));
                        }
                    }

                    let res: Result<(), Box<dyn Error + Send + Sync>> = Ok(());
                    res
                }));
            }
        }
    }

    let handles = futures::future::join_all(join_handles).await;
    for handle in handles {
        let _ = handle?;
    }

    println!("Blob downloads done in {:.3}s", download_start_all.elapsed().as_secs_f64());

    Ok(())
}

async fn upload_files_to_server(args: &Cli, path: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let upload_start_all = std::time::Instant::now();
    let server_url = args.server_url.clone();
    let mut entries = tokio::fs::read_dir(path).await?;
    let mut merkle_buffer = Directory {
        entries: Vec::new(),
    };
    let mut join_handles = Vec::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(args.parallelism));
    while let Some(e) = entries.next_entry().await? {
        let ft = e.file_type().await?;
        if ft.is_file() {
            let filename = e.file_name().into_string().unwrap();
            let permit = semaphore.clone().acquire_owned().await?;
            let server_url = server_url.clone();
            let result = tokio::spawn(async move {
                let mut file = tokio::fs::File::open(e.path()).await?;
                let mut buffer = Vec::with_capacity(1024);
                let _ = file.read_to_end(&mut buffer).await?;
                let file_size = buffer.len();

                let hash = hex::encode(hmac_sha256::Hash::hash(&buffer));

                let exists = reqwest::Client::default()
                    .head(format!("{server_url}/api/v1/blob/{hash}"))
                    .send()
                    .await?;

                if exists.status().as_u16() == 404 {
                    // not found, upload
                    let upload_start_file = std::time::Instant::now();
                    let response = reqwest::Client::default()
                        .put(format!("{server_url}/api/v1/blob/{hash}"))
                        .body(buffer)
                        .send()
                        .await?;

                    if !response.status().is_success() {
                        let e: Box<dyn Error + Send + Sync> =
                            Box::new(ClientErrors::FailedBlobUpload {
                                file: filename.clone(),
                                error: String::from_utf8(response.bytes().await?.to_vec())?,
                            });
                        return Err(e);
                    } else {
                        println!("Uploaded {} with size {} over {:.3}s", filename, file_size, upload_start_file.elapsed().as_secs_f64());
                    }
                }

                drop(permit);

                // pleasing compiler
                let r: Result<common::data::DirEntry, Box<dyn Error + Send + Sync>> =
                    Ok(common::data::DirEntry::File { filename, hash });
                r
            });
            join_handles.push(result);
        }
    }

    let joined = futures::future::join_all(join_handles).await;
    if joined.is_empty() {
        return Err(Box::new(ClientErrors::EmptyDirectory));
    }

    for res in joined {
        let entry = res??;
        merkle_buffer.entries.push(entry);
    }

    println!("Blob uploads done in {:.3}s", upload_start_all.elapsed().as_secs_f64());

    // generate merkle tree locally to ensure hash is the same
    let mut tree_items = Vec::with_capacity(merkle_buffer.entries.len());
    for i in &merkle_buffer.entries {
        tree_items.push(serde_json::to_vec(i)?);
    }

    let mt = common::merkle_tree::MerkleTree::new(
        tree_items
            .iter()
            .map(|i| i.as_slice())
            .collect::<Vec<_>>()
            .as_slice(),
    )?;

    let expected_hash = hex::encode(mt.root_hash());

    let resp = reqwest::Client::default()
        .put(format!("{server_url}/api/v1/directory"))
        .json(&merkle_buffer)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(Box::new(ClientErrors::ErrorDuringDirectoryUpload {
            error: String::from_utf8(resp.bytes().await?.to_vec())?,
        }));
    }

    let res = resp.bytes().await?.to_vec();
    let resp = serde_json::from_slice::<DirectoryUploadResponse>(&res)?;

    if resp.merkle_root == expected_hash {
        println!("Directory {} upload successful, time elapsed {:.3}s merkle root: {}", path, upload_start_all.elapsed().as_secs_f64(), expected_hash);
    } else {
        eprintln!(
            "Merkle tree hash mistmatch, ours: {}, servers: {}",
            expected_hash, resp.merkle_root
        );
    }

    Ok(())
}
