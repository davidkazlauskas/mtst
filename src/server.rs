#[macro_use]
extern crate lazy_static;

use std::{collections::HashSet, error::Error};

use actix_web::{get, head, post, put, web, App, HttpResponse, HttpServer};
use clap::{command, Parser};
use dotenv::dotenv;
use futures::StreamExt;
use serde::Deserialize;

use common::{
    data::{DirEntry, Directory, DirectoryUploadResponse},
    merkle_tree::copy_merkle_root,
};

mod server_metrics;

#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "mtst")]
#[command(about = "Merkle tree storage server")]
struct Cli {
    /// PostgreSQL database host
    #[arg(long, default_value = "localhost")]
    pg_host: String,
    /// PostgreSQL database port
    #[arg(long, default_value = "5432")]
    pg_port: u16,
    /// PostgreSQL database name
    #[arg(long, default_value = "merkle_storage")]
    pg_database: String,
    /// PostgreSQL user name. Password can only provided via PG_PASSWORD environment variable
    #[arg(long, default_value = "merkle_storage")]
    pg_user: String,
    /// Maximum PostgreSQL connection pool size
    #[arg(long, default_value = "16")]
    pg_pool_size: usize,
    /// S3 url, credentials are derived from
    /// AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables
    #[arg(long, default_value = "http://localhost:9000")]
    s3_endpoint: String,
    /// S3 region to use
    #[arg(long, default_value = "eu-central-1")]
    s3_region: String,
    /// S3 bucket
    #[arg(long, default_value = "merkle-storage-blobs")]
    s3_bucket: String,
    /// Listening address with port for HTTP server
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    listen_address: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub pg: deadpool_postgres::Config,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    // load secret environment variables
    // like postgres password and aws access keys
    dotenv().ok();

    let pg_cfg = deadpool_postgres::Config {
        host: Some(cli.pg_host.clone()),
        port: Some(cli.pg_port),
        dbname: Some(cli.pg_database),
        user: Some(cli.pg_user.clone()),
        password: Some(
            std::env::var("PG_PASSWORD")
                .expect("PG_PASSWORD environment variable is required to be set"),
        ),
        ..Default::default()
    };

    dotenv().ok();
    env_logger::init();

    let creds = s3::creds::Credentials::from_env().expect("Can't get S3 bucket credentials");

    let pool = pg_cfg
        .create_pool(None, tokio_postgres::NoTls)
        .expect("Can't open PostgreSQL connection");

    let bucket = s3::Bucket::create_with_path_style(
        &cli.s3_bucket,
        s3::Region::Custom {
            region: cli.s3_region.clone(),
            endpoint: cli.s3_endpoint.clone(),
        },
        creds,
        s3::BucketConfiguration::private(),
    )
    .await
    .expect("Can't create S3 bucket");

    init_db_schema(&pool).await.expect("Cannot initialize PostgreSQL schema");

    HttpServer::new(move || {
        App::new()
            .wrap(actix_web::middleware::Logger::default())
            .app_data(actix_web::web::Data::new(pool.clone()))
            .app_data(actix_web::web::Data::new(bucket.bucket.clone()))
            .service(server_metrics::healthcheck)
            .service(server_metrics::prometheus_metrics)
            .service(check_blob)
            .service(get_blob)
            .service(upload_blob)
            .service(upload_directory)
            .service(list_directory)
            .service(generate_merkle_proofs_for_requested_data)
    })
    .bind(&cli.listen_address)?
    .run()
    .await
}

async fn init_db_schema(pool: &deadpool_postgres::Pool) -> Result<(), Box<dyn Error>> {
    let schema = include_str!("schema.sql");

    let conn = pool.get().await?;

    let check = conn.query("SELECT root_hash_256 FROM directory_merkle_trees LIMIT 1", &[]).await;
    match check {
        Ok(_) => {},
        Err(e) => {
            if e.to_string().contains("does not exist") {
                log::info!("SQL schema not initialized yet, applying migrations...");
                conn.batch_execute(schema).await?;
                log::info!("SQL migrations done");
            }
        },
    }

    Ok(())
}

/// Used to check if blob already uploaded
#[head("/api/v1/blob/{hash}")]
async fn check_blob(
    hash: web::Path<String>,
    pg_pool: web::Data<deadpool_postgres::Pool>,
) -> Result<HttpResponse, Box<dyn Error>> {
    let start_time = std::time::Instant::now();
    // fetch blob from S3, ensure it exists in our database
    let hash = hash.to_lowercase();
    let conn = pg_pool.get().await?;
    let res = conn
        .query(
            "SELECT size_bytes FROM blobs WHERE hash_sha256 = $1",
            &[&hash],
        )
        .await?;
    server_metrics::MTST_BLOB_CHECK_TIME.observe(start_time.elapsed().as_secs_f64());
    if !res.is_empty() {
        // already exists, return ok
        Ok(HttpResponse::Ok().finish())
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[get("/api/v1/blob/{hash}")]
async fn get_blob(
    hash: web::Path<String>,
    pg_pool: web::Data<deadpool_postgres::Pool>,
    bucket: web::Data<s3::Bucket>,
) -> Result<HttpResponse, Box<dyn Error>> {
    let start_time = std::time::Instant::now();
    // fetch blob from S3, ensure it exists in our database
    let hash = hash.to_lowercase();
    let conn = pg_pool.get().await?;
    let res = conn
        .query(
            "SELECT size_bytes FROM blobs WHERE hash_sha256 = $1",
            &[&hash],
        )
        .await?;
    if !res.is_empty() {
        // already exists, return ok
        let res = bucket.get_object(&hash).await?;
        server_metrics::MTST_BLOB_RETRIEVE_TIME.observe(start_time.elapsed().as_secs_f64());
        return Ok(HttpResponse::Ok().body(res.bytes().to_vec()));
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[put("/api/v1/blob/{hash}")]
async fn upload_blob(
    hash: web::Path<String>,
    mut payload: web::Payload,
    pg_pool: web::Data<deadpool_postgres::Pool>,
    bucket: web::Data<s3::Bucket>,
) -> Result<HttpResponse, Box<dyn Error>> {
    let start_time = std::time::Instant::now();
    let hash = hash.to_lowercase();
    {
        let conn = pg_pool.get().await?;
        let res = conn
            .query(
                "SELECT size_bytes FROM blobs WHERE hash_sha256 = $1",
                &[&hash],
            )
            .await?;
        if !res.is_empty() {
            // already exists, return ok
            return Ok(HttpResponse::Created().finish());
        }
    }

    let mut calc_hash = hmac_sha256::Hash::new();
    let mut file_bytes = Vec::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        calc_hash.update(&chunk);
        file_bytes.extend_from_slice(&chunk);
    }
    let calc_hash = hex::encode(calc_hash.finalize());
    if calc_hash != hash {
        Ok(HttpResponse::BadRequest().body("Payload hash path mismatched actual file hash"))
    } else {
        let _res = bucket.put_object(&hash, &file_bytes).await?;
        let conn = pg_pool.get().await?;
        let _res = conn
            .execute(
                "INSERT INTO blobs(hash_sha256, size_bytes)
                 VALUES($1, $2)
                 ON CONFLICT (hash_sha256) DO NOTHING",
                &[&hash, &(file_bytes.len() as i32)],
            )
            .await?;

        server_metrics::MTST_BLOB_UPLOAD_TIME.observe(start_time.elapsed().as_secs_f64());
        Ok(HttpResponse::Created().finish())
    }
}

/// All blobs must be uploaded first
#[put("/api/v1/directory")]
async fn upload_directory(
    payload: web::Json<Directory>,
    pg_pool: web::Data<deadpool_postgres::Pool>,
) -> Result<HttpResponse, Box<dyn Error>> {
    let start_time = std::time::Instant::now();
    // Check that all exist
    let mut merkle_tree_values = Vec::with_capacity(payload.entries.len());
    let mut entries: HashSet<&str> = HashSet::new();
    for entry in &payload.entries {
        merkle_tree_values.push(serde_json::to_string(entry)?);
        match entry {
            DirEntry::File { filename, .. } => {
                if !entries.insert(filename) {
                    return Ok(HttpResponse::BadRequest()
                        .body(format!("Duplicate file name {filename} in directory.")));
                }
            }
        }
    }

    let bytes_vec = merkle_tree_values
        .iter()
        .map(|i| i.as_bytes())
        .collect::<Vec<_>>();
    let mt = common::merkle_tree::MerkleTree::new(&bytes_vec)?;
    let root_hash_str = hex::encode(mt.root_hash());
    // hashes without duplicates to store on db
    let merkle_tree_hashes = mt
        .merkle_tree_hashes()
        .iter()
        .map(hex::encode)
        .collect::<Vec<_>>();

    let mut conn = pg_pool.get().await?;
    let trx = conn.transaction().await?;
    let count = trx
        .execute(
            "INSERT INTO directory_merkle_trees(
                 root_hash_sha256,
                 merkle_tree_leaf_size,
                 merkle_tree_leaf_offset,
                 merkle_tree_hashes,
                 merkle_tree_values
             )
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (root_hash_sha256) DO NOTHING",
            &[
                &root_hash_str,
                &(payload.entries.len() as i32),
                &(mt.leaf_offset() as i32),
                &merkle_tree_hashes,
                &merkle_tree_values,
            ],
        )
        .await?;

    if count == 0 {
        // merkle tree already uploaded, return
        let json = serde_json::to_value(DirectoryUploadResponse {
            merkle_root: root_hash_str,
        })?;
        return Ok(HttpResponse::Ok().json(json));
    }

    // We can use this data later for garbage collecting
    // unused s3 objects in the background
    let blob_ref_count = trx
        .prepare(
            "UPDATE blobs
             SET ref_count = ref_count + 1
             WHERE hash_sha256 = $1",
        )
        .await?;
    for entry in &payload.entries {
        match entry {
            DirEntry::File { hash, .. } => {
                let exec = trx.execute(&blob_ref_count, &[hash]).await?;
                if exec == 0 {
                    // not found
                    return Ok(HttpResponse::BadRequest()
                        .body(format!("Blob with hash {hash} is not uploaded yet.")));
                }
            }
        }
    }
    trx.commit().await?;

    server_metrics::MTST_DIRECTORY_METADATA_UPLOAD_TIME.observe(start_time.elapsed().as_secs_f64());
    Ok(HttpResponse::Ok().json(&DirectoryUploadResponse {
        merkle_root: root_hash_str,
    }))
}

#[get("/api/v1/directory/{merkle_root}")]
async fn list_directory(
    merkle_root: web::Path<String>,
    pg_pool: web::Data<deadpool_postgres::Pool>,
) -> Result<HttpResponse, Box<dyn Error>> {
    let start_time = std::time::Instant::now();
    let conn = pg_pool.get().await?;
    let res = conn
        .query(
            "SELECT unnest(merkle_tree_values)
             FROM directory_merkle_trees
             WHERE root_hash_sha256 = $1",
            &[&merkle_root.as_str()],
        )
        .await?;

    if res.is_empty() {
        return Ok(HttpResponse::NotFound().finish());
    }

    let mut result = Directory {
        entries: Vec::new(),
    };

    for row in res {
        let json = row.try_get::<usize, String>(0)?;
        let de = serde_json::from_str::<DirEntry>(&json)?;
        result.entries.push(de);
    }

    server_metrics::MTST_DIRECTORY_LIST_TIME.observe(start_time.elapsed().as_secs_f64());
    Ok(HttpResponse::Ok().json(&result))
}

#[post("/api/v1/directory/{merkle_root}/proofs")]
async fn generate_merkle_proofs_for_requested_data(
    merkle_root: web::Path<String>,
    payload: web::Json<Vec<DirEntry>>,
    pg_pool: web::Data<deadpool_postgres::Pool>,
) -> Result<HttpResponse, Box<dyn Error>> {
    let start_time = std::time::Instant::now();
    let conn = pg_pool.get().await?;
    let res = conn
        .query(
            "SELECT unnest(merkle_tree_hashes)
             FROM directory_merkle_trees
             WHERE root_hash_sha256 = $1",
            &[&merkle_root.as_str()],
        )
        .await?;

    if res.is_empty() {
        return Ok(HttpResponse::NotFound().finish());
    }

    let lc = conn
        .query(
            "SELECT merkle_tree_leaf_size
             FROM directory_merkle_trees
             WHERE root_hash_sha256 = $1",
            &[&merkle_root.as_str()],
        )
        .await?;

    let merkle_leaf_size = lc[0].try_get::<usize, i32>(0)?;

    let mut hashes = Vec::with_capacity(res.len());

    for row in res {
        let res = row.try_get::<usize, String>(0)?;
        let arr = hex::decode(&res)?;
        if arr.len() != 32 {
            log::error!(
                "Invalid length of hash retrieved from the database, expected 32, got {}",
                arr.len()
            );
            return Ok(HttpResponse::InternalServerError().body("Try again later"));
        }

        let mut hash: [u8; 32] = [0; 32];
        copy_merkle_root(&arr, &mut hash);
        hashes.push(hash);
    }

    let tree = common::merkle_tree::MerkleTree::from_raw(merkle_leaf_size as usize, &hashes)?;

    let mut proofs = Vec::with_capacity(payload.len());
    for req in payload.iter() {
        let v = serde_json::to_string(req)?;
        let proof = tree.generate_merkle_proof_for_value(v.as_bytes());
        proofs.push(proof);
    }

    server_metrics::MTST_MERKLE_PROOF_GENERATION_TIME.observe(start_time.elapsed().as_secs_f64());
    Ok(HttpResponse::Ok().json(&proofs))
}