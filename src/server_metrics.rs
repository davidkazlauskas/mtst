use std::error::Error;

use actix_web::{HttpResponse, get};
use prometheus::{Histogram, register_histogram, histogram_opts};


lazy_static! {
    pub static ref MTST_BLOB_UPLOAD_TIME: Histogram = register_histogram!(histogram_opts!(
        "mtst_blob_upload_time",
        "Time taken to upload blob to S3 and register to database",
        vec![0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    )).unwrap();
    pub static ref MTST_BLOB_RETRIEVE_TIME: Histogram = register_histogram!(histogram_opts!(
        "mtst_blob_retrieve_time",
        "Time taken to download blob from S3 with database check for metadata",
        vec![0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    )).unwrap();
    pub static ref MTST_BLOB_CHECK_TIME: Histogram = register_histogram!(histogram_opts!(
        "mtst_blob_check_time",
        "Time taken to check if blob exists in database",
        vec![0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    )).unwrap();
    pub static ref MTST_DIRECTORY_METADATA_UPLOAD_TIME: Histogram = register_histogram!(histogram_opts!(
        "mtst_directory_metadata_upload_time",
        "Time taken to upload directory metadata to storage with all checks",
        vec![0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    )).unwrap();
    pub static ref MTST_DIRECTORY_LIST_TIME: Histogram = register_histogram!(histogram_opts!(
        "mtst_directory_list_time",
        "Time taken to list directory metadata",
        vec![0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    )).unwrap();
    pub static ref MTST_MERKLE_PROOF_GENERATION_TIME: Histogram = register_histogram!(histogram_opts!(
        "mtst_merkle_proof_generation_time",
        "Time taken to generate requested merkle proofs",
        vec![0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    )).unwrap();
}

#[get("/healthz")]
async fn healthcheck() -> HttpResponse {
    HttpResponse::Ok().body("OK")
}

#[get("/metrics")]
async fn prometheus_metrics() -> Result<HttpResponse, Box<dyn Error>> {
    use prometheus::Encoder;

    let mut buffer = Vec::new();
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    encoder.encode(&metric_families, &mut buffer)?;
    Ok(HttpResponse::Ok().body(buffer))
}