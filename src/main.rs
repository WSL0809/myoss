use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use axum::{extract::Multipart, http::{StatusCode, header}, response::Html, routing::post, Router, response};
use ctr::cipher::{KeyIvInit};
use dotenv::dotenv;
use futures::{stream::TryStreamExt, StreamExt};
use hex::decode;
use rand::{rngs::OsRng, Rng};
use std::env;
use std::path::PathBuf;
use axum::body::Body;
use axum::extract::Path;
use axum::response::{IntoResponse, Response};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use uuid::Uuid;
fn encrypt_data(data: &[u8]) -> Result<(Vec<u8>), &'static str> {
    let key_string = env::var("KEY").map_err(|_| "Unable to get KEY from env")?;

    let key_bytes = decode(key_string).map_err(|_| "Failed to decode KEY")?;

    if key_bytes.len() != 32 {
        return Err("KEY must be 32 bytes long");
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);

    let nonce = OsRng.gen::<[u8; 12]>();

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key_array));
    let nonce_array = GenericArray::from_slice(&nonce);

    match cipher.encrypt(nonce_array, data) {
        Ok(mut encrypted_data) => {
            let mut result = Vec::with_capacity(nonce.len() + encrypted_data.len());
            result.extend_from_slice(&nonce);
            result.append(&mut encrypted_data);
            Ok(result)
        }
        Err(_) => Err("Encryption failed"),
    }
}

fn decrypt_data(
    encrypted_data: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, &'static str> {
    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);

    let cipher = Aes256Gcm::new(key);

    match cipher.decrypt(nonce, encrypted_data) {
        Ok(decrypted_data) => Ok(decrypted_data),
        Err(_) => Err("Decryption failed"),
    }
}
async fn upload_file(mut multipart: Multipart) -> Result<Html<String>, (StatusCode, String)> {
    while let Ok(Some(field)) = multipart.next_field().await {
        let file_name = field
            .file_name()
            .map(ToString::to_string)
            .unwrap_or_else(|| "file".to_string());
        let uuid = Uuid::new_v4();
        let file_path = format!("./uploads/{}-{}", uuid, file_name);

        let file = match File::create(&file_path).await {
            Ok(file) => file,
            Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
        };

        let mut writer = BufWriter::new(file);

        let mut stream = field.into_stream();
        while let Some(chunk) = stream.next().await {
            let data = chunk.expect("Error while reading chunk");
            let encrypted_data = encrypt_data(&data).expect("Failed to encrypt data");

            writer
                .write_all(&encrypted_data)
                .await
                .expect("Failed to write encrypted data");
        }
        writer.flush().await.expect("Failed to flush writer");

        return Ok(Html(format!("File '{}' uploaded successfully!", file_path)));
    }

    Err((StatusCode::BAD_REQUEST, "No file uploaded".into()))
}

// download file by file_path
async fn download_file(Path(file_path): Path<String>) -> impl IntoResponse {
    let file_path = format!("./uploads/{}", file_path);
    let path = PathBuf::from(file_path);

    match File::open(path).await {
        Ok(mut file) => {
            let mut buffer = Vec::new();
            if file.read_to_end(&mut buffer).await.is_ok() {
                Response::builder()
                    .status(StatusCode::OK)
                    // 设置 Content-Type 为 octet-stream 表示二进制数据流
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(Body::from(buffer))
                    .unwrap()
            } else {
                // 文件读取失败
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Failed to read file"))
                    .unwrap()
            }
        },
        Err(_) => {
            // 文件打开失败，可能是文件不存在或者路径错误
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("File not found or access denied"))
                .unwrap()
        }
    }
}
#[tokio::main]
async fn main() {
    dotenv().ok();

    let app = Router::new().route("/upload", post(upload_file))
        .route("/download", post(download_file));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
