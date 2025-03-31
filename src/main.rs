use anyhow::{Context, Result};
use axum::{
    extract::{Json, State},
    http::{HeaderValue, Method, StatusCode},
    routing::post,
    Router,
};
use chrono::{DateTime, Utc};
use nostr::{
    Event, EventBuilder, Keys, Kind, Tag, Timestamp, PublicKey,
};
use opentimestamps::{
    timestamp::{DetachedTimestampFile, Timestamp as OtsTimestamp},
    op::Op,
    crypto::Sha256,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tower_http::cors::CorsLayer;
use tracing::{error, info, Level};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dotenv::dotenv;
use std::env;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Failed to get block hash: {0}")]
    BlockHashError(String),
    #[error("Failed to create Nostr event: {0}")]
    NostrError(String),
    #[error("Failed to create timestamp: {0}")]
    TimestampError(String),
    #[error("Internal server error: {0}")]
    InternalError(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Failed to verify timestamp: {0}")]
    TimestampVerificationError(String),
    #[error("Failed to fetch Nostr profile: {0}")]
    NostrProfileError(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            AppError::BlockHashError(_) => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            AppError::NostrError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::TimestampError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::InternalError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::InvalidSignature(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::TimestampVerificationError(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::NostrProfileError(_) => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            AppError::InvalidInput(_) => (StatusCode::BAD_REQUEST, self.to_string()),
        };

        let body = serde_json::json!({
            "error": error_message
        });

        (status, axum::Json(body)).into_response()
    }
}

#[derive(Deserialize)]
struct MessageRequest {
    message: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    signed_event: Event,
    ots_event: Event,
}

#[derive(Serialize)]
struct MessageResponse {
    signed_event: Event,
    ots_event: Event,
}

#[derive(Serialize)]
struct VerifyResponse {
    signature_valid: bool,
    block_time: DateTime<Utc>,
    timestamp_time: DateTime<Utc>,
    pubkey: String,
    username: Option<String>,
    nip05: Option<String>,
}

struct AppState {
    nostr_keys: Keys,
}

async fn get_latest_block_hash() -> Result<String, AppError> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://cyphernode.com/api/v1/bitcoin/blocks/latest")
        .send()
        .await
        .map_err(|e| AppError::BlockHashError(e.to_string()))?;
    
    let block: serde_json::Value = response
        .json()
        .await
        .map_err(|e| AppError::BlockHashError(e.to_string()))?;
    
    block["hash"]
        .as_str()
        .ok_or_else(|| AppError::BlockHashError("No hash in response".to_string()))
        .map(|s| s.to_string())
}

async fn get_block_time(block_hash: &str) -> Result<DateTime<Utc>, AppError> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("https://cyphernode.com/api/v1/bitcoin/blocks/{}", block_hash))
        .send()
        .await
        .map_err(|e| AppError::BlockHashError(e.to_string()))?;
    
    let block: serde_json::Value = response
        .json()
        .await
        .map_err(|e| AppError::BlockHashError(e.to_string()))?;
    
    let time = block["timestamp"]
        .as_i64()
        .ok_or_else(|| AppError::BlockHashError("No timestamp in response".to_string()))?;
    
    Ok(DateTime::from_timestamp(time as i64, 0)
        .ok_or_else(|| AppError::BlockHashError("Invalid timestamp".to_string()))?)
}

async fn get_nostr_profile(pubkey: &PublicKey) -> Result<(Option<String>, Option<String>), AppError> {
    // TODO: Implement Nostr profile lookup
    Ok((None, None))
}

async fn verify_timestamp(timestamp_file: &str) -> Result<DateTime<Utc>, AppError> {
    // Verify that this is a valid NIP-03 event
    if timestamp_file.is_empty() {
        return Err(AppError::TimestampVerificationError("No timestamp provided".to_string()));
    }

    // Decode the base64 content
    let ots_data = BASE64.decode(timestamp_file.as_bytes())
        .map_err(|e| AppError::TimestampVerificationError(format!("Invalid base64: {}", e)))?;

    // TODO: Implement actual OTS verification
    // For now, return the current time
    Ok(Utc::now())
}

async fn process_message(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<MessageRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    // 1. Get latest Bitcoin block hash
    let block_hash = get_latest_block_hash().await?;

    // 2. Create the message with block hash
    let message_with_hash = format!("{} | Block Hash: {}", payload.message, block_hash);

    // 3. Create and sign Nostr event using the stored keys
    let event = EventBuilder::new(
        Kind::TextNote,
        message_with_hash,
        &[Tag::Generic(
            Tag::Kind("block_hash".to_string()),
            vec![block_hash],
        )],
    )
    .to_event(&state.nostr_keys)
    .map_err(|e| AppError::NostrError(e.to_string()))?;

    // 4. Create OpenTimestamps attestation
    let hash = Sha256::digest(event.as_json().as_bytes());
    let mut timestamp = OtsTimestamp::new(hash);
    timestamp.add_op(Op::Append(0x01));
    
    let mut detached = DetachedTimestampFile::new();
    detached.add_timestamp(timestamp);

    // 5. Create NIP-03 event with the OTS attestation
    let ots_event = EventBuilder::new(
        Kind::OpenTimestamps,
        BASE64.encode(detached.to_string().as_bytes()),
        &[
            Tag::Generic(
                Tag::Kind("e".to_string()),
                vec![event.id.to_string(), "wss://your-relay.com".to_string()],
            ),
            Tag::Generic(
                Tag::Kind("alt".to_string()),
                vec!["opentimestamps attestation".to_string()],
            ),
        ],
    )
    .to_event(&state.nostr_keys)
    .map_err(|e| AppError::NostrError(e.to_string()))?;

    // 6. Return response
    Ok(Json(MessageResponse {
        signed_event: event,
        ots_event,
    }))
}

async fn verify_message(
    State(_state): State<Arc<AppState>>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    // 1. Verify Nostr signature of main event
    if !payload.signed_event.verify() {
        return Err(AppError::InvalidSignature("Invalid Nostr signature".to_string()));
    }

    // 2. Verify NIP-03 event
    if payload.ots_event.kind != Kind::OpenTimestamps {
        return Err(AppError::InvalidInput("Invalid OTS event kind".to_string()));
    }

    // 3. Verify OTS event signature
    if !payload.ots_event.verify() {
        return Err(AppError::InvalidSignature("Invalid OTS event signature".to_string()));
    }

    // 4. Verify OTS event references main event
    let event_id = payload.ots_event.tags.iter()
        .find(|tag| tag.as_vec().first() == Some(&"e".to_string()))
        .and_then(|tag| tag.as_vec().get(1))
        .ok_or_else(|| AppError::InvalidInput("Missing event reference in OTS event".to_string()))?;

    if event_id != &payload.signed_event.id.to_string() {
        return Err(AppError::InvalidInput("Event reference mismatch".to_string()));
    }

    // 5. Extract block hash from message
    let block_hash = payload.signed_event
        .tags
        .iter()
        .find(|tag| tag.kind() == "block_hash")
        .and_then(|tag| tag.values().first())
        .ok_or_else(|| AppError::InvalidInput("No block hash found in message".to_string()))?;

    // 6. Get block time
    let block_time = get_block_time(block_hash).await?;

    // 7. Get Nostr profile
    let (username, nip05) = get_nostr_profile(&payload.signed_event.pubkey).await?;

    // 8. Verify timestamp
    let timestamp_time = verify_timestamp(&payload.ots_event.content).await?;

    Ok(Json(VerifyResponse {
        signature_valid: true,
        block_time,
        timestamp_time,
        pubkey: payload.signed_event.pubkey.to_string(),
        username,
        nip05,
    }))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables
    dotenv().ok();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    // Get Nostr private key from environment
    let nostr_private_key = env::var("NOSTR_PRIVATE_KEY")
        .context("NOSTR_PRIVATE_KEY environment variable not set")?;
    
    let nostr_keys = Keys::from_sk_str(&nostr_private_key)
        .context("Failed to parse Nostr private key")?;

    let state = Arc::new(AppState { nostr_keys });

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::POST])
        .allow_headers(vec![http::header::CONTENT_TYPE]);

    // Create router
    let app = Router::new()
        .route("/stamp", post(process_message))
        .route("/verify", post(verify_message))
        .layer(cors)
        .with_state(state);

    // Start server
    let addr = "0.0.0.0:3000";
    info!("Starting server on {}", addr);
    axum::Server::bind(&addr.parse().unwrap())
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use mockito::{mock, Matcher};

    fn create_test_app() -> Router {
        let nostr_keys = Keys::generate(&mut rand::thread_rng());
        let state = Arc::new(AppState { nostr_keys });
        
        Router::new()
            .route("/stamp", post(process_message))
            .route("/verify", post(verify_message))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_process_message_success() {
        let app = create_test_app();
        let request = Request::builder()
            .method("POST")
            .uri("/stamp")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"message": "test message"}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let response: MessageResponse = serde_json::from_slice(&body).unwrap();

        // Verify Nostr event
        assert_eq!(response.signed_event.kind, Kind::TextNote);
        assert!(response.signed_event.content.contains("test message"));
        assert!(response.signed_event.content.contains("Block Hash:"));
        assert!(response.signed_event.verify().is_ok());

        // Verify timestamp file
        assert!(!response.ots_event.content.is_empty());
    }

    #[tokio::test]
    async fn test_process_message_invalid_json() {
        let app = create_test_app();
        let request = Request::builder()
            .method("POST")
            .uri("/stamp")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"invalid": "json"}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_process_message_empty_message() {
        let app = create_test_app();
        let request = Request::builder()
            .method("POST")
            .uri("/stamp")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"message": ""}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let response: MessageResponse = serde_json::from_slice(&body).unwrap();
        assert!(response.signed_event.content.contains("Block Hash:"));
    }

    #[tokio::test]
    async fn test_process_message_with_special_characters() {
        let app = create_test_app();
        let request = Request::builder()
            .method("POST")
            .uri("/stamp")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"message": "Test with special chars: !@#$%^&*()"}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let response: MessageResponse = serde_json::from_slice(&body).unwrap();
        assert!(response.signed_event.content.contains("Test with special chars: !@#$%^&*()"));
    }

    #[tokio::test]
    async fn test_verify_message_success() {
        let app = create_test_app();
        let keys = Keys::generate(&mut rand::thread_rng());
        let event = EventBuilder::new(
            Kind::TextNote,
            "test message | Block Hash: test_block_hash",
            &[Tag::Generic(
                Tag::Kind("block_hash".to_string()),
                vec!["test_block_hash"],
            )],
        )
        .to_event(&keys)
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&VerifyRequest {
                signed_event: event,
                ots_event: "test_timestamp".to_string(),
            }).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let response: VerifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(response.signature_valid);
        assert_eq!(response.pubkey, keys.public_key().to_string());
    }

    #[tokio::test]
    async fn test_verify_message_invalid_signature() {
        let app = create_test_app();
        let mut event = EventBuilder::new(
            Kind::TextNote,
            "test message | Block Hash: test_block_hash",
            &[Tag::Generic(
                Tag::Kind("block_hash".to_string()),
                vec!["test_block_hash"],
            )],
        )
        .to_event(&Keys::generate(&mut rand::thread_rng()))
        .unwrap();
        
        // Modify the signature to make it invalid
        event.sig = "invalid_signature".to_string();

        let request = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&VerifyRequest {
                signed_event: event,
                ots_event: "test_timestamp".to_string(),
            }).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_verify_message_missing_block_hash() {
        let app = create_test_app();
        let event = EventBuilder::new(
            Kind::TextNote,
            "test message",
            &[],
        )
        .to_event(&Keys::generate(&mut rand::thread_rng()))
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&VerifyRequest {
                signed_event: event,
                ots_event: "test_timestamp".to_string(),
            }).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_verify_message_invalid_block_hash() {
        let app = create_test_app();
        let event = EventBuilder::new(
            Kind::TextNote,
            "test message | Block Hash: invalid_hash",
            &[Tag::Generic(
                Tag::Kind("block_hash".to_string()),
                vec!["invalid_hash"],
            )],
        )
        .to_event(&Keys::generate(&mut rand::thread_rng()))
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&VerifyRequest {
                signed_event: event,
                ots_event: "test_timestamp".to_string(),
            }).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_verify_message_invalid_timestamp() {
        let app = create_test_app();
        let event = EventBuilder::new(
            Kind::TextNote,
            "test message | Block Hash: test_block_hash",
            &[Tag::Generic(
                Tag::Kind("block_hash".to_string()),
                vec!["test_block_hash"],
            )],
        )
        .to_event(&Keys::generate(&mut rand::thread_rng()))
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&VerifyRequest {
                signed_event: event,
                ots_event: "invalid_timestamp".to_string(),
            }).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_verify_message_invalid_json() {
        let app = create_test_app();
        let request = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"invalid": "json"}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_verify_message_empty_timestamp() {
        let app = create_test_app();
        let event = EventBuilder::new(
            Kind::TextNote,
            "test message | Block Hash: test_block_hash",
            &[Tag::Generic(
                Tag::Kind("block_hash".to_string()),
                vec!["test_block_hash"],
            )],
        )
        .to_event(&Keys::generate(&mut rand::thread_rng()))
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&VerifyRequest {
                signed_event: event,
                ots_event: "".to_string(),
            }).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_verify_message_with_profile() {
        let app = create_test_app();
        let keys = Keys::generate(&mut rand::thread_rng());
        let event = EventBuilder::new(
            Kind::TextNote,
            "test message | Block Hash: test_block_hash",
            &[Tag::Generic(
                Tag::Kind("block_hash".to_string()),
                vec!["test_block_hash"],
            )],
        )
        .to_event(&keys)
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&VerifyRequest {
                signed_event: event,
                ots_event: "test_timestamp".to_string(),
            }).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let response: VerifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(response.signature_valid);
        assert_eq!(response.pubkey, keys.public_key().to_string());
        // Note: username and nip05 are currently None as we haven't implemented profile lookup
        assert!(response.username.is_none());
        assert!(response.nip05.is_none());
    }
}
