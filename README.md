# Keystamp API Server

⚠️ **WARNING: 100% vibecoded. Do not use** ⚠️

A Rust API server that integrates Nostr message signing with Bitcoin block hashes and OpenTimestamps for message timestamping. This is a CypherApp that runs within the CypherNode Docker network.

## Features

- Sign messages with Nostr private keys
- Fetch Bitcoin block hashes from CypherNode
- Create OpenTimestamps attestations (NIP-03 compliant)
- Verify signed messages and timestamps
- Look up Nostr profile information
- CORS support for web applications

## Prerequisites

- Rust 1.70 or later
- Docker and Docker Compose
- A Nostr private key
- A running CypherNode instance

## Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd keystamp
   ```

2. Copy the environment file and edit it:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and add your Nostr private key.

3. Make sure your CypherNode instance is running and accessible.

4. Build and run with Docker:
   ```bash
   docker-compose up --build
   ```

The app will automatically connect to CypherNode through the Docker network.

## API Documentation

### Stamp Endpoint

Signs a message with a Nostr private key, includes a Bitcoin block hash, and creates an OpenTimestamps attestation following NIP-03.

**Endpoint:** `POST /stamp`

**Request:**
```json
{
    "message": "Your message to sign and timestamp"
}
```

**Response:**
```json
{
    "signed_event": {
        "id": "event_id_here",
        "pubkey": "nostr_public_key_here",
        "created_at": 1234567890,
        "kind": 1,
        "tags": [
            ["block_hash", "bitcoin_block_hash_here"]
        ],
        "content": "Your message to sign and timestamp | Block Hash: bitcoin_block_hash_here",
        "sig": "nostr_signature_here"
    },
    "ots_event": {
        "id": "ots_event_id_here",
        "pubkey": "nostr_public_key_here",
        "created_at": 1234567890,
        "kind": 1040,
        "tags": [
            ["e", "event_id_here", "wss://your-relay.com"],
            ["alt", "opentimestamps attestation"]
        ],
        "content": "base64_encoded_ots_file_content",
        "sig": "nostr_signature_here"
    }
}
```

**Example using curl:**
```bash
curl -X POST http://localhost:3000/stamp \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello, world!"}'
```

### Verify Endpoint

Verifies a signed message, its NIP-03 OTS attestation, and retrieves the signer's profile information.

**Endpoint:** `POST /verify`

**Request:**
```json
{
    "signed_event": {
        "id": "event_id_here",
        "pubkey": "nostr_public_key_here",
        "created_at": 1234567890,
        "kind": 1,
        "tags": [
            ["block_hash", "bitcoin_block_hash_here"]
        ],
        "content": "Your message to sign and timestamp | Block Hash: bitcoin_block_hash_here",
        "sig": "nostr_signature_here"
    },
    "ots_event": {
        "id": "ots_event_id_here",
        "pubkey": "nostr_public_key_here",
        "created_at": 1234567890,
        "kind": 1040,
        "tags": [
            ["e", "event_id_here", "wss://your-relay.com"],
            ["alt", "opentimestamps attestation"]
        ],
        "content": "base64_encoded_ots_file_content",
        "sig": "nostr_signature_here"
    }
}
```

**Response:**
```json
{
    "signature_valid": true,
    "block_time": "2024-03-14T12:34:56Z",
    "timestamp_time": "2024-03-14T12:34:57Z",
    "pubkey": "nostr_public_key_here",
    "username": "example_user",
    "nip05": "example@domain.com"
}
```

**Example using curl:**
```bash
curl -X POST http://localhost:3000/verify \
  -H "Content-Type: application/json" \
  -d '{
    "signed_event": {
        "id": "event_id_here",
        "pubkey": "nostr_public_key_here",
        "created_at": 1234567890,
        "kind": 1,
        "tags": [["block_hash", "bitcoin_block_hash_here"]],
        "content": "Your message to sign and timestamp | Block Hash: bitcoin_block_hash_here",
        "sig": "nostr_signature_here"
    },
    "ots_event": {
        "id": "ots_event_id_here",
        "pubkey": "nostr_public_key_here",
        "created_at": 1234567890,
        "kind": 1040,
        "tags": [
            ["e", "event_id_here", "wss://your-relay.com"],
            ["alt", "opentimestamps attestation"]
        ],
        "content": "base64_encoded_ots_file_content",
        "sig": "nostr_signature_here"
    }
}'
```

## Error Handling

The API uses standard HTTP status codes and returns error messages in the following format:

```json
{
    "error": "Error message description"
}
```

Common error scenarios:
- `400 Bad Request`: Invalid input data, missing fields, or invalid signatures
- `503 Service Unavailable`: Failed to fetch block hash or Nostr profile
- `500 Internal Server Error`: Server-side processing errors

## Security Notes

- The Nostr private key is loaded from environment variables and never exposed in responses
- Authentication is managed through CypherApps existing infrastructure
- All timestamps are verified against the Bitcoin blockchain
- CORS is configured to allow requests from `http://localhost:3000`

## Development

To run tests:
```bash
cargo test
```

For detailed test output:
```bash
cargo test -- --nocapture
```

## License

[Your chosen license] 