# Keystamp Protocol Documentation

This document describes the protocol and functionality of the Keystamp API server, which provides timestamping services for messages using Bitcoin block hashes, Nostr events, and OpenTimestamps attestations.

## Overview

Keystamp is an API server that allows users to:
1. Create timestamped messages with Bitcoin block hashes
2. Sign these messages using Nostr private keys
3. Create OpenTimestamps attestations for the messages
4. Verify the authenticity and timestamps of messages

## Endpoints

### 1. Stamp Endpoint (`POST /stamp`)

The stamp endpoint creates a timestamped and signed message with the following steps:

1. **Message Reception**
   - Accepts a JSON request with a `message` field
   - Validates the input format

2. **Block Hash Retrieval**
   - Fetches the latest Bitcoin block hash from CypherNode
   - This provides a reference point in the Bitcoin blockchain

3. **Main Event Creation**
   - Creates a Nostr event of kind 1 (Text Note)
   - Includes the original message and block hash in the content
   - Adds a `block_hash` tag with the Bitcoin block hash
   - Signs the event with the server's Nostr private key

4. **OpenTimestamps Attestation**
   - Creates a SHA256 hash of the main event's JSON representation
   - Creates an OpenTimestamps attestation for this hash
   - This provides cryptographic proof of the event's existence

5. **NIP-03 Event Creation**
   - Creates a Nostr event of kind 1040 (OpenTimestamps)
   - Includes the base64-encoded OTS attestation in the content
   - Adds required NIP-03 tags:
     - `["e", <event-id>, <relay-url>]` to reference the main event
     - `["alt", "opentimestamps attestation"]` to indicate the event type
   - Signs the event with the same Nostr key

6. **Response**
   - Returns both the main event and the NIP-03 event in the response
   - Both events are properly signed and ready for verification

### 2. Verify Endpoint (`POST /verify`)

The verify endpoint validates a timestamped message and its attestation with the following steps:

1. **Input Validation**
   - Accepts a JSON request containing:
     - The original signed event
     - The NIP-03 OTS attestation event
   - Validates the input format

2. **Signature Verification**
   - Verifies the Nostr signature of the main event
   - Verifies the Nostr signature of the NIP-03 event
   - Ensures both events were signed by the same key

3. **NIP-03 Event Validation**
   - Confirms the OTS event is of kind 1040
   - Verifies the OTS event properly references the main event
   - Validates the presence of required NIP-03 tags

4. **Block Hash Verification**
   - Extracts the block hash from the main event's tags
   - Fetches the block time from CypherNode
   - This provides the Bitcoin blockchain timestamp

5. **OpenTimestamps Verification**
   - Decodes the base64-encoded OTS attestation
   - Verifies the attestation against the main event
   - This provides cryptographic proof of the timestamp

6. **Profile Information**
   - Retrieves the Nostr profile information for the signer
   - Includes username and NIP-05 identifier if available

7. **Response**
   - Returns a JSON response containing:
     - Signature validity status
     - Block time from Bitcoin blockchain
     - Timestamp time from OTS attestation
     - Signer's public key
     - Signer's profile information (username and NIP-05)

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

## Security Considerations

1. **Private Key Management**
   - Nostr private key is loaded from environment variables
   - Never exposed in responses or logs
   - Used only for signing events

2. **Signature Verification**
   - All events are verified before processing
   - Invalid signatures are rejected immediately
   - Ensures message authenticity

3. **Timestamp Verification**
   - Multiple layers of verification:
     - Bitcoin block hash provides blockchain timestamp
     - OpenTimestamps provides cryptographic proof
     - NIP-03 ensures proper attestation format

4. **CORS Configuration**
   - Restricted to specific origins
   - Only allows necessary HTTP methods
   - Protects against unauthorized access

## Example Usage

### Stamping a Message
```bash
curl -X POST http://localhost:3000/stamp \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello, world!"}'
```

### Verifying a Message
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
        "content": "Hello, world! | Block Hash: bitcoin_block_hash_here",
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