# SRUN Portal Authentication

Xidian University campus network authentication client.

## Overview

The SRUN portal uses a challenge-response authentication protocol with custom encryption. This document describes the authentication flow and API details.

## Authentication Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  rad_user_info  │────>│  get_challenge  │────>│  srun_portal    │
│  (check status) │     │  (get token)    │     │  (login)        │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                      ↑
                                            acid extracted from bing.com
```

**Step 1**: Check login status via `rad_user_info`
- If `error == "ok"`, already authenticated — exit
- Otherwise, proceed to step 2

**Step 2**: Get ACID via `get_acid`
- Fetches `http://bing.com` and extracts the ACID from URL pattern `/index_(\d+).html`

**Step 3**: Get challenge token via `get_challenge`
- Required for building the encrypted payload

**Step 4**: Login via `srun_portal`
- Submit encrypted credentials and checksum

## API Reference

### 1. Check User Status

```
GET https://w.xidian.edu.cn/cgi-bin/rad_user_info?callback=jsonp
```

**Response** (JSONP, strip `jsonp(` prefix and `)` suffix):

```json
{
  "error": "ok",
  "online_ip": "10.0.0.1"
}
```

| Field     | Type    | Description                          |
|-----------|---------|--------------------------------------|
| error     | string  | `"ok"` if authenticated, else error  |
| online_ip | string  | Current assigned IP address          |

### 2. Get ACID

```
GET http://bing.com
```

Extract ACID by regex: `/index_(\d+).html`

The ACID corresponds to the campus network area/zone.

### 3. Get Challenge Token

```
GET https://w.xidian.edu.cn/cgi-bin/get_challenge?callback=jsonp&username=<USER>&ip=<IP>
```

**Parameters**:

| Field    | Description           |
|----------|-----------------------|
| username | User's login name     |
| ip       | Current IP address    |

**Response** (JSONP):

```json
{
  "challenge": "abc123..."
}
```

| Field     | Type   | Description           |
|-----------|--------|-----------------------|
| challenge | string | Token for encryption  |

### 4. Login

```
GET https://w.xidian.edu.cn/cgi-bin/srun_portal?callback=jsonp&action=login&...
```

**Parameters**:

| Field    | Description                                           |
|----------|-------------------------------------------------------|
| callback | Always `jsonp`                                        |
| action   | Always `login`                                        |
| username | User's login name                                     |
| password | `{MD5}` + HMAC-MD5( token, password ) in hex          |
| chksum   | SHA1 of concatenated fields (see below)               |
| info     | Encrypted payload (see below)                         |
| ac_id    | Campus zone ID                                        |
| ip       | Current IP address                                    |
| n        | Always `200`                                          |
| type     | Always `1`                                            |

## Payload Encryption

### Info Field (SRBX1 format)

```rust
info = format!("{{SRBX1}}{}", fkbase64(xencode(json_payload, token)))
```

Where `json_payload`:
```json
{
  "username": "user",
  "password": "pass",
  "ip": "10.0.0.1",
  "acid": "1",
  "enc_ver": "srun_bx1"
}
```

### Checksum Calculation

Concatenate fields in order, then SHA1:

```
chksum = SHA1( token + username + token + hmd5 + token + acid + token + ip + token + n + token + type + token + info )
```

Where:
- `token` = challenge from `get_challenge`
- `hmd5` = HMAC-MD5( token, password ) encoded as hex

### Custom Encoding: `xencode`

TEA-like cipher operating on 32-bit words with 32 rounds. Input is padded to 4-byte alignment with size appended.

### Custom Encoding: `fkbase64`

Base64 with modified alphabet:

```
LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA
```

Standard Base64 uses `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`

## Constants

| Constant | Value | Description            |
|----------|-------|------------------------|
| SRUN_N   | "200" | Protocol version       |
| SRUN_TYPE| "1"   | Authentication type    |

## Build & Run

```bash
cargo build --release
./target/x86_64-unknown-linux-musl/release/srun-auth <USERNAME> <PASSWORD> [ACID]
```

ACID is optional; if not provided, it will be fetched automatically from bing.com.

## Behavior

- **Success**: exits with code 0 with no output
- **Already logged in**: exits immediately (no re-login)
- **Failure**: error message printed to stderr, process exits with error
