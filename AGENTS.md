# srun-auth

Rust binary for Xidian University SRUN portal authentication.

## Build & Run

```bash
cargo build --release   # Produces static binary at target/x86_64-unknown-linux-musl/release/srun-auth
cargo run --release -- <USERNAME> <PASSWORD> [ACID]
```

## Project Structure

- `src/main.rs` - CLI entry, takes username, password, optional acid
- `src/lib.rs` - `run()` orchestrates: get_user_info -> get_acid -> login
- `src/apis.rs` - HTTP calls to Xidian auth endpoints
- `src/utils.rs` - `xencode()` and `fkbase64()` (custom SRUN encoding)
- `.cargo/config.toml` - Cross-compiles to `x86_64-unknown-linux-musl` (static MUSL binary)

## Notes

- `edition = "2024"` in Cargo.toml (requires rustc 1.94+)
- No tests in this repo
- Auth protocol uses custom HMAC-MD5, SHA1 checksums, and a modified base64 encoding
