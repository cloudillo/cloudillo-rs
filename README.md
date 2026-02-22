<p align="center">
  <img src="https://cloudillo.org/images/logo-full.svg" alt="Cloudillo" width="400">
</p>

<h3 align="center">Your Data, Your Rules</h3>

<p align="center">
  <a href="https://github.com/cloudillo/cloudillo-rs/actions/workflows/general.yaml"><img src="https://github.com/cloudillo/cloudillo-rs/actions/workflows/general.yaml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/cloudillo"><img src="https://img.shields.io/crates/v/cloudillo.svg" alt="crates.io"></a>
  <a href="https://github.com/cloudillo/cloudillo-rs/blob/main/LICENSE.LESSER"><img src="https://img.shields.io/crates/l/cloudillo.svg" alt="License: LGPL-3.0-only"></a>
</p>

## What is Cloudillo?

Online collaboration platforms typically fall into two categories:

1. **Cloud-based services** — convenient but may raise concerns about privacy, data ownership, and censorship.
2. **Self-hosted applications** — provide control but are challenging to set up and don't integrate well with each other.

Cloudillo bridges this gap. It is a **federated, self-hosted web application platform** that gives you the convenience of cloud services without sacrificing privacy or control over your data. Each user runs their own Cloudillo instance and connects with others through open federation protocols — no central server required.

## Key Features

- **Federation** — Instances communicate using signed activity tokens, so users on different servers can interact seamlessly
- **Real-time collaboration** — Collaborative document editing via CRDT (Yjs), plus a Firebase-style real-time database over WebSocket
- **File storage** — Content-addressed immutable blob storage with automatic image processing and variant generation
- **Social features** — Posts, comments, reactions, and community spaces with role-based access control
- **Identity portability** — Your identity is a cryptographic key pair, not an account on someone else's server
- **Self-hosted** — Runs on your own hardware with automatic TLS via ACME/Let's Encrypt

## Architecture

Cloudillo-RS is a Rust workspace with 20 crates organized into three layers:

| Layer | Crates | Purpose |
|-------|--------|---------|
| **Feature crates** | `cloudillo-action`, `cloudillo-auth`, `cloudillo-file`, `cloudillo-crdt`, `cloudillo-rtdb`, `cloudillo-profile`, and more | Business logic for each feature area |
| **Core** | `cloudillo`, `cloudillo-types`, `cloudillo-core` | Shared types, middleware, extractors, scheduling, and the application builder |
| **Adapters** | `auth-adapter-sqlite`, `meta-adapter-sqlite`, `blob-adapter-fs`, `rtdb-adapter-redb`, `crdt-adapter-redb` | Pluggable storage backends behind trait interfaces |

Key technologies: **Axum** (HTTP), **SQLite** (metadata and auth), **redb** (real-time and CRDT storage), **Tokio** (async runtime), **Yrs** (Yjs CRDT).

The codebase enforces `#![forbid(unsafe_code)]` — no `unsafe` anywhere.

## Getting Started

### Prerequisites

- Rust 1.75+ (2021 edition)
- For production deployment:
  - DNS A (or CNAME) records for your domain **and** `cl-o.<domain>` pointing to your server IP
  - Ports 443 (HTTPS) and 80 (HTTP / ACME challenges) open

### Build and Run

```bash
# Build everything
cargo build

# Build the server binary
cargo build -p cloudillo-server

# Run (see Configuration below for all env vars)
BASE_ID_TAG=dev cargo run -p cloudillo-server

# Optimized release build (LTO, stripped)
cargo build --profile release-lto
```

### Frontend

The server serves a frontend built from the separate [cloudillo/cloudillo](https://github.com/cloudillo/cloudillo) repository. You need Node.js 22+ and [pnpm](https://pnpm.io/).

```bash
# Clone and build the frontend
git clone https://github.com/cloudillo/cloudillo.git
cd cloudillo
pnpm install --frozen-lockfile
pnpm -r --filter '!@cloudillo/storybook' build

# Assemble into the dist directory (adjust path to your cloudillo-rs checkout)
mkdir -p ../cloudillo-rs/dist/apps
cp -r shell/dist/* ../cloudillo-rs/dist/
for app in apps/*/; do
  name=$(basename "$app")
  if [ -d "$app/dist" ]; then
    cp -r "$app/dist" "../cloudillo-rs/dist/apps/$name"
  fi
done
```

The server looks for these files in `DIST_DIR` (`./dist` by default).

### Configuration

The server is configured through environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `BASE_ID_TAG` | Tenant identifier / domain (**required**) | — |
| `LOCAL_ADDRESS` | Comma-separated server IP(s) for DNS validation | — |
| `BASE_APP_DOMAIN` | App domain for the base tenant | `BASE_ID_TAG` |
| `BASE_PASSWORD` | Initial admin password | — |
| `ACME_EMAIL` | Email for Let's Encrypt certificates | — |
| `MODE` | `standalone`, `proxy`, or `stream-proxy` | `standalone` |
| `LISTEN` | HTTPS bind address | `127.0.0.1:1443` |
| `LISTEN_HTTP` | HTTP bind address (ACME challenges) | `127.0.0.1:1080` |
| `DB_DIR` | Database directory | `./data` |
| `DATA_DIR` | Blob storage directory | `./data` |
| `DIST_DIR` | Frontend static files directory | `./dist` |
| `RUST_LOG` | Log level filter | — |
| `DISABLE_CACHE` | Set to any value to disable HTTP caching | — |

For Docker deployment instructions, see [DOCKER.md](DOCKER.md).

## Development

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p cloudillo

# Lint (matches CI strictness)
cargo clippy -- -D warnings

# Check formatting (uses hard tabs)
cargo fmt --check

# Apply formatting
cargo fmt
```

CI runs tests, formatting checks, and Clippy on every push and pull request.

## Project Status

Cloudillo is in **alpha**. The core platform is functional, but APIs may change and some features are still in development. Feedback, bug reports, and contributions are welcome.

## License

[LGPL-3.0-only](LICENSE)

## Links

- [Website](https://cloudillo.org)
- [GitHub](https://github.com/cloudillo/cloudillo-rs)
- [Issue Tracker](https://github.com/cloudillo/cloudillo-rs/issues)
