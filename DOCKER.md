# Cloudillo - Self-Hosted Collaboration Platform

**Your Data, Your Rules**

## What is Cloudillo?

Online collaboration platforms typically fall into two categories:

1. **Cloud-based services:** Convenient but may raise concerns about privacy, data ownership, and vendor lock-in.
2. **Self-hosted applications:** Flexible but challenging to set up and often don't integrate well with each other.

Cloudillo bridges this gap—a self-hosted, federated platform that combines the convenience of cloud services with complete control over your data.

Learn more at [cloudillo.org](https://cloudillo.org).

## Installation

Install Cloudillo using Docker. Choose between **standalone mode** (built-in TLS via Let's Encrypt) or **proxy mode** (bring your own TLS termination).

## Standalone Mode

Standalone mode handles TLS certificates automatically via Let's Encrypt.

### Quick Start

**Prerequisites:**
1. Configure DNS: Create A (or CNAME) records for both your domain and `cl-o.` subdomain pointing to your server's IP
2. Open ports: Ensure ports 443 and 80 are open in your firewall and forwarded in your router

Create the data directory with correct permissions:

```bash
sudo mkdir -p /var/vol/cloudillo
sudo chown -R 10001:10001 /var/vol/cloudillo
```

Start the container:

```bash
docker run -d --name cloudillo \
  -v /var/vol/cloudillo:/cloudillo/data \
  -p 443:443 -p 80:80 \
  -e LOCAL_ADDRESS=1.2.3.4 \
  -e BASE_ID_TAG=agatha.example.com \
  -e BASE_APP_DOMAIN=agatha.example.com \
  -e BASE_PASSWORD=YourSecretPassword \
  -e ACME_EMAIL=user@example.com \
  cloudillo/cloudillo:latest
```

Mount a local directory to `/cloudillo/data` inside the container and expose ports 443 (HTTPS) and 80 (HTTP for ACME challenges).

> **Important:** For Let's Encrypt certificate issuance, ensure both `$BASE_APP_DOMAIN` and `cl-o.$BASE_ID_TAG` have DNS A or CNAME records pointing to `$LOCAL_ADDRESS` before starting the container.

### Docker Compose

```yaml
services:
  cloudillo:
    # Pin the verified digest from cloudillo-X.Y.Z.image-digest.txt (see below), never :latest.
    image: cloudillo/cloudillo@sha256:<digest>
    container_name: cloudillo
    volumes:
      - /var/vol/cloudillo:/cloudillo/data
    ports:
      - "443:443"
      - "80:80"
    environment:
      LOCAL_ADDRESS: "1.2.3.4"
      BASE_ID_TAG: "agatha.example.com"
      BASE_APP_DOMAIN: "agatha.example.com"
      BASE_PASSWORD: "YourSecretPassword"
      ACME_EMAIL: "user@example.com"
```

`:latest` (and the moving `:X.Y`) are for trying Cloudillo out. In production, reference the
image by the digest of a verified release, as in the compose example above.

### Verifying a release

Every release `vX.Y.Z` of [cloudillo-rs](https://github.com/cloudillo/cloudillo-rs/releases) is
signed with the project's `cosign` key. Before installing or upgrading, download the release
assets and the public key
`https://raw.githubusercontent.com/cloudillo/cloudillo-rs/vX.Y.Z/cosign.pub`, and run these on an
administration host with `cosign`, `jq` and `sha256sum` (replace `X.Y.Z`):

```bash
# 1. The checksum file, then every asset
cosign verify-blob --key cosign.pub --bundle SHA256SUMS.sigstore.json SHA256SUMS
sha256sum -c SHA256SUMS

# 2. The image signature
DIGEST=$(cat cloudillo-X.Y.Z.image-digest.txt)
cosign verify --key cosign.pub "cloudillo/cloudillo@${DIGEST}"

# 3. The SBOM attestation, compared with the downloaded SBOM
cosign verify-attestation --key cosign.pub --type cyclonedx "cloudillo/cloudillo@${DIGEST}" \
  | jq -r '.payload' | head -n1 | base64 -d | jq '.predicate' > attested.cdx.json
diff <(jq -S . attested.cdx.json) <(jq -S . cloudillo-X.Y.Z.cdx.json)
```

Then put `cloudillo/cloudillo@${DIGEST}` in `compose.yaml`. If any step fails, do not install;
report it as described in [SECURITY.md](SECURITY.md).

## Proxy Mode

Two modes put Cloudillo behind a reverse proxy. Pick by who holds the certificates.

| Mode | TLS terminated by | Certificates | Client IP from |
|------|-------------------|--------------|----------------|
| `MODE=proxy` | the proxy | the proxy obtains them; Cloudillo runs no ACME | `X-Forwarded-For` |
| `MODE=stream-proxy` | Cloudillo | Cloudillo (ACME), as in standalone mode | PROXY protocol header |

### HTTP proxy (`MODE=proxy`)

Cloudillo serves **plain HTTP** on `LISTEN`. It starts no `LISTEN_HTTP` listener and does no ACME
work (`ACME_EMAIL` is ignored, and certificate renewal tasks left over from a standalone run are
skipped). The proxy terminates TLS and forwards every path with the original `Host` header.

```bash
docker run -d --name cloudillo \
  -v /var/vol/cloudillo:/cloudillo/data \
  -p 127.0.0.1:1443:1443 \
  -e MODE=proxy \
  -e LISTEN=0.0.0.0:1443 \
  -e LOCAL_ADDRESS=1.2.3.4 \
  -e BASE_ID_TAG=agatha.example.com \
  -e BASE_APP_DOMAIN=agatha.example.com \
  -e BASE_PASSWORD=YourSecretPassword \
  cloudillo/cloudillo:latest
```

The image defaults to `LISTEN=0.0.0.0:443`, so set it explicitly as above.

Every tenant needs a certificate for two names: `<id_tag>` (the app) and `cl-o.<id_tag>` (the
API). Tenants are created at runtime (registration, communities), so let the proxy obtain
certificates on demand and ask Cloudillo first:

`GET /.well-known/cloudillo/tenant?domain=<host>` answers `200` when `<host>` is `<id_tag>` or
`cl-o.<id_tag>` of a tenant on this server, or a custom app domain that has a certificate row on
this server (e.g. one issued in an earlier standalone run), else `404`. No auth, empty body.

> **Security:** In proxy mode Cloudillo takes the client IP from the `X-Forwarded-For` header (leftmost entry) for rate limiting and bans. Never expose port 1443 directly — publish it on `127.0.0.1` only — and make sure your proxy **replaces** a client-supplied `X-Forwarded-For` instead of appending to it. nginx does with `proxy_set_header X-Forwarded-For $remote_addr;` as shown below (not `$proxy_add_x_forwarded_for`). Caddy and Traefik drop client-supplied forwarded headers by default; keep it that way: don't list untrusted networks in Caddy's `trusted_proxies` or Traefik's `forwardedHeaders.trustedIPs`, and don't set `forwardedHeaders.insecure`.

#### Caddy (on-demand TLS)

```caddyfile
{
	email admin@example.com
	on_demand_tls {
		# Caddy appends ?domain=<host>; only hosts Cloudillo answers 200 for get a certificate.
		ask http://127.0.0.1:1443/.well-known/cloudillo/tenant
	}
}

https:// {
	tls {
		on_demand
	}
	reverse_proxy 127.0.0.1:1443
}
```

Caddy keeps the `Host` header, sets `X-Forwarded-For` from the client address and proxies
WebSockets without extra configuration.

#### nginx

nginx has no on-demand certificates; issue them with certbot for both names of each tenant.

```nginx
server {
    listen 80;
    server_name agatha.example.com cl-o.agatha.example.com;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name agatha.example.com cl-o.agatha.example.com;
    ssl_certificate /etc/letsencrypt/live/agatha.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/agatha.example.com/privkey.pem;
    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:1443;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}

# In the http block:
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

### TLS passthrough (`MODE=stream-proxy`)

Use this to share port 443 with other services while Cloudillo keeps its own certificates. The
proxy routes by SNI without decrypting and passes the client address in a PROXY protocol header;
`PROXY_PROTOCOL` lists the addresses allowed to connect (with Docker port publishing, the
connection arrives from the bridge gateway, hence `172.16.0.0/12`).

```bash
docker run -d --name cloudillo \
  -v /var/vol/cloudillo:/cloudillo/data \
  -p 127.0.0.1:1443:1443 \
  -p 127.0.0.1:1080:1080 \
  -e MODE=stream-proxy \
  -e PROXY_PROTOCOL=127.0.0.1,172.16.0.0/12 \
  -e LISTEN=0.0.0.0:1443 \
  -e LISTEN_HTTP=0.0.0.0:1080 \
  -e ACME_EMAIL=admin@example.com \
  -e LOCAL_ADDRESS=1.2.3.4 \
  -e BASE_ID_TAG=agatha.example.com \
  -e BASE_PASSWORD=YourSecretPassword \
  cloudillo/cloudillo:latest
```

```nginx
stream {
    # Cloudillo's names go to Cloudillo, everything else to the existing web server.
    map $ssl_preread_server_name $tls_backend {
        ~(^|\.)agatha\.example\.com$  cloudillo;
        default                        other_https;
    }
    upstream cloudillo   { server 127.0.0.1:1443; }
    upstream other_https { server 127.0.0.1:8443; }

    server {
        listen 443;
        ssl_preread on;
        proxy_pass $tls_backend;
        proxy_protocol on;
    }
}
```

`proxy_protocol on` here also reaches `other_https`; drop it there, or give that upstream its
own `server` block, if it does not expect the header. Cloudillo answers ACME HTTP-01 challenges
on `LISTEN_HTTP`, which takes no PROXY header: forward `/.well-known/acme-challenge/` on port 80
for Cloudillo's names to `http://127.0.0.1:1080` with an ordinary `http` block.

## Configuration Reference

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MODE` | Server mode: `standalone`, `proxy`, or `stream-proxy` | `standalone` |
| `PROXY_PROTOCOL` | Comma-separated IPs/CIDRs of the trusted proxies, e.g. `127.0.0.1,172.16.0.0/12`: only they may connect, and each connection must carry a PROXY protocol v1/v2 header (`stream-proxy` only; nginx `proxy_protocol on;`, HAProxy `send-proxy-v2`). Without it, `stream-proxy` sees the proxy's IP — forwarding headers are never trusted in that mode | - |
| `LISTEN` | HTTPS bind address (plain HTTP in proxy mode) | `0.0.0.0:443` in the image (`0.0.0.0:1443` outside it) |
| `LISTEN_HTTP` | HTTP bind address for ACME challenges; `none` disables it; not started in proxy mode | `0.0.0.0:80` in the image (`0.0.0.0:1080` outside it) |
| `LOCAL_ADDRESS` | Comma-separated IP addresses this node serves | - |
| `BASE_ID_TAG` | ID tag for the initial admin user (**required**) | - |
| `BASE_APP_DOMAIN` | App domain for the admin user | Same as `BASE_ID_TAG` |
| `BASE_PASSWORD` | Password for the initial admin user | - |
| `ACME_EMAIL` | Email for Let's Encrypt registration; ignored in proxy mode | - |
| `DATA_DIR` | Blob storage directory | `./data` (`/cloudillo/data` in the image) |
| `DB_DIR` | Database directory (SQLite + redb) | `./data` (`/cloudillo/data` in the image) |
| `BACKUP_DIR` | Backup snapshot directory (see [Backup and Restore](#backup-and-restore)) | `$DATA_DIR/backup` (`/cloudillo/data/backup` in the image) |
| `SECRET_KEY` | Key for encryption at rest: base64 of exactly 32 bytes, e.g. `openssl rand -base64 32`. Encrypts profile signing keys, TLS and proxy-site certificate keys, TOTP secrets, the JWT secret, the ACME account, IdP API keys and secret settings (SMTP password). The first start with a key encrypts existing plaintext; a wrong key, or encrypted data without a key, refuses to start. Never generated — back it up (see [Backup and Restore](#backup-and-restore)). Unset = no encryption at rest | - |
| `SECRET_KEY_FILE` | Path of a file holding `SECRET_KEY`, e.g. `/run/secrets/cloudillo_key`. Set only one of the two; prefer this one, as an environment variable is visible in `docker inspect` and `/proc/<pid>/environ` | - |
| `DIST_DIR` | Frontend distribution directory | `./dist` (`/cloudillo/dist` in the image) |
| `RUST_LOG` | Logging level: `trace`, `debug`, `info`, `warn`, `error` | `info` |
| `DISABLE_CACHE` | Disable caching (set to any value to enable) | - |
| `ENABLE_DNSSEC` | Validate DNSSEC on federation DNS lookups (set to any value). Requires an upstream resolver that passes DNSSEC records; Docker's embedded DNS `127.0.0.11` and many home routers don't | - |

### Cloudillo Identity System

If you're new to Cloudillo, here's how identities work:

- **ID Tag**: The unique identifier for a Cloudillo profile. It's a domain name associated with a user (e.g., `agatha.example.com`).
- **App Domain**: The domain users visit to access their Cloudillo shell. Usually the same as the ID tag.
- **API Domain**: Cloudillo API endpoints are served from the `cl-o` subdomain (e.g., `cl-o.agatha.example.com`).

### Required DNS Records

For Cloudillo to work, create these DNS records:

| Name | Type | Value | Purpose |
|------|------|-------|---------|
| `agatha.example.com` | A | `1.2.3.4` | App domain |
| `cl-o.agatha.example.com` | A | `1.2.3.4` | API domain |

Replace `agatha.example.com` with your actual domain and `1.2.3.4` with your server's IP address.
You can also use another domain for the app domain (in case you already run a
website on the same domain).

## Data Persistence

Mount a volume to `/cloudillo/data` to persist:
- SQLite databases (authentication, metadata)
- Blob storage (uploaded files)
- CRDT documents (collaborative editing data)
- RTDB databases (real-time database)

Example:
```bash
-v /var/vol/cloudillo:/cloudillo/data
```

## Backup and Restore

The server takes **online** snapshots of every store (SQLite, redb, blobs) while it runs; no
downtime. Each store's snapshot is consistent on its own, but the stores are snapshotted one
after another, not at a single point in time: a tenant created or purged during the run may be
half-present in a restore. Each snapshot is a directory `BACKUP_DIR/<yyyymmddThhmmssZ>/` with
`auth/`, `meta/`, `crdt/`, `rtdb/`, `blob/` and a `manifest.json` listing every file with its size and sha256.
A run in progress writes to `<name>.partial/`, so a directory without that suffix is complete.

`BACKUP_DIR` defaults to `$DATA_DIR/backup`, inside the data volume; the server sets it to mode
`0700`. To keep snapshots on another disk, mount a separate volume owned by `10001:10001` and
point `BACKUP_DIR` at it:

```bash
-v /var/vol/cloudillo-backup:/cloudillo/backup -e BACKUP_DIR=/cloudillo/backup
```

Blob snapshots hard-link the previous snapshot's blobs; keep each `BACKUP_DIR` on one filesystem.

Blobs are content-addressed and never change, so each snapshot hard-links the blobs it shares
with the previous one; daily snapshots only cost the new files.

**Schedule** (admin settings, server-wide):

| Setting | Meaning | Default |
|---------|---------|---------|
| `backup.time` | Daily run, UTC `HH:MM`; empty disables it. Read at startup — restart after changing it | empty |
| `backup.keep` | Snapshots to keep; older ones are deleted after each run | `7` |

**On demand:** `POST /api/admin/backup` starts a run (`202`, or `409` while one runs);
`GET /api/admin/backup` returns `{running, last: {at, ok, bytes, error?}, snapshots: [{name,
createdAt, bytes}]}`. Every run is recorded in the audit log as `admin.backup`.

**Off-site copy and encryption are your job.** Copy `BACKUP_DIR` elsewhere after the nightly
run, encrypted, e.g. with `restic backup /var/vol/cloudillo/backup` or `rsync -aH` to another
host (`-H` keeps the blob hard links). Skip `*.partial` directories.

**`SECRET_KEY`:** with a key set, snapshots hold the secrets only as ciphertext, and a restore
needs the same key. Store the key apart from `BACKUP_DIR` and the off-site copy (a password
manager, a secrets store), never next to them. Removing the key once data is encrypted is not
supported.

### Restore

Restore is **offline**: stop the server first. Run the image's binary with the `restore`
subcommand against the same volumes:

```bash
docker stop cloudillo
docker run --rm \
  -v /var/vol/cloudillo:/cloudillo/data \
  cloudillo/cloudillo:latest /usr/bin/cloudillo restore /cloudillo/data/backup/20261020T040000Z
docker start cloudillo
```

Usage: `cloudillo restore <snapshot-dir> [--force]`. It verifies every file against the manifest
(and changes nothing if one does not match), moves the current `DB_DIR/{auth,meta,crdt,rtdb}` and
`DATA_DIR/blob` aside to `*.pre-restore-<unix-time>`, and copies the snapshot in. Delete the
`*.pre-restore-*` directories once the restored server works. It refuses while a server holds
`DB_DIR/cloudillo.lock`, even with `--force`, which only allows a snapshot from a newer version.
Pass the same `DB_DIR`/`DATA_DIR` as the server if you changed them.

**Restore drill:** once a quarter, restore the latest off-site copy into a scratch machine or
volume and start a server on it. A backup that was never restored is not a backup. Use the
`SECRET_KEY` from where you store it, not from the running server: the drill proves you have it.

**Suspended tenants:** suspending (or expiring) a tenant refuses new logins, API-key exchanges
and access-token refreshes, but access tokens already issued stay valid for up to one hour.
A restore does not change that either way.

## Container Permissions

The Cloudillo container runs as a non-root user for security:

| Property | Value |
|----------|-------|
| Username | `cloudillo` |
| UID | `10001` |
| GID | `10001` |

**Important:** The data directory (and a separate backup directory, if you use one) must be writable by this user. Set the correct ownership before starting the container:

```bash
sudo mkdir -p /var/vol/cloudillo /var/vol/cloudillo-backup
sudo chown -R 10001:10001 /var/vol/cloudillo /var/vol/cloudillo-backup
```

If you need a different UID/GID (e.g., to match an existing user), rebuild the image with custom build arguments:

```bash
docker build --build-arg UID=1000 --build-arg GID=1000 -t cloudillo/cloudillo:custom .
```

## Getting Help

- Documentation: [cloudillo.org/docs](https://cloudillo.org/docs)
- GitHub: [github.com/cloudillo](https://github.com/cloudillo)
- Community: [Discord](https://discord.com/invite/u7gPdYjNjC)
