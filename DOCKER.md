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
  -v /var/vol/cloudillo:/data \
  -p 443:443 -p 80:80 \
  -e LOCAL_ADDRESS=1.2.3.4 \
  -e BASE_ID_TAG=agatha.example.com \
  -e BASE_APP_DOMAIN=agatha.example.com \
  -e BASE_PASSWORD=YourSecretPassword \
  -e ACME_EMAIL=user@example.com \
  cloudillo/cloudillo:latest
```

Mount a local directory to `/data` inside the container and expose ports 443 (HTTPS) and 80 (HTTP for ACME challenges).

> **Important:** For Let's Encrypt certificate issuance, ensure both `$BASE_APP_DOMAIN` and `cl-o.$BASE_ID_TAG` have DNS A or CNAME records pointing to `$LOCAL_ADDRESS` before starting the container.

### Docker Compose

```yaml
services:
  cloudillo:
    image: cloudillo/cloudillo:latest
    container_name: cloudillo
    volumes:
      - /var/vol/cloudillo:/data
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

## Proxy Mode

Use proxy mode when running Cloudillo behind a reverse proxy (nginx, Traefik, Caddy, etc.) that handles TLS termination.

```bash
docker run -d --name cloudillo \
  -v /var/vol/cloudillo:/data \
  -p 1443:1443 \
  -e MODE=proxy \
  -e LOCAL_ADDRESS=1.2.3.4 \
  -e BASE_ID_TAG=agatha.example.com \
  -e BASE_APP_DOMAIN=agatha.example.com \
  -e BASE_PASSWORD=YourSecretPassword \
  cloudillo/cloudillo:latest
```

In proxy mode, Cloudillo serves HTTP on port 1443. Configure your reverse proxy to handle TLS and forward requests.

### Nginx Configuration Example

```nginx
server {
    listen 80;
    server_name agatha.example.com cl-o.agatha.example.com;

    location /.well-known/ {
        root /var/www/certbot;
        autoindex off;
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

    location /.well-known/cloudillo/id-tag {
        add_header 'Access-Control-Allow-Origin' '*';
        return 200 '{"idTag":"agatha.example.com"}\n';
    }
    location /api/ {
        proxy_pass http://localhost:1443/;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $host;
        client_max_body_size 100M;
    }
    location /ws {
        proxy_pass http://localhost:1443;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
    }
    location / {
        # Serve the Cloudillo shell locally or proxy it
        root /home/agatha/cloudillo/shell;
        try_files $uri /index.html;
        autoindex off;
        expires 0;
    }
}
```

## Configuration Reference

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MODE` | Server mode: `standalone`, `proxy`, or `stream-proxy` | `standalone` |
| `LISTEN` | HTTPS bind address | `0.0.0.0:443` |
| `LISTEN_HTTP` | HTTP bind address (for ACME challenges in standalone mode) | - |
| `LOCAL_ADDRESS` | Comma-separated IP addresses this node serves | - |
| `BASE_ID_TAG` | ID tag for the initial admin user (**required**) | - |
| `BASE_APP_DOMAIN` | App domain for the admin user | Same as `BASE_ID_TAG` |
| `BASE_PASSWORD` | Password for the initial admin user | - |
| `ACME_EMAIL` | Email for Let's Encrypt registration | - |
| `DATA_DIR` | Blob storage directory | `/data` |
| `DB_DIR` | Database directory (SQLite + redb) | `/data` |
| `PRIVATE_DATA_DIR` | Private data directory | `/data/priv` |
| `PUBLIC_DATA_DIR` | Public data directory | `/data/pub` |
| `DIST_DIR` | Frontend distribution directory | `/dist` |
| `RUST_LOG` | Logging level: `trace`, `debug`, `info`, `warn`, `error` | `info` |
| `DISABLE_CACHE` | Disable caching (set to any value to enable) | - |

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

Mount a volume to `/data` to persist:
- SQLite databases (authentication, metadata)
- Blob storage (uploaded files)
- CRDT documents (collaborative editing data)
- RTDB databases (real-time database)

Example:
```bash
-v /var/vol/cloudillo:/data
```

## Container Permissions

The Cloudillo container runs as a non-root user for security:

| Property | Value |
|----------|-------|
| Username | `cloudillo` |
| UID | `10001` |
| GID | `10001` |

**Important:** The data directory must be writable by this user. Set the correct ownership before starting the container:

```bash
sudo mkdir -p /var/vol/cloudillo
sudo chown -R 10001:10001 /var/vol/cloudillo
```

If you need a different UID/GID (e.g., to match an existing user), rebuild the image with custom build arguments:

```bash
docker build --build-arg UID=1000 --build-arg GID=1000 -t cloudillo/cloudillo:custom .
```

## Getting Help

- Documentation: [cloudillo.org/docs](https://cloudillo.org/docs)
- GitHub: [github.com/cloudillo](https://github.com/cloudillo)
- Community: [Discord](https://discord.com/invite/u7gPdYjNjC)
