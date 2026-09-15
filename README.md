# CertWatch_ACME

A TLS/SSL certificate monitoring and automated renewal web application built with Flask, MySQL, and ACME v2 (Pebble test CA).

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (v20.10+)
- [Docker Compose](https://docs.docker.com/compose/install/) (v2.0+)

No Python installation required on the host — everything runs inside containers.

---

## Quick Start

```bash
# Build and start all services
docker compose up --build -d

# Verify all containers are running
docker compose ps
```

The app is available at **http://localhost:5000**.

Default login credentials:
- **Username:** `admin`
- **Password:** `admin123`

---

## Docker Compose Commands

### Starting and Stopping

| Command | Description |
|---|---|
| `docker compose up -d` | Start all containers in the background (detached mode) |
| `docker compose up --build -d` | Rebuild images and start all containers in the background |
| `docker compose up` | Start all containers in the foreground (logs stream to terminal) |
| `docker compose down` | Stop and remove all containers, networks |
| `docker compose down -v` | Stop and remove all containers, networks, **and volumes** (deletes all data) |
| `docker compose stop` | Stop all containers without removing them |
| `docker compose start` | Start stopped containers without rebuilding |
| `docker compose restart` | Restart all running containers |

### Building

| Command | Description |
|---|---|
| `docker compose build` | Build the web image without starting containers |
| `docker compose build --no-cache` | Build from scratch — no Docker layer caching, downloads everything fresh |
| `docker compose up --build` | Build and immediately start containers |
| `docker compose up --build --no-cache -d` | Full fresh rebuild + start in background |

### Viewing Logs

| Command | Description |
|---|---|
| `docker compose logs` | View logs from all containers |
| `docker compose logs -f` | Follow (tail) logs from all containers |
| `docker compose logs web` | View logs from the web container only |
| `docker compose logs -f web` | Follow logs from the web container only |
| `docker compose logs db` | View logs from the MySQL container only |
| `docker compose logs pebble` | View logs from the Pebble CA container only |

### Inspecting Containers

| Command | Description |
|---|---|
| `docker compose ps` | List all containers and their status |
| `docker compose exec web bash` | Open a shell inside the running web container |
| `docker compose exec db mysql -u certwatch -pcertwatch certwatch` | Open a MySQL shell inside the database container |
| `docker compose exec web pip list` | List installed Python packages inside the web container |

### Removing Everything

| Command | Description |
|---|---|
| `docker compose down` | Remove containers and networks (data volumes preserved) |
| `docker compose down -v` | Remove containers, networks, **and all data volumes** |
| `docker compose down --rmi all` | Remove containers, networks, **and all built images** |
| `docker compose down -v --rmi all` | Remove everything — containers, networks, images, and volumes |

---

## Common Workflows

### First-Time Setup

```bash
git clone <repo-url>
cd CertWatch_ACME
docker compose up --build -d
docker compose ps
# Open http://localhost:5000
```

### After Code Changes

```bash
docker compose up --build -d
```

### After Dependency Changes (requirements.txt)

```bash
docker compose build --no-cache
docker compose up -d
```

### Full Clean Rebuild (nuclear option)

```bash
docker compose down -v --rmi all
docker compose up --build -d
```

### Viewing Real-Time Logs During Development

```bash
docker compose up --build
```

(Runs in foreground — Ctrl+C to stop)

---

## Services

| Service | Container | Image | Port | Purpose |
|---|---|---|---|---|
| `web` | certwatch-web | Built from Dockerfile | `5000` | Flask application |
| `db` | certwatch-db | mysql:8.4 | `3307` (host) / `3306` (internal) | MySQL database |
| `pebble` | certwatch-pebble | ghcr.io/letsencrypt/pebble:2.10.0 | `14000`, `15000` | ACME test CA |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `certwatch-demo-secret` | Flask secret key for sessions |
| `DATABASE_URL` | `mysql+pymysql://certwatch:certwatch@db:3306/certwatch` | SQLAlchemy database URI |
| `CERT_EXPIRY_WARNING_DAYS` | `30` | Days before expiry to flag a certificate |
| `ACME_DIRECTORY_URL` | `https://pebble:14000/dir` | ACME directory endpoint |
| `ACME_EMAIL` | `certwatch@example.invalid` | Email for ACME account registration |
| `ACME_CA_CERT` | `/app/pebble.minica.pem` | Path to Pebble root CA certificate |
| `ACME_STORAGE` | `/app/data/acme` | Path to store ACME account keys |

---

## Volumes

| Volume | Purpose |
|---|---|
| `certwatch_mysql` | MySQL database data persistence |
| `certwatch_acme` | ACME account keys and metadata |
| `certwatch_certs` | Downloaded/renewed certificates |