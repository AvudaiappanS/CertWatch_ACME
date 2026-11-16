# Deploying CertWatch Lab on the Ubuntu 24.04 VPS

Target server: Ubuntu Server 24.04, 2 vCPU, 2 GB RAM, 30 GB SSD.
Domain: certwatchlab.in (see GODADDY_DNS.md first - DNS must point at the VPS
before Let's Encrypt can validate HTTP-01).

## 1. Connect and prepare the server

```bash
ssh <user>@<VPS_PUBLIC_IP>
sudo apt update && sudo apt -y upgrade
```

## 2. Install Docker + Compose plugin

```bash
sudo apt install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER && newgrp docker
```

## 3. Firewall (UFW)

```bash
sudo apt install -y ufw
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp        # HTTP-01 challenges + the app (until TLS is fronted)
sudo ufw enable
```

## 4. Get the code and configure

```bash
mkdir -p ~/apps && cd ~/apps
# either upload the ZIP (scp CertWatch_Lab.zip <user>@<VPS_PUBLIC_IP>:apps/)
# and:  sudo apt install -y unzip && unzip CertWatch_Lab.zip
# or:   git clone <your-repo-url> CertWatch_Lab
cd CertWatch_Lab
cp .env.example .env
nano .env
```

Minimum edits for the first boot:

```
SECRET_KEY=<output of: openssl rand -hex 32>
ADMIN_PASSWORD=<a strong password you will change after first login>
ACME_MODE=pebble          # or staging once DNS is live
ACME_EMAIL=<your real email>
ALERT_TEST_MODE=true      # keep until SMTP is configured
```

## 5. Start

```bash
docker compose up -d --build
docker compose ps                 # web + scheduler, health should be ok
curl -fsS http://127.0.0.1/health
```

Open http://certwatchlab.in (or http://<VPS_PUBLIC_IP>) and log in.

## 6. Optional: Pebble test CA on the VPS

```bash
docker compose --profile pebble up -d
```

## 7. Verify

- Log in as admin -> dashboard shows the scheduler jobs within ~1 minute.
- Scan `certwatchlab.in` and `example.com` from the dashboard.
- Run a CT scan for `certwatchlab.in`.
- Settings page shows the effective configuration.

## Notes for the 2 GB VPS

- Gunicorn runs 2 sync workers; the scheduler runs in its own container so
  jobs never run twice.
- Compose caps memory: web 512 MB, scheduler 384 MB, pebble 512 MB.
- Leave at least ~1 GB free disk; logs: `docker compose logs -f web`.
