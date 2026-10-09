#!/usr/bin/env bash
# Fresh Ubuntu 24.04 EC2 only. Run from this folder's project root with sudo.
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo 'Run: sudo bash runner/setup-ec2.sh'; exit 1; fi
source /etc/os-release
if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 24.04 ]]; then
  echo 'This script supports a fresh Ubuntu 24.04 EC2 instance.'; exit 1
fi
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
apt-get update
apt-get install -y ca-certificates curl python3 nginx certbot python3-certbot-nginx
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.sources <<DOCKER_REPO
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
DOCKER_REPO
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
id sentinel-runner >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin sentinel-runner
usermod -aG docker sentinel-runner
install -d -m 0755 /opt/sentinel-runner
install -m 0644 "$project_dir/runner/server.py" /opt/sentinel-runner/server.py
docker build -t sentinel-tools:local "$project_dir/runner"
if [[ ! -f /etc/sentinel-runner.env ]]; then
  (umask 077; python3 - <<'PY' > /etc/sentinel-runner.env
import secrets
print('RUNNER_TOKEN='+secrets.token_urlsafe(32))
PY
  )
fi
install -m 0644 "$project_dir/runner/sentinel-runner.service" /etc/systemd/system/sentinel-runner.service
systemctl daemon-reload
systemctl enable --now sentinel-runner
systemctl restart sentinel-runner
echo 'Runner installed on localhost:8765. Finish HTTPS configuration in AWS_RUNNER_SETUP.md.'
echo 'Runner token saved in /etc/sentinel-runner.env (not printed).'
