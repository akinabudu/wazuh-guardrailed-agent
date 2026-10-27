#!/usr/bin/env bash
#
# setup.sh - Setup for the Guardrailed Agentic AI Framework for Threat
#            Hunting and Human-Supervised Remediation in Wazuh.
#
# Tuned for a modest 16 GB RAM cloud instance without a GPU (the evaluation
# used an AWS EC2 t3.xlarge). The language model is Claude on Amazon Bedrock,
# called with the instance's IAM role; the only other outbound traffic is the
# optional Telegram notification.
#
# On 16 GB, RAM is the binding constraint. This script therefore:
#   - caps the Wazuh indexer heap hard
#   - keeps the Wazuh dashboard lean and installs the native agent plugin
#   - creates a swap file as a safety net
# For real comfort, split Wazuh onto a second machine (see README).
#
# Steps:
#   1. Prereqs, resource checks, and swap
#   2. Docker + Compose
#   3. Kernel tuning for the Wazuh indexer
#   4. Environment + secrets
#   5. Wazuh single-node with the native dashboard plugin
#   6. Language model: Bedrock check, or Ollama + a small model
#   7. Verify the packaged Wazuh Dashboard plugin
#   8. App tier via docker compose (postgres + backend)
#   9. Health checks + next steps
#
# Usage:  chmod +x setup.sh && ./setup.sh   (./setup.sh --help for options)
#
set -euo pipefail

# --------------------------------------------------------------------------
# Configuration (override via env before running)
# --------------------------------------------------------------------------
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_VERSION="${WAZUH_VERSION:-4.9.2}"
WAZUH_DASHBOARD_VERSION="2.13.0"
LLM_PROVIDER="${LLM_PROVIDER:-bedrock}"     # bedrock, or ollama for a self-hosted model
OLLAMA_MODEL="${OLLAMA_MODEL:-phi4-mini}"   # used only with ollama; ~2.5 GB on CPU
WAZUH_AGENT_BIND="${WAZUH_AGENT_BIND:-127.0.0.1}"  # address agents enrol on (1514/1515)
INDEXER_HEAP="${INDEXER_HEAP:-}"             # auto-set from RAM below
MIN_RAM_GB="${MIN_RAM_GB:-8}"
SWAP_GB="${SWAP_GB:-8}"
POSTGRES_USER="${POSTGRES_USER:-agent}"
POSTGRES_DB="${POSTGRES_DB:-guardrail}"
WAZUH_CREDENTIALS_MARKER="${PROJECT_DIR}/.wazuh-credentials-synced"

# --------------------------------------------------------------------------
c_reset="\033[0m"; c_blue="\033[1;34m"; c_green="\033[1;32m"
c_yellow="\033[1;33m"; c_red="\033[1;31m"
log()  { echo -e "${c_blue}[*]${c_reset} $*"; }
ok()   { echo -e "${c_green}[+]${c_reset} $*"; }
warn() { echo -e "${c_yellow}[!]${c_reset} $*"; }
err()  { echo -e "${c_red}[x]${c_reset} $*" >&2; }
die()  { err "$*"; exit 1; }
step() { echo -e "\n${c_blue}=== $* ===${c_reset}"; }

[[ "${1:-}" == "--help" ]] && { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# --------------------------------------------------------------------------
# Step 1 - Prereqs, resources, swap
# --------------------------------------------------------------------------
step "Step 1/9  Prerequisites, resources, and swap"

[[ $EUID -eq 0 ]] && die "Do not run as root. Run as a normal user with sudo rights."
command -v sudo >/dev/null || die "sudo is required."

if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  log "OS: ${PRETTY_NAME}"
  [[ "${ID:-}" =~ ^(ubuntu|debian)$ ]] || warn "Targets Ubuntu/Debian; other distros may need tweaks."
fi

ram_gb=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 / 1024 ))
log "Total RAM: ${ram_gb} GB"
(( ram_gb < MIN_RAM_GB )) && die "Under ${MIN_RAM_GB} GB RAM - this stack will not run. Split Wazuh onto another host."

# Pick indexer heap from available RAM
if [[ -z "${INDEXER_HEAP}" ]]; then
  if   (( ram_gb <= 16 )); then INDEXER_HEAP="1g"
  elif (( ram_gb <  24 )); then INDEXER_HEAP="2g"
  else                          INDEXER_HEAP="4g"
  fi
fi
LOW_RAM=0
(( ram_gb < 24 )) && LOW_RAM=1
(( LOW_RAM == 1 )) && warn "Low-RAM mode: indexer heap ${INDEXER_HEAP}."

# Swap safety net (crucial on 16 GB)
swap_kb=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
swap_gb=$(( swap_kb / 1024 / 1024 ))
if (( ram_gb < 20 )) && (( swap_gb < 4 )); then
  if [[ ! -f /swapfile ]]; then
    log "Creating ${SWAP_GB} GB swap file (safety net for a 16 GB box)..."
    sudo fallocate -l "${SWAP_GB}G" /swapfile 2>/dev/null || \
      sudo dd if=/dev/zero of=/swapfile bs=1M count=$((SWAP_GB*1024)) status=none
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile >/dev/null
    sudo swapon /swapfile
    grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
    ok "Swap enabled (${SWAP_GB} GB)."
  else
    ok "Swap file already present."
  fi
else
  ok "Swap sufficient (${swap_gb} GB) or plenty of RAM."
fi

disk_gb=$(df -BG --output=avail "${PROJECT_DIR}" | tail -1 | tr -dc '0-9')
log "Free disk: ${disk_gb} GB"
(( disk_gb < 25 )) && warn "Under 25 GB free; images + model + indices may not fit."
ok "Prerequisite checks complete."

# --------------------------------------------------------------------------
# Step 2 - Docker
# --------------------------------------------------------------------------
step "Step 2/9  Installing Docker"
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  ok "Docker and Compose already installed."
else
  log "Installing Docker Engine + Compose plugin..."
  sudo apt-get update -qq
  sudo apt-get install -y -qq ca-certificates curl gnupg git openssl
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null || true
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  # shellcheck disable=SC1091
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -qq
  sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
  sudo usermod -aG docker "$USER" || true
  warn "Added you to 'docker' group. If the next docker command fails, run: newgrp docker (or re-login) and re-run."
  ok "Docker installed."
fi
sudo apt-get install -y -qq git openssl curl >/dev/null 2>&1 || true

if docker info >/dev/null 2>&1; then
  DOCKER=(docker)
elif sudo docker info >/dev/null 2>&1; then
  DOCKER=(sudo docker)
else
  die "Docker is installed but its service is unavailable."
fi

# --------------------------------------------------------------------------
# Step 3 - Kernel tuning
# --------------------------------------------------------------------------
step "Step 3/9  Tuning kernel for Wazuh indexer"
current_map=$(sysctl -n vm.max_map_count)
if (( current_map < 262144 )); then
  echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-wazuh.conf >/dev/null
  sudo sysctl -q -w vm.max_map_count=262144
  ok "Set vm.max_map_count=262144."
else
  ok "vm.max_map_count already sufficient."
fi

# --------------------------------------------------------------------------
# Step 4 - Env + secrets
# --------------------------------------------------------------------------
step "Step 4/9  Environment and secrets"
ENV_FILE="${PROJECT_DIR}/.env"
gen() { openssl rand -hex 24; }
gen_wazuh() { printf 'Wz1!%s' "$(openssl rand -hex 20)"; }
if [[ ! -f "${ENV_FILE}" ]]; then
  cp "${PROJECT_DIR}/.env.example" "${ENV_FILE}"
  sed -i "s|__POSTGRES_PASSWORD__|$(gen)|" "${ENV_FILE}"
  sed -i "s|__WAZUH_API_PASSWORD__|$(gen_wazuh)|" "${ENV_FILE}"
  sed -i "s|__INDEXER_PASSWORD__|$(gen_wazuh)|"   "${ENV_FILE}"
  sed -i "s|__APP_SECRET__|$(gen)|"         "${ENV_FILE}"
  sed -i "s|__POSTGRES_USER__|${POSTGRES_USER}|" "${ENV_FILE}"
  sed -i "s|__POSTGRES_DB__|${POSTGRES_DB}|"     "${ENV_FILE}"
  sed -i "s|^LLM_PROVIDER=.*|LLM_PROVIDER=${LLM_PROVIDER}|" "${ENV_FILE}"
  sed -i "s|^OLLAMA_MODEL=.*|OLLAMA_MODEL=${OLLAMA_MODEL}|" "${ENV_FILE}"
  sed -i "s|^WAZUH_AGENT_BIND=.*|WAZUH_AGENT_BIND=${WAZUH_AGENT_BIND}|" "${ENV_FILE}"
  ok "Wrote ${ENV_FILE} (secret; git-ignored)."
  warn "Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env for alerts (optional)."
else
  ok ".env already exists; leaving it untouched."
  if [[ ! -f "${WAZUH_CREDENTIALS_MARKER}" ]]; then
    log "Rotating unsynchronised Wazuh credentials before first managed setup."
    sed -i "s|^WAZUH_API_PASSWORD=.*|WAZUH_API_PASSWORD=$(gen_wazuh)|" "${ENV_FILE}"
    sed -i "s|^INDEXER_PASSWORD=.*|INDEXER_PASSWORD=$(gen_wazuh)|" "${ENV_FILE}"
  fi
fi
set -a
# shellcheck disable=SC1090
. "${ENV_FILE}"
set +a

# --------------------------------------------------------------------------
# Step 5 - Wazuh
# --------------------------------------------------------------------------
step "Step 5/9  Deploying Wazuh (single-node)"
[[ "${WAZUH_VERSION}" == "4.9.2" ]] || \
  die "The dashboard plugin currently targets Wazuh 4.9.2."
plugin_archive="${PROJECT_DIR}/dashboard-plugin/wazuhGuardrail-${WAZUH_DASHBOARD_VERSION}.zip"
[[ -f "${plugin_archive}" ]] || die "Dashboard plugin archive is missing."
log "Building the Wazuh dashboard image with the guardrail plugin."
"${DOCKER[@]}" build \
  --build-arg "WAZUH_VERSION=${WAZUH_VERSION}" \
  -t "guardrail-wazuh-dashboard:${WAZUH_VERSION}" \
  "${PROJECT_DIR}/dashboard-plugin"
WAZUH_DIR="${PROJECT_DIR}/wazuh-docker"
if [[ ! -d "${WAZUH_DIR}" ]]; then
  log "Fetching Wazuh single-node deployment (v${WAZUH_VERSION})..."
  git clone --depth 1 --branch "v${WAZUH_VERSION}" \
    https://github.com/wazuh/wazuh-docker.git "${WAZUH_DIR}"
fi
cd "${WAZUH_DIR}/single-node"
WAZUH_COMPOSE=("${DOCKER[@]}" compose --env-file "${ENV_FILE}"
  -f docker-compose.yml -f "${PROJECT_DIR}/deploy/wazuh-compose.override.yml")
if grep -q "OPENSEARCH_JAVA_OPTS" docker-compose.yml; then
  sed -i "s|OPENSEARCH_JAVA_OPTS=.*|OPENSEARCH_JAVA_OPTS=-Xms${INDEXER_HEAP} -Xmx${INDEXER_HEAP}\"|" docker-compose.yml || true
  log "Indexer heap set to ${INDEXER_HEAP}."
fi
dashboard_config_state="$(python3 - config/wazuh_dashboard/wazuh.yml <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
original = path.read_text()
lines = []
for line in original.splitlines():
    indent = line[: len(line) - len(line.lstrip())]
    key = line.strip().split(":", 1)[0]
    if key == "username":
        line = f"{indent}username: {os.environ['WAZUH_API_USER']}"
    elif key == "password":
        line = f"{indent}password: {os.environ['WAZUH_API_PASSWORD']}"
    elif key == "run_as":
        line = f"{indent}run_as: true"
    lines.append(line)
updated = "\n".join(lines) + "\n"
if updated != original:
    path.write_text(updated)
print("changed" if updated != original else "current")
PY
)"
if ! sudo find config/wazuh_indexer_ssl_certs -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
  log "Generating indexer certificates (one-time)..."
  "${DOCKER[@]}" compose --project-name wazuh-certs \
    -f generate-indexer-certs.yml run --rm generator
fi
if [[ ! -f "${WAZUH_CREDENTIALS_MARKER}" ]]; then
  log "Hashing the private indexer credential for Wazuh."
  indexer_hash="$(printf '%s\n' "${INDEXER_PASSWORD}" | \
    "${DOCKER[@]}" run --rm -i "wazuh/wazuh-indexer:${WAZUH_VERSION}" \
    bash -c 'IFS= read -r HASH_PASSWORD; export HASH_PASSWORD; \
      exec /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh \
      -env HASH_PASSWORD' \
    2>/dev/null | tail -1)"
  [[ "${indexer_hash}" == \$2* ]] || die "Wazuh indexer password hashing failed."
  sed -i "/^admin:/,/^[^[:space:]]/ \
    s|^\([[:space:]]*hash:[[:space:]]*\).*|\1\"${indexer_hash}\"|" \
    config/wazuh_indexer/internal_users.yml
fi
log "Starting Wazuh (first run pulls images; be patient)..."
if [[ ! -f "${WAZUH_CREDENTIALS_MARKER}" ]]; then
  "${WAZUH_COMPOSE[@]}" up -d --force-recreate
else
  "${WAZUH_COMPOSE[@]}" up -d
  if [[ "${dashboard_config_state}" == "changed" ]]; then
    "${WAZUH_COMPOSE[@]}" up -d --force-recreate wazuh.dashboard
  fi
fi
for _ in $(seq 1 60); do
  code="$(curl -k -sS -o /dev/null -w '%{http_code}' \
    --max-time 5 "${WAZUH_INDEXER_URL%/}/" 2>/dev/null || true)"
  [[ "${code}" != "000" ]] && break
  sleep 2
done
[[ "${code}" != "000" ]] || die "Wazuh indexer did not start within 120 seconds."
if [[ ! -f "${WAZUH_CREDENTIALS_MARKER}" ]]; then
  log "Applying the synchronized indexer credential."
  indexer_container="$("${WAZUH_COMPOSE[@]}" ps -q wazuh.indexer)"
  # shellcheck disable=SC2016
  "${DOCKER[@]}" exec "${indexer_container}" bash -c \
    'export CONFIG_DIR=/usr/share/wazuh-indexer JAVA_HOME=/usr/share/wazuh-indexer/jdk; bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd "$CONFIG_DIR/opensearch-security/" -nhnv -cacert "$CONFIG_DIR/certs/root-ca.pem" -cert "$CONFIG_DIR/certs/admin.pem" -key "$CONFIG_DIR/certs/admin-key.pem" -p 9200 -icl' \
    >/dev/null
  "${WAZUH_COMPOSE[@]}" up -d --force-recreate wazuh.manager
fi
manager_code="000"
indexer_code="000"
for _ in $(seq 1 60); do
  manager_code="$(curl -k -sS -o /dev/null -w '%{http_code}' --max-time 5 \
    --user "${WAZUH_API_USER}:${WAZUH_API_PASSWORD}" -X POST \
    "${WAZUH_URL%/}/security/user/authenticate?raw=true" 2>/dev/null || true)"
  indexer_code="$(curl -k -sS -o /dev/null -w '%{http_code}' --max-time 5 \
    --user "${INDEXER_USER}:${INDEXER_PASSWORD}" \
    "${WAZUH_INDEXER_URL%/}/" 2>/dev/null || true)"
  [[ "${manager_code}" == "200" && "${indexer_code}" == "200" ]] && break
  sleep 2
done
[[ "${manager_code}" == "200" ]] || die "Wazuh manager credential check failed."
[[ "${indexer_code}" == "200" ]] || die "Wazuh indexer credential check failed."
touch "${WAZUH_CREDENTIALS_MARKER}"
chmod 600 "${WAZUH_CREDENTIALS_MARKER}"
ok "Wazuh credentials synchronized and verified."
ok "Wazuh started."
cd "${PROJECT_DIR}"

# --------------------------------------------------------------------------
# Step 6 - Language model
# --------------------------------------------------------------------------
step "Step 6/9  Language model (${LLM_PROVIDER})"
if [[ "${LLM_PROVIDER}" == "bedrock" ]]; then
  # The backend signs Bedrock calls with the instance's IAM role, read from the
  # instance metadata service; there is nothing to install here.
  bedrock_model="${BEDROCK_MODEL:-us.anthropic.claude-opus-4-6-v1}"
  imds_token="$(curl -fsS --max-time 2 -X PUT http://169.254.169.254/latest/api/token \
    -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null || true)"
  if [[ -n "${imds_token}" ]] && curl -fsS --max-time 2 -H "X-aws-ec2-metadata-token: ${imds_token}" \
      http://169.254.169.254/latest/meta-data/iam/security-credentials/ >/dev/null 2>&1; then
    ok "Instance IAM role found. It must allow bedrock:InvokeModel on ${bedrock_model}."
  else
    warn "No instance IAM role found. Give the backend AWS credentials that may invoke ${bedrock_model}."
  fi
elif [[ "${LLM_PROVIDER}" == "ollama" ]]; then
  command -v ollama >/dev/null || { log "Installing Ollama..."; curl -fsSL https://ollama.com/install.sh | sh; }
  docker_gateway="$("${DOCKER[@]}" network inspect bridge \
    --format '{{(index .IPAM.Config 0).Gateway}}')"
  [[ -n "${docker_gateway}" ]] || die "Could not resolve the Docker bridge address."
  sudo mkdir -p /etc/systemd/system/ollama.service.d
  # It binds to the Docker bridge, so it must start after Docker, and be
  # enabled so it comes back after a reboot.
  printf '[Unit]\nAfter=docker.service\nWants=docker.service\n\n[Service]\nEnvironment="OLLAMA_HOST=%s:11434"\n' \
    "${docker_gateway}" | sudo tee /etc/systemd/system/ollama.service.d/guardrail.conf >/dev/null
  sudo systemctl daemon-reload
  sudo systemctl enable ollama
  sudo systemctl restart ollama
  ollama_url="http://${docker_gateway}:11434"
  for _ in $(seq 1 30); do
    curl -fsS --max-time 2 "${ollama_url}/api/tags" >/dev/null 2>&1 && break
    sleep 2
  done
  curl -fsS --max-time 2 "${ollama_url}/api/tags" >/dev/null 2>&1 || \
    die "Ollama did not start within 60 seconds."
  log "Pulling '${OLLAMA_MODEL}' (small, CPU-friendly)..."
  OLLAMA_HOST="${ollama_url}" ollama pull "${OLLAMA_MODEL}"
  ok "Model ready on the private Docker bridge. On CPU expect a few tokens/sec."
else
  die "LLM_PROVIDER must be bedrock or ollama, not '${LLM_PROVIDER}'."
fi

# --------------------------------------------------------------------------
# Step 7 - Wazuh Dashboard plugin
# --------------------------------------------------------------------------
step "Step 7/9  Verifying the Wazuh Dashboard plugin"
plugin_list="$("${DOCKER[@]}" run --rm --entrypoint \
  /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin \
  "guardrail-wazuh-dashboard:${WAZUH_VERSION}" list)"
grep -q '^wazuhGuardrail@' <<<"${plugin_list}" || \
  die "Dashboard plugin image verification failed."
ok "Wazuh Dashboard plugin packaged for the installed release."

# --------------------------------------------------------------------------
# Step 8 - App tier via docker compose (postgres + backend)
# --------------------------------------------------------------------------
step "Step 8/9  Building and starting the app tier"
log "docker compose up -d --build  (first backend build may take a few minutes)..."
"${DOCKER[@]}" compose up -d --build --remove-orphans
ok "App tier up: postgres and backend (:8000)."

# --------------------------------------------------------------------------
# Step 9 - Health checks
# --------------------------------------------------------------------------
step "Step 9/9  Health checks"
log "Waiting for the backend to answer /health..."
backend_healthy=0
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
    backend_healthy=1
    ok "Backend healthy."
    break
  fi
  sleep 2
done
(( backend_healthy == 1 )) || die "Backend failed its health check."
dashboard_healthy=0
for _ in $(seq 1 30); do
  dashboard_code="$(curl -ksS -o /dev/null -w '%{http_code}' \
    https://127.0.0.1/ 2>/dev/null || true)"
  if [[ "${dashboard_code}" == "200" || "${dashboard_code}" == "302" ]]; then
    dashboard_healthy=1
    break
  fi
  sleep 2
done
(( dashboard_healthy == 1 )) || die "Dashboard failed its health check."
ok "Dashboard healthy."

cat <<EOF

Setup complete
--------------
Dashboard :  https://127.0.0.1 (open Guardrailed AI after login)
Backend   :  http://127.0.0.1:8000/health
Wazuh API :  https://127.0.0.1:55000

Everyday commands
-----------------
  docker compose up -d --build      # start / rebuild the app tier
  docker compose down               # stop the app tier
  docker compose logs -f backend    # watch backend logs
  cd wazuh-docker/single-node && docker compose down   # stop Wazuh when idle

16 GB survival tips
-------------------
  - Stop Wazuh when you are not testing; it is the biggest memory user.
  - The ${SWAP_GB} GB swap file cushions spikes but swap is slow - expect
    sluggishness if everything runs at once. Prefer running Wazuh OR a heavy
    hunt at a time, not both under load.
  - For real comfort, put Wazuh on a second cheap box and point WAZUH_URL /
    WAZUH_INDEXER_URL in .env at it.

Security reminders
------------------
  - Rotate the generated Wazuh and application credentials periodically.
  - Keep .env secret. Approvals happen only in the dashboard, never Telegram.
  - Telegram alerts stay off until TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are set.
  - Wazuh Dashboard authentication and RBAC protect every analyst action.
  - Review backend/guardrails.py - it is the safety control.
EOF
ok "All done."
