#!/usr/bin/env bash
# Capture the environment evidence for Section 4.1 (Table 4.1) and Section 4.5.
# Run on the lab host as root:  ./collect_env.sh results/<date>/env
set -uo pipefail
out="${1:?usage: $0 <out-dir>}"
mkdir -p "$out"
repo="$(cd "$(dirname "$0")/.." && pwd)"
run() { local name="$1"; shift; { echo "\$ $*"; "$@"; } > "$out/$name.txt" 2>&1; }

run uname        uname -a
run os-release   cat /etc/os-release
run lscpu        lscpu
run memory       free -h
run disk         df -h /
run swap         swapon --show
run docker       docker version
run compose      docker compose version
run containers   docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'
run wazuh        docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control info
run agents       docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
run ollama       ollama --version
run model        ollama show phi4-mini
run model-params ollama show phi4-mini --parameters
run pip-freeze   docker exec guardrail-backend pip freeze
run postgres     docker exec guardrail-postgres postgres --version
run pgvector     docker exec guardrail-postgres sh -c 'psql -At -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT extversion FROM pg_extension WHERE extname = '"'"'vector'"'"'"'
run git          git -C "$repo" log -1 --format='%H %cI %s'
run sampling     grep -E '^(OLLAMA_MODEL|OLLAMA_TEMPERATURE|OLLAMA_SEED|CROWN_JEWEL_ASSETS|AUTO_ACTION_RATE_LIMIT)=' "$repo/.env"
run backend-log  docker logs --tail 300 guardrail-backend
run dashboard-log docker logs --tail 300 single-node-wazuh.dashboard-1
run setup-log    tail -n 200 /var/log/lab-setup.log
echo "wrote $out"
