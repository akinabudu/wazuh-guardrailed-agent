#!/usr/bin/env bash
set -euo pipefail

plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${plugin_dir}/.." && pwd)"
wazuh_version="${WAZUH_VERSION:-4.9.2}"
dashboard_version="2.13.0"
rebuild=0

usage() {
  cat <<'USAGE'
Install or update Guardrailed AI in this project's Wazuh Dashboard.

Usage:
  ./dashboard-plugin/install.sh [--rebuild]

Options:
  --rebuild  Compile the plugin with the pinned Wazuh SDK before installing it.
  --help     Show this help.

Run ./setup.sh instead when installing the complete stack for the first time.
USAGE
}

while (( $# )); do
  case "$1" in
    --rebuild) rebuild=1 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

[[ $EUID -ne 0 ]] || {
  echo "Run this installer as a normal user with Docker access." >&2
  exit 1
}

if docker info >/dev/null 2>&1; then
  docker_cmd=(docker)
elif command -v sudo >/dev/null && sudo docker info >/dev/null 2>&1; then
  docker_cmd=(sudo docker)
else
  echo "Docker is unavailable. Run ./setup.sh for the first installation." >&2
  exit 1
fi

env_file="${project_dir}/.env"
wazuh_dir="${project_dir}/wazuh-docker/single-node"
archive="${plugin_dir}/wazuhGuardrail-${dashboard_version}.zip"
override="${project_dir}/deploy/wazuh-compose.override.yml"

[[ -f "${env_file}" ]] || {
  echo "Missing ${env_file}. Run ./setup.sh first." >&2
  exit 1
}
[[ -f "${wazuh_dir}/docker-compose.yml" ]] || {
  echo "Wazuh single-node files are missing. Run ./setup.sh first." >&2
  exit 1
}
[[ -f "${override}" ]] || {
  echo "Missing Wazuh Compose override: ${override}" >&2
  exit 1
}

if (( rebuild )); then
  echo "Building the plugin with OpenSearch Dashboards ${dashboard_version}..."
  "${plugin_dir}/build.sh"
  built_archive="${plugin_dir}/build/wazuhGuardrail-${dashboard_version}.zip"
  [[ -f "${built_archive}" ]] || {
    echo "The SDK build did not produce ${built_archive}." >&2
    exit 1
  }
  install -m 0644 "${built_archive}" "${archive}"
fi

[[ -f "${archive}" ]] || {
  echo "Missing plugin archive: ${archive}" >&2
  echo "Run this command again with --rebuild." >&2
  exit 1
}

set -a
# shellcheck disable=SC1090
. "${env_file}"
set +a

for variable in INDEXER_USER INDEXER_PASSWORD WAZUH_API_USER WAZUH_API_PASSWORD APP_SECRET; do
  [[ -n "${!variable:-}" ]] || {
    echo "${variable} is missing from .env." >&2
    exit 1
  }
done

echo "Building the persistent Wazuh Dashboard image..."
"${docker_cmd[@]}" build \
  --build-arg "WAZUH_VERSION=${wazuh_version}" \
  -t "guardrail-wazuh-dashboard:${wazuh_version}" \
  "${plugin_dir}"

if ! "${docker_cmd[@]}" inspect -f '{{.State.Running}}' guardrail-backend \
  2>/dev/null | grep -q '^true$'; then
  echo "Starting the Guardrailed AI backend..."
  "${docker_cmd[@]}" compose \
    --env-file "${env_file}" \
    -f "${project_dir}/docker-compose.yml" \
    up -d --build backend
fi

compose=("${docker_cmd[@]}" compose --env-file "${env_file}"
  -f "${wazuh_dir}/docker-compose.yml" -f "${override}")

echo "Installing the plugin and restarting only Wazuh Dashboard..."
"${compose[@]}" up -d --force-recreate wazuh.dashboard

dashboard_container="$("${compose[@]}" ps -q wazuh.dashboard)"
[[ -n "${dashboard_container}" ]] || {
  echo "Wazuh Dashboard did not start." >&2
  exit 1
}

ready=0
for _ in $(seq 1 60); do
  code="$(curl -k -sS -o /dev/null -w '%{http_code}' --max-time 3 \
    https://127.0.0.1/ 2>/dev/null || true)"
  if [[ "${code}" == "200" || "${code}" == "302" ]]; then
    ready=1
    break
  fi
  sleep 2
done
(( ready )) || {
  echo "Wazuh Dashboard did not become ready within 120 seconds." >&2
  exit 1
}

plugin_list="$("${docker_cmd[@]}" exec "${dashboard_container}" \
  /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin list)"
grep -q '^wazuhGuardrail@' <<<"${plugin_list}" || {
  echo "The dashboard started, but plugin verification failed." >&2
  exit 1
}

echo
echo "Guardrailed AI is installed."
echo "Open: https://127.0.0.1/app/wazuhGuardrail"
