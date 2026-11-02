#!/usr/bin/env bash
set -euo pipefail

plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# DOCKER_CMD lets setup.sh pass "sudo docker" before group membership applies.
${DOCKER_CMD:-docker} run --rm --platform linux/amd64 \
  -v "${plugin_dir}:/home/node/kbn/plugins/wazuh_guardrail" \
  -w /home/node/kbn/plugins/wazuh_guardrail \
  quay.io/wazuh/osd-dev:2.19.6 \
  bash -lc 'yarn install --frozen-lockfile && yarn build'
