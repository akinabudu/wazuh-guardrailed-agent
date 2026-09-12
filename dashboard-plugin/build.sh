#!/usr/bin/env bash
set -euo pipefail

plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker run --rm --platform linux/amd64 \
  -v "${plugin_dir}:/home/node/kbn/plugins/wazuh_guardrail" \
  -w /home/node/kbn/plugins/wazuh_guardrail \
  quay.io/wazuh/osd-dev:2.13.0 \
  bash -lc 'yarn install --frozen-lockfile && yarn build'
