#!/usr/bin/env bash
# Run a shell command on the deployment host over SSM and print its output.
#
#     ./scripts/ssm.sh 'cd /home/ubuntu/wazuh-guardrailed-agent && git status -sb'
#     ./scripts/ssm.sh --timeout 1800 './dashboard-plugin/install.sh --rebuild'
#
# The host is a SPOT instance, so it is addressed by instance ID, never by IP.
# Commands run as root in / - cd to the repo yourself.
set -euo pipefail

profile="${AWS_PROFILE:-orglobal}"
region="${AWS_REGION:-us-east-1}"
instance="${WAZUH_INSTANCE_ID:-i-028474aa41eca073b}"
timeout=600

while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) timeout="$2"; shift 2 ;;
    --instance) instance="$2"; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) break ;;
  esac
done

[[ $# -ge 1 ]] || { echo "usage: $0 [--timeout SECONDS] '<command>'" >&2; exit 2; }

# Embed the command as a single JSON string argument.
payload="$(python -c 'import json,sys; print(json.dumps({"commands":[sys.argv[1]]}))' "$1")"

command_id="$(aws ssm send-command \
  --profile "${profile}" --region "${region}" \
  --instance-ids "${instance}" \
  --document-name AWS-RunShellScript \
  --timeout-seconds "${timeout}" \
  --cli-input-json "{\"Parameters\": $(echo "${payload}" | python -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))')}" \
  --query Command.CommandId --output text)"

echo "CommandId: ${command_id}" >&2

deadline=$(( SECONDS + timeout ))
status=Pending
while (( SECONDS < deadline )); do
  sleep 5
  status="$(aws ssm get-command-invocation \
    --profile "${profile}" --region "${region}" \
    --command-id "${command_id}" --instance-id "${instance}" \
    --query Status --output text 2>/dev/null || echo Pending)"
  case "${status}" in
    Success|Failed|Cancelled|TimedOut) break ;;
  esac
done

aws ssm get-command-invocation \
  --profile "${profile}" --region "${region}" \
  --command-id "${command_id}" --instance-id "${instance}" \
  --query StandardOutputContent --output text

err="$(aws ssm get-command-invocation \
  --profile "${profile}" --region "${region}" \
  --command-id "${command_id}" --instance-id "${instance}" \
  --query StandardErrorContent --output text)"
[[ -n "${err}" && "${err}" != "None" ]] && printf '%s\n' "--- stderr ---" "${err}" >&2

echo "Status: ${status}" >&2
[[ "${status}" == "Success" ]]
