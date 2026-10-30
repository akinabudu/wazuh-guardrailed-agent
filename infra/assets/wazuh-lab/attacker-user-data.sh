#!/bin/bash
# wazuh-lab attacker: the source address for emulated SSH and HTTP attacks and
# for injection payloads carried in attacker-controlled fields. No Wazuh agent.
set -euo pipefail
exec > >(tee -a /var/log/lab-setup.log) 2>&1
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q curl openssh-client
touch /var/lib/lab-setup.done
echo "lab-setup done $(date -Is)"
