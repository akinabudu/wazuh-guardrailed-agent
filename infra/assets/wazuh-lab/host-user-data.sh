#!/bin/bash
# wazuh-lab host: Wazuh 4.14.9 + guardrailed agent, provisioned by the repo's
# own setup.sh. Runs once, on first boot. Progress: /var/log/lab-setup.log;
# /var/lib/lab-setup.done appears when setup.sh has finished.
set -euo pipefail
exec > >(tee -a /var/log/lab-setup.log) 2>&1
echo "lab-setup start $(date -Is)"

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q git jq python3-venv sysstat
snap install aws-cli --classic

imds_token=$(curl -sS -X PUT http://169.254.169.254/latest/api/token \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
private_ip=$(curl -sS -H "X-aws-ec2-metadata-token: $imds_token" \
  http://169.254.169.254/latest/meta-data/local-ipv4)
mac=$(curl -sS -H "X-aws-ec2-metadata-token: $imds_token" \
  http://169.254.169.254/latest/meta-data/mac)
vpc_cidr=$(curl -sS -H "X-aws-ec2-metadata-token: $imds_token" \
  "http://169.254.169.254/latest/meta-data/network/interfaces/macs/$mac/vpc-ipv4-cidr-block")
# The VPC resolver sits at the network base address + 2.
dns_ip=$(python3 -c "import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1])[2])" "$vpc_cidr")

repo=/home/ubuntu/wazuh-guardrailed-agent
if [ ! -d "$repo" ]; then
  sudo -u ubuntu git clone --branch __REPO_BRANCH__ __REPO_URL__ "$repo"
fi

# setup.sh refuses root. WAZUH_AGENT_BIND opens enrolment on the private
# address only; the security group limits it to the lab endpoint.
# PROTECTED_NETWORKS: block_ip and isolate_host may never target the manager
# itself or the VPC resolver.
sudo -iu ubuntu bash -lc "cd $repo && WAZUH_AGENT_BIND=$private_ip PROTECTED_NETWORKS=$private_ip/32,$dns_ip/32 ./setup.sh"

touch /var/lib/lab-setup.done
echo "lab-setup done $(date -Is)"
