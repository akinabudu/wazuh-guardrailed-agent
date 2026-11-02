#!/bin/bash
# wazuh-lab endpoint: the monitored Linux host. Wazuh agent 4.14.9 with auditd,
# realtime FIM on persistence paths, nginx and sshd as attacker-reachable log
# sources, and Atomic Red Team for adversary emulation. Runs once, on first
# boot. Progress: /var/log/lab-setup.log; /var/lib/lab-setup.done when done.
set -euo pipefail
exec > >(tee -a /var/log/lab-setup.log) 2>&1
echo "lab-setup start $(date -Is)"

manager_ip="__MANAGER_IP__"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q auditd nginx curl gnupg apt-transport-https wget git

# --- Wazuh agent -----------------------------------------------------------
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update -q
WAZUH_MANAGER="$manager_ip" WAZUH_AGENT_NAME="lab-linux-01" \
  apt-get install -y -q "wazuh-agent=__WAZUH_AGENT_VERSION__"
apt-mark hold wazuh-agent

# A second <ossec_config> block is merged with the packaged one.
mkdir -p /srv/drop
cat >> /var/ossec/etc/ossec.conf <<'EOF'
<ossec_config>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
  <syscheck>
    <directories realtime="yes">/etc/cron.d,/etc/crontab,/var/spool/cron</directories>
    <directories realtime="yes">/etc/systemd/system,/root/.ssh,/home</directories>
    <directories realtime="yes">/srv/drop</directories>
  </syscheck>
</ossec_config>
EOF

# Wazuh's recommended command-execution rules plus a read watch on shadow.
cat > /etc/audit/rules.d/wazuh.rules <<'EOF'
-a exit,always -F euid=0 -F arch=b64 -S execve -k audit-wazuh-c
-a exit,always -F euid=0 -F arch=b32 -S execve -k audit-wazuh-c
-w /etc/shadow -p r -k audit-wazuh-r
-w /etc/passwd -p wa -k audit-wazuh-w
EOF
augenrules --load
systemctl enable --now auditd

systemctl daemon-reload
systemctl enable --now wazuh-agent

# --- Atomic Red Team ------------------------------------------------------
# PowerShell from Microsoft's apt repo, Invoke-AtomicRedTeam from the
# PowerShell Gallery, and the atomics from a shallow clone of the upstream repo.
source /etc/os-release
wget -q "https://packages.microsoft.com/config/ubuntu/$VERSION_ID/packages-microsoft-prod.deb" \
  -O /tmp/packages-microsoft-prod.deb
dpkg -i /tmp/packages-microsoft-prod.deb
apt-get update -q
apt-get install -y -q powershell
pwsh -NoProfile -Command "Set-PSRepository PSGallery -InstallationPolicy Trusted; Install-Module invoke-atomicredteam,powershell-yaml -Scope AllUsers -Force"
git clone --depth 1 https://github.com/redcanaryco/atomic-red-team /opt/atomic-red-team

touch /var/lib/lab-setup.done
echo "lab-setup done $(date -Is)"
