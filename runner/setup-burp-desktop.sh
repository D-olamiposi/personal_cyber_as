#!/usr/bin/env bash
# Optional owner-operated GUI desktop on fresh Ubuntu 24.04. No public RDP listener.
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo 'Run: sudo bash runner/setup-burp-desktop.sh'; exit 1; fi
source /etc/os-release
if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 24.04 ]]; then
  echo 'Use Ubuntu 24.04 for this script.'; exit 1
fi
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y xfce4 xfce4-terminal xrdp xorgxrdp dbus-x11
id burp-user >/dev/null 2>&1 || useradd -m -s /bin/bash burp-user
printf 'exec startxfce4\n' > /home/burp-user/.xsession
chown burp-user:burp-user /home/burp-user/.xsession
# Change only the global listener, preserving session-specific port settings.
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/xrdp/xrdp.ini')
lines=p.read_text().splitlines(); section=''; changed=False
for i,line in enumerate(lines):
    if line.strip().startswith('['):section=line.strip()
    if section=='[Globals]' and line.strip().startswith('port='):
        lines[i]='port=tcp://127.0.0.1:3389';changed=True
if not changed:raise SystemExit('Could not find global xrdp port; inspect configuration before continuing')
p.write_text('\n'.join(lines)+'\n')
PY
usermod -aG ssl-cert xrdp
systemctl enable --now xrdp
systemctl restart xrdp
echo 'Set a desktop password: sudo passwd burp-user'
echo 'Connect through SSH/SSM forwarding only. Install Burp via its official native Linux installer in the desktop.'
