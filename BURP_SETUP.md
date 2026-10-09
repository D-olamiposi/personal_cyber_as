# Burp Suite on the separate EC2 desktop

Burp Community/Professional is a graphical desktop application. This setup adds an Ubuntu XFCE desktop accessed privately from Windows Remote Desktop. It does not embed Burp into Streamlit or implement a Burp API adapter. Community is available without a Professional license; Professional requires your license. Download the appropriate current edition from PortSwigger.

## 1. Prepare the desktop on EC2

From the project root on Ubuntu 24.04:

```bash
sudo bash runner/setup-burp-desktop.sh
sudo passwd burp-user
sudo ss -ltnp | grep 3389
```

Confirm the listener is **127.0.0.1:3389**, not 0.0.0.0. Set a strong private password for the separate `burp-user`. This account is not in the Docker group and is not the container runner user. Do not add it to sudo/docker groups.

## 2. Private desktop connection from your laptop

With SSH port 22 restricted to your IP, run this in Windows PowerShell (replace the key path and EC2 address):

```powershell
ssh -i "C:\path\to\your-key.pem" -N -L 13389:127.0.0.1:3389 ubuntu@YOUR_EC2_PUBLIC_ADDRESS
```

Leave that terminal open. Launch **Remote Desktop Connection** on Windows, connect to `127.0.0.1:13389`, and log in as `burp-user` with the desktop password. Choose the Xorg session if prompted. The Linux desktop runs on EC2; your laptop displays it. Desktop streaming consumes your mobile/internet data.

If you already have Systems Manager configured, AWS CLI and the Session Manager plugin offer an alternative tunnel:

```bash
aws ssm start-session --target YOUR_INSTANCE_ID --document-name AWS-StartPortForwardingSession --parameters '{"portNumber":["3389"],"localPortNumber":["13389"]}'
```

Use a shell compatible with the example's quoting (WSL/Bash). This needs appropriate IAM permissions, SSM Agent connectivity, and the local Session Manager plugin. It is an alternative to SSH, not required by this package.

## 3. Download and install Burp

On PortSwigger's official release page, obtain the native **Linux x64** installer for the chosen edition. The native installer manages its bundled Java runtime. Do not rely on a guessed version/download URL.

To download using EC2's connection, copy the official installer download URL, then run in the EC2 desktop terminal:

```bash
curl --fail --location 'PASTE_THE_OFFICIAL_PORTSWIGGER_INSTALLER_URL' -o "$HOME/burp-installer.sh"
sh "$HOME/burp-installer.sh"
```

Follow the installer as `burp-user`, choosing a writable directory under that user's home. Do not run the downloaded installer as root. Launch Burp from its installed application shortcut/executable. Accept licensing prompts and use your Professional license only if applicable. The installer and embedded browser may need additional OS libraries; follow PortSwigger's current documentation if dependencies are reported missing.

## 4. Use the remote browser

In Burp, open **Proxy → Open browser** and browse an authorized target. Configure Burp's target scope explicitly. Keep proxy listeners on loopback. No inbound security-group rule for port 8080 is needed when using the browser on EC2. Do not publish the RDP or interception proxy ports.

Community supports manual proxy-based assessment; this setup does not give it Professional scanning features. It does not automatically relay browser traffic, control Burp from the LLM, or ingest Burp output into the knowledge base. Export sanitized results separately if you want to review them with the assistant.

## Resource and verification notes

PortSwigger lists two CPU cores and 4GB RAM as a minimum for basic use; the desktop and runner also consume resources. Avoid simultaneous heavy workloads on a small instance. Installation and desktop functionality need testing on your actual EC2 machine; neither was deployed here.

Official references:
- https://portswigger.net/burp/documentation/desktop/getting-started/download-and-install
- https://portswigger.net/burp/documentation/desktop/getting-started/system-requirements
- https://manpages.ubuntu.com/manpages/jammy/man5/xrdp.ini.5.html
