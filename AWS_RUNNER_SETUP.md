# Separate EC2 runner for Streamlit

These files prepare deployment; they do not create or launch an AWS instance. The model has no AWS credentials or automatic tool-install permissions.

## 1. Create the instance

In EC2 Launch instance, choose Ubuntu Server 24.04 LTS, **x86_64**, and a new instance separate from AgroFlow. For basic Burp usage, PortSwigger specifies at least two CPU cores and 4GB RAM; a t3.medium has that resource shape, but is not a promise of good performance with concurrent workloads. Choose adequate encrypted EBS storage (for example 25GB for the OS, desktop, and image), and check the AWS console's region-specific cost before launch. Keep Burp and runner usage sequential on a small machine. Ubuntu defaults to user `ubuntu` for SSH.

Create your key pair and download it privately. Allow SSH port 22 from your current public IP only. Allow ports 80 and 443 for the HTTPS proxy. Do not open 8765, 3389, 8080, or the Docker API. If using SSM instead, attach appropriate Systems Manager instance permissions and verify agent connectivity; SSH is the simpler path below.

Stop the instance when finished. Compute, EBS, public IPv4, and network pricing are separate; storage can still cost money when stopped. Credits expiring can lead to billed usage. No prices are hardcoded here.

## 2. Copy the project and install the runner

Upload/extract the provided ZIP onto EC2 (SCP or your repository). In its project root:

```bash
sudo bash runner/setup-ec2.sh
sudo systemctl status sentinel-runner --no-pager
```

The script targets a fresh Ubuntu 24.04 host. It installs Docker from Docker's Ubuntu repository, builds `sentinel-tools:local`, creates a service account, and installs a systemd runner bound to localhost:8765. The service account can control Docker and is trusted like a host administrator; do not share its token. Code containers do not receive that socket, host mounts, or tokens.

The image has Python, Bash, Nmap, curl, DNS utilities (`dig`), jq, requests, and Pillow. Installation occurs on the server during build. Inspect versions in the Streamlit terminal after connecting. The arbitrary-code container has **no network**; Nmap being installed does not enable target scans. Existing bounded assessment adapters remain separate; selecting a target in Streamlit does not automatically configure the Burp desktop's scope or the runner's shell network permissions.

## 3. Publish the runner through HTTPS

Use a DNS name you control pointing to the instance's public address. A stable address avoids DNS changes when stopping/starting, but check public IPv4 charges. If you have no domain, use an HTTPS tunnel service instead and forward it to localhost:8765; this requires separate provider setup and may change the endpoint on restart. Never use an unencrypted public HTTP endpoint for the token.

For a DNS name, edit `runner/nginx.conf.example`, replacing `runner.example.com` with your actual hostname, then:

```bash
sudo cp runner/nginx.conf.example /etc/nginx/sites-available/sentinel-runner
sudo ln -sf /etc/nginx/sites-available/sentinel-runner /etc/nginx/sites-enabled/sentinel-runner
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d YOUR_ACTUAL_RUNNER_HOSTNAME
```

Follow Certbot prompts to enable HTTPS and HTTP-to-HTTPS redirection. Ensure DNS is correct and ports 80/443 are reachable. Do not configure Streamlit before HTTPS works. Nginx is configured to stream output without buffering. The runner enforces bearer authentication on both health and execution endpoints.

## 4. Connect Streamlit

Privately display the generated token on EC2:

```bash
sudo cat /etc/sentinel-runner.env
```

Copy only its value into Streamlit **App settings → Secrets**, alongside your existing API and owner settings:

```toml
RUNNER_URL = "https://your-actual-runner-hostname"
RUNNER_TOKEN = "value-from-ec2"
```

Keep APP_ACCESS_TOKEN and RUNNER_TOKEN different. Do not commit `.env` or `.streamlit/secrets.toml`. The application does not need AWS access keys.

In **Code & terminal**, click **Check EC2 runner connection**, then run `print('hello from EC2')` in Python mode and `nmap --version` in shell mode. Health checks confirm connectivity and image presence, not successful execution or resource enforcement. Check the actual run output too.

## 5. Controlled packages

Add owner-reviewed Python packages to `runner/python-packages.txt` and Linux apt packages to `runner/Dockerfile`. Build the new image on EC2:

```bash
sudo docker build -t sentinel-tools:local runner
```

New runs use that image. Python/pip installation is not permitted inside an offline disposable cell. Installation downloads consume the EC2 server's connection; your connection carries interface traffic and output. AWS may bill network usage.

## 6. Burp

See BURP_SETUP.md for the optional desktop. Burp stays outside the code-cell sandbox and runs as a separate Linux user. Its desktop work is owner-operated and has network access; its activity is not automatically gated by the chatbot or recorded as chatbot assessment evidence.

## Verification and limitations

Automated local tests cover validation and interface navigation. Docker image build, EC2 provisioning, HTTPS issuance, remote streaming, desktop login, and Burp installation have not been executed in this workspace. No AWS resources were provisioned. Run only authorized assessments.

References:
- https://docs.docker.com/engine/install/ubuntu/
- https://portswigger.net/burp/documentation/desktop/getting-started/system-requirements
- https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-sessions-start.html
