For the separate AWS deployment, follow [AWS_RUNNER_SETUP.md](AWS_RUNNER_SETUP.md) and [BURP_SETUP.md](BURP_SETUP.md).

# Linux code runner and readiness tools

Streamlit now has **Readiness** and **Code & terminal** views. Existing chat, target management, and assessment tools remain available.

## DDoS readiness

The readiness form records owner-verified protection settings; unknown settings stay unknown. It does not infer protection from response headers. Download its review as JSON.

The optional availability sample sends at most five root GET requests, concurrency one, at most one per second, with a five-minute runtime cooldown. It stops on HTTP errors or a response slower than three seconds. This is a small availability sample, not a DDoS simulation or capacity test. Add separately approved lab/staging origins to owner configuration:

```dotenv
LOAD_TEST_ORIGINS=https://your-staging.example
```

Do not use multiple replicas to bypass the runtime cooldown. The cooldown is not persisted across restarts. Download sample results before a cloud restart.

## Ubuntu / WSL runner

Use a dedicated Ubuntu machine or VM with Docker Engine installed and resource limits supported. The runner service has permission to control Docker: keep it private, owner-only, and separate from sensitive workloads. Container isolation is not a full VM security boundary.

From the project root, on that machine:

```bash
docker build -t sentinel-tools:local runner
export RUNNER_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python runner/server.py
```

Keep the token for your Streamlit configuration. The service listens only on localhost port 8765. For Streamlit on the same machine:

```dotenv
RUNNER_URL=http://127.0.0.1:8765
RUNNER_TOKEN=your-generated-runner-token
```

For Streamlit Community Cloud, localhost refers to the cloud server, not your computer. Put this runner behind an HTTPS reverse proxy or authenticated HTTPS tunnel on your runner machine; then set RUNNER_URL to that HTTPS origin and RUNNER_TOKEN in Streamlit secrets. Configure the proxy to disable response buffering, allow streaming, and forward Authorization. Do not expose the Docker daemon or socket. The runner token is separate from APP_ACCESS_TOKEN. Never commit either token.

Each run uses a disposable sentinel-tools:local Linux container: no network, no host mounts or secrets, non-root UID, read-only filesystem, 16MB temporary storage, 128MB memory, 0.5 CPU, 64 processes, dropped capabilities, no-new-privileges. Defaults retain Docker seccomp. Maximum 15 seconds and 64KB output. Only one run at a time. A client disconnect triggers cleanup when the service detects it; the deadline also bounds work. No interactive stdin, persistent files, package installation, or external scanning is provided. Python, requests, Pillow, Bash, Nmap, curl, dig, and jq in the built image are available. Network access remains disabled in code cells. The model cannot invoke the runner automatically.

Termux is an Android terminal environment; it is not embedded in Streamlit. Use Ubuntu/WSL for this Docker runner. This update does not install or configure a remote machine for you.

## Verification

Automated tests validate command restrictions, runner-client URL validation, load-sample limits, and existing application flows. Actual Docker execution and a remote HTTPS streaming connection require verification on your runner machine. Start with `print('hello')` and `uname -a` in the interface.
