# Sentinel — Personal Cybersecurity Assistant

A local, single-owner Flask assistant connected to the knowledge base, with Markdown chat, image understanding, provider fallbacks and bounded assessment tools. No live targets have been assessed as part of building this package.

## Start on WSL / Linux / macOS
Python 3.12 is recommended.

```bash
cd personal-cyber-assistant
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r chatbot/requirements.txt
cp chatbot/.env.example chatbot/.env
cp chatbot/config/scopes.example.json chatbot/config/scopes.json
python knowledge_base/scripts/kb.py build
```

Edit `chatbot/.env` locally and add your API keys. Start the server:

```bash
python chatbot/run.py
```

Open **http://127.0.0.1:5000**. Keep the terminal running. No Flask debug mode or reloader is enabled.

## Windows PowerShell

```powershell
cd personal-cyber-assistant
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r chatbot/requirements.txt
Copy-Item chatbot/.env.example chatbot/.env
Copy-Item chatbot/config/scopes.example.json chatbot/config/scopes.json
python knowledge_base/scripts/kb.py build
python chatbot/run.py
```

If your activation policy prevents the script running, use `.\.venv\Scripts\python.exe` directly for the Python commands instead of changing system policy.

## Model setup

Configuration and credentials stay on the server. Edit `.env`, then restart.

| Route | Primary | Fallbacks |
| --- | --- | --- |
| Text chat and tool planning | Groq `GROQ_CHAT_MODEL` | Groq `GROQ_FALLBACK_MODEL`, then xAI `XAI_CHAT_MODEL` |
| Image understanding | xAI `XAI_VISION_MODEL` | Groq `GROQ_VISION_MODEL` |

The example model IDs were checked against provider documentation on 2026-09-30. Your account must actually have access. Groq vision's configured Qwen model is documented as a preview model and may change. Use your provider account's current supported IDs if a model is unavailable. You can customize `config/providers.json` by copying `providers.example.json` and changing the ordered entries. Entries without both a key and a model ID are skipped.

For text chat, start by adding `GROQ_API_KEY`. For the requested primary-and-fallback image chain, add **both** `XAI_API_KEY` and `GROQ_API_KEY` and verify the corresponding vision model IDs. Without both provider configurations, the app cannot offer both image routes. Fallbacks handle transport/API/malformed-response failures; a completed refusal is not retried on another provider. Prompts and processed images may be sent to a fallback provider. Review content before sending it; do not paste credentials.

No API keys were available during development. Provider request construction, routing and failure handling were tested using controlled fixtures, not billed live requests. The UI indicates missing configuration. It never substitutes fake model output.

Provider documentation:
- https://console.groq.com/docs/openai
- https://console.groq.com/docs/models
- https://console.groq.com/docs/vision
- https://docs.x.ai/developers/models
- https://docs.x.ai/developers/rest-api-reference/inference/chat-completions

## Chat interface

- Markdown, tables, lists, fenced code and syntax highlighting.
- Copy buttons above messages and code blocks; paste text with the button or keyboard.
- Up to three PNG/JPEG/WebP images per request, maximum 8 MB each and 20 megapixels. Pasted clipboard images are supported where the browser supplies them.
- Original images stay in private runtime storage. Models receive a resized JPEG with metadata removed; images are not added to the knowledge corpus.
- Saved conversations, JSON export, background jobs, progress events, cancellation and downloadable evidence.
- Enter sends; Shift+Enter adds a newline.
- Check **Allow scoped tools for this message** to permit the text model to choose available tools within configured scope and fixed budgets.
- Vision chat is read-only: it does not automatically call tools. Use the Assessment tools panel for a separate authorized check.

The local JS libraries are bundled with their licence files and exact versions/hashes in `chatbot/static/vendor/manifest.json`. The browser loads no third-party scripts or fonts. Model-supplied Markdown is sanitized; model-supplied images, forms and scripts are removed.

## Supported execution adapters

| Adapter | Actual behavior | Needs |
| --- | --- | --- |
| Knowledge search | Retrieves local passages with provenance | Built knowledge index |
| HTTPS headers & TLS | One verified HTTPS root-page GET; selected headers and informational observations | Exact approved HTTPS origin |
| DNS lookup | Resolves an approved origin; no infrastructure scanning | Exact approved HTTPS origin |
| Nmap | TCP connect scan of 1..16 separately approved ports on one literal IP | Installed Nmap and exact approved IP |
| Image metadata | Image dimensions, format and hashes | Image attached to the request |

These tools can also be run manually through **Assessment tools**, without a model key. The other tools from your original list remain catalogued knowledge targets; they do **not** yet have executable integrations. This package does not claim a comprehensive vulnerability assessment engine or full coverage of every cybersecurity discipline.

Nmap command construction, cancellation and XML parsing were tested using a controlled process fixture. Nmap is not installed in the development environment, so a real Nmap binary run remains to be verified on your machine. Install it separately; on Ubuntu/WSL:

```bash
sudo apt update
sudo apt install nmap
nmap --version
```

Use a disposable owned lab target to verify it before operational assessments. For Windows, install the official Nmap distribution and ensure `nmap` is available on PATH.

## Configure target scope

Use **Manage targets** in the header to add or remove an approved website origin or separately approved Nmap IP. Changes take effect immediately and are saved privately in `chatbot/runtime/managed-scopes.json` (or your configured data directory). Finish or cancel active jobs before changing targets. The model cannot add targets. On first startup, `chatbot/config/scopes.json` supplies initial targets; after the first UI change, the saved runtime configuration takes precedence. Keep runtime files when upgrading to preserve targets and conversations. Initial targets depend on your configuration file. An example web assessment configuration is:

```json
{
  "web_origins": ["https://nikky-luxe.vercel.app"],
  "nmap_targets": [],
  "nmap_ports": [80, 443]
}
```

This example is not enabled in the archive. HTTPS origins must match exactly; wildcards, credentials, paths, query strings and non-443 ports are rejected. Web tools refuse nonpublic DNS answers, pin the validated IP when connecting and never follow redirects. A headers check cannot verify that SSRF, broken authorization or other application vulnerabilities are absent.

Approve Nmap infrastructure IPs independently. Owning an application on Vercel does not grant authority to scan other services on Vercel's shared IPs. Nmap accepts literal IPs only: no domains, ranges, user-provided flags, scripts, version probes, brute-force or exploitation. It uses fixed slow-rate settings, a host timeout and a local process timeout. No shell is involved.

Agent jobs have at most four model rounds and six tool calls. Jobs are limited to two active workers and eight queued/active jobs, with one job per conversation. Cancellation is cooperative: a provider or DNS/HTTP operation already in progress can finish before the cancellation boundary; completed network activity cannot be undone. Nmap subprocesses are terminated on cancellation. Evidence from completed tool calls persists even when a later step fails or is cancelled. Jobs interrupted by server restart are marked interrupted and never silently resumed.

## Local access and data

Default binding is `127.0.0.1`; unconfigured-token mode accepts loopback clients only and validates trusted hostnames. CSRF protections apply to mutation routes. To protect local access too, set a long random `APP_ACCESS_TOKEN` in `.env`; enter it on the sign-in dialog. Never put the token in a URL.

For remote use, configure an HTTPS reverse proxy, a 24+ character owner token, exact `APP_TRUSTED_HOSTS` and `APP_COOKIE_SECURE=true`. Remote binding or a nonlocal trusted hostname is rejected without these settings. The proxy must preserve the correct Host and Origin and provide the HTTPS deployment correctly. This archive has not been deployed or tested with a remote proxy.

Private runtime state lives in `chatbot/runtime/` by default: conversations, job logs, upload originals/previews, evidence and a session secret. It is not part of the public static directory and is excluded from the archive. API responses carrying private data are not cacheable. Back up this directory privately if you need to retain history; deleting it resets local state. Run one application process; distributed workers and multi-user roles are not implemented.

## Knowledge coverage

The bundled corpus remains **16 documents / 20 passages**: original project notes and tool inventory, not full vendor manuals. References are preserved in each retrieved passage. Retrieval currently uses SQLite FTS5 BM25, not semantic embeddings or the hybrid reranking pipeline used in AgroFlow. Deeper documentation ingestion and retrieval-quality evaluation remain important before relying on specialized answers.

```bash
python knowledge_base/scripts/kb.py import /absolute/path/manual.md --title "My manual" --origin "https://example.org/manual" --license "permission recorded by owner"
python knowledge_base/scripts/kb.py build
```

Stop the chatbot before rebuilding the index. See `knowledge_base/COLLECTION_GUIDE.md` for source quality and reuse checks. There is no autonomous internet crawler in this package.

## Verification

```bash
python -m unittest discover -s knowledge_base/tests -v
python -m unittest discover -s chatbot/tests -v
```

See `chatbot/TEST_REPORT.md` for verified behavior and remaining integration checks. This is functioning application code with bounded adapters; it is not a claim of zero defects or complete cybersecurity expertise.

## Evidence hashes

Each recorded evidence card displays the backend SHA-256 of the exact JSON download bytes, its evidence ID, timestamp, and tool name. Use **Copy SHA-256** or **Verify download** to compare the download with the saved digest. Verification requires a secure browser context (HTTPS or localhost). The hash is external to the JSON file to avoid a self-referential digest. A matching hash establishes byte consistency with the stored record, not that the assessment is complete or its conclusions correct.

## Updating an existing installation

Stop the app and copy the updated `chatbot/app/tools.py`, `chatbot/app/web.py`, `chatbot/app/engine.py`, `chatbot/static/app.js`, `chatbot/static/app.css`, and `chatbot/templates/index.html` into your project. Keep your existing `.env`, provider configuration, `scopes.json`, and `chatbot/runtime/`. The uploaded Groq SDK transport fix is retained. Install requirements, restart once for the code update, and refresh the browser. Subsequent target changes do not need a restart.
