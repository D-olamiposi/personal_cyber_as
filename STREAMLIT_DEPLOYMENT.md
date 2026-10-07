# Run Sentinel with Streamlit

The Streamlit interface imports the existing Python engine directly. Flask remains available as an alternative; do not run both interfaces against the same runtime directory at once. This is a single-owner workspace, not a multi-user service. Authenticated browser sessions belong to the same owner and can access the same conversations, targets, and evidence.

## Run in Codespaces or locally

From the repository root:

```bash
python -m pip install -r requirements.txt
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy the generated value into `APP_ACCESS_TOKEN` in `chatbot/.env`. Keep your existing provider API keys and model settings. This Streamlit interface requires an owner token even for local development. Then run:

```bash
python -m streamlit run streamlit_app.py --server.address 0.0.0.0 --server.port 8501
```

In Codespaces, open port 8501 in the Ports tab and keep it private. Enter your owner token in the app. Streamlit handles its own server and XSRF protection; Flask `APP_HOST`, trusted-host and cookie settings do not control this interface.

## Deploy to Streamlit Community Cloud

1. Merge the archive contents into your existing GitHub project. Keep `streamlit_app.py`, root `requirements.txt`, `.streamlit/config.toml`, the `chatbot` modules/configuration, and `knowledge_base` sources and index at the repository root. Do not add a second outer folder.
2. Keep `.env`, `.streamlit/secrets.toml`, virtual environments, and `chatbot/runtime/` out of Git. The example secrets file is safe to commit because it contains no credentials.
3. Open https://share.streamlit.io/ and select **Create app**. Choose your repository and branch; set the main file to **streamlit_app.py**.
4. In **Advanced settings**, choose Python 3.12 and paste the contents of `.streamlit/secrets.example.toml` into **Secrets**, replacing the owner-token placeholder and provider keys with your real values. TOML uses quoted strings, unlike `.env` syntax. Model IDs must be available to your account; unused provider keys can stay empty.
5. Deploy and open the app. Enter your owner token, open Manage targets, and add an approved origin. Run a local knowledge search first, then an HTTPS check or chat. API-provider costs and quotas are separate from hosting.

No cloud deployment has been performed as part of delivering this archive. Streamlit account access, provider access, outbound connectivity and hosted resource usage require verification on your deployment.

## Interface features

- Native chat with Markdown tables, highlighted fenced code, and built-in code-copy controls. The Copy message expander presents the full original Markdown in a copyable code widget. Raw HTML is not enabled.
- Validated PNG/JPEG/WebP uploads; up to three images, 8 MB each, with resized metadata-stripped model previews. Remove pending uploads using the uploader controls. Browser clipboard image pasting is not implemented in this native Streamlit interface; upload screenshots as files.
- Primary/fallback text and vision provider chains are unchanged. Only currently attached images are sent for visual analysis.
- Manage targets applies changes without restarting and stores them in private runtime state. Scope changes are blocked during pending jobs.
- Background jobs, live progress via a Streamlit fragment, cancellation, conversation export, evidence download and exact-byte SHA-256 verification. Provider/DNS requests already underway may finish before cancellation.

## Community Cloud execution and storage

Nmap execution is disabled by default in Streamlit. Knowledge search, approved HTTPS/DNS checks and image metadata remain available. Other tools in the catalog do not gain executable integrations by changing frontend.

For a self-hosted Streamlit process with Nmap installed and separately approved infrastructure, set `STREAMLIT_ENABLE_NMAP=true`. The existing bounded port and target rules still apply. Enabling that flag alone does not install Nmap or guarantee hosted privileges, policy compatibility or networking. No Nmap installation is included in the default Community Cloud dependencies.

Runtime SQLite, uploads, targets, and evidence use local disk. They are not a durable cloud database and may be lost on redeployment, reset, or infrastructure replacement. Export important chats and evidence, and keep initial website targets in your Git configuration if you want them available again after a reset. Do not rely on Community Cloud as an always-running task worker: hibernation/restarts can interrupt jobs; interrupted jobs are not silently resumed. Durable external storage is not implemented in this conversion.

The knowledge corpus remains 16 introductory documents with SQLite FTS5 retrieval. This conversion does not add full cybersecurity manuals or semantic embeddings. API-backed models keep local memory use lower than hosting the LLM itself.

## Existing installation

Keep your `chatbot/.env` and runtime folder when merging the update. The Groq SDK correction, target manager and hash display are retained. Stop Flask before starting Streamlit. To return to Flask, stop Streamlit, install `chatbot/requirements.txt`, and run `python chatbot/run.py`.

## References

- https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app
- https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/secrets-management
- https://docs.streamlit.io/develop/api-reference/execution-flow/st.fragment
- https://docs.streamlit.io/deploy/streamlit-community-cloud/manage-your-app

## Local verification

```bash
python -m unittest discover -s chatbot/tests -q
python -m unittest discover -s knowledge_base/tests -q
python tests/streamlit_smoke.py
```

The Streamlit smoke script uses a temporary runtime and test owner token; it does not call model providers or scan websites. Backend tests additionally need Flask installed from `chatbot/requirements.txt`.
