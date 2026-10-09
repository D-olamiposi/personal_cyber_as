"""Single-owner Streamlit interface; calls the Python engine directly."""
import atexit
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

from dotenv import load_dotenv
import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "chatbot"))
from app.config import Settings
from app.engine import Engine
from app.providers import ModelRouter
from app.retrieval import Retriever
from app.store import Store
from app.tools import ToolRunner
from app.uploads import ImageUploads

st.set_page_config(page_title="Sentinel", page_icon="🛡️", layout="wide")
load_dotenv(ROOT / "chatbot/.env")
try:
    for name in ("APP_ACCESS_TOKEN", "GROQ_API_KEY", "XAI_API_KEY", "GROQ_CHAT_MODEL", "GROQ_FALLBACK_MODEL", "GROQ_VISION_MODEL", "XAI_CHAT_MODEL", "XAI_VISION_MODEL", "APP_DATA_DIR", "SCOPES_FILE", "PROVIDERS_FILE", "STREAMLIT_ENABLE_NMAP", "RUNNER_URL", "RUNNER_TOKEN", "LOAD_TEST_ORIGINS"):
        if name in st.secrets:
            value = st.secrets[name]
            os.environ[name] = str(value).lower() if isinstance(value, bool) else str(value)
except FileNotFoundError:
    pass

token = os.environ.get("APP_ACCESS_TOKEN", "")
if len(token) < 24 or token.startswith("REPLACE_"):
    st.error("Set APP_ACCESS_TOKEN to a random value of at least 24 characters in your secrets or chatbot/.env before starting.")
    st.stop()
owner_digest = hashlib.sha256(token.encode()).hexdigest()
if st.session_state.get("owner_digest") != owner_digest:
    st.title("Sentinel · private workspace")
    with st.form("owner_login"):
        supplied = st.text_input("Owner access token", type="password")
        login = st.form_submit_button("Unlock workspace")
    if login:
        if hmac.compare_digest(supplied, token):
            st.session_state.owner_digest = owner_digest
            st.rerun()
        else:
            st.error("Invalid access token.")
    st.stop()

@st.cache_resource
def runtime():
    settings = Settings.load(validate_web=False)
    settings.enable_nmap = os.environ.get("STREAMLIT_ENABLE_NMAP", "false").lower() == "true"
    settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    store = Store(settings.data_dir)
    tools = ToolRunner(settings, store)
    engine = Engine(settings, store, Retriever(settings.kb_root), ModelRouter(settings), tools)
    atexit.register(engine.close)
    return SimpleNamespace(settings=settings, store=store, tools=tools, engine=engine, uploads=ImageUploads(settings, store))

try:
    app = runtime()
except (ValueError, OSError):
    st.error("The application configuration could not be loaded. Check provider and scope configuration files.")
    st.stop()

store, engine, tools = app.store, app.engine, app.tools
if "chat_id" not in st.session_state:
    chats = store.chats()
    st.session_state.chat_id = chats[0]["id"] if chats else store.create_chat()
chat = st.session_state.chat_id
pending = store.pending()
active = next((job for job in pending if job["chat"] == chat), None)
busy = active is not None

with st.sidebar:
    st.title("Sentinel")
    st.caption("Personal security workspace")
    view = st.radio("Workspace", ["Chat", "Assessments", "Targets", "Readiness", "Code & terminal", "Tools setup"], key="workspace_view")
    if st.button("New conversation", disabled=busy):
        st.session_state.chat_id = store.create_chat()
        st.session_state.upload_version = st.session_state.get("upload_version", 0) + 1
        st.rerun()
    chats = store.chats()
    selected = st.selectbox("Conversations", [item["id"] for item in chats], index=next((i for i, item in enumerate(chats) if item["id"] == chat), 0), format_func=lambda key: next(item["title"] for item in chats if item["id"] == key), disabled=busy)
    if selected != chat:
        st.session_state.chat_id = selected
        st.session_state.upload_version = st.session_state.get("upload_version", 0) + 1
        st.rerun()
    exported = {"id": chat, "messages": store.history(chat), "evidence": store.chat_evidence(chat)}
    st.download_button("Export conversation", json.dumps(exported, indent=2), file_name="conversation-" + chat + ".json", mime="application/json")
    if st.button("Sign out"):
        st.session_state.clear()
        st.rerun()
    st.caption("Cloud runtime files are not durable backups. Download important evidence and conversations.")

st.title({"Chat": "Chat", "Assessments": "Run an assessment", "Targets": "Manage targets", "Readiness": "DDoS readiness", "Code & terminal": "Code & terminal", "Tools setup": "Tools & EC2 setup"}[view])
if view == "Chat" and not app.settings.providers["text"]:
    st.info("Add a model API key to enable chat. Local knowledge search is available under Assessments.")
if view == "Targets":
    st.caption("Add approved targets once, then select them when running checks.")
if view == "Assessments":
    st.caption("Choose a check, select an approved target, then run it.")

if view == "Targets":
    capabilities = tools.capabilities()
    kind = st.selectbox("Target type", ["web", "nmap"], format_func=lambda value: "Website · HTTPS origin" if value == "web" else "Nmap · infrastructure IP")
    if kind == "nmap":
        st.caption("Approve infrastructure separately. Website ownership does not authorize scanning shared hosting IPs. Nmap is disabled by default on this interface.")
    with st.form("add_target"):
        target = st.text_input("Target", placeholder="https://your-website.example" if kind == "web" else "192.168.1.20")
        confirmed = st.checkbox("I own this target or have permission for the supported checks.")
        add = st.form_submit_button("Add target", disabled=bool(pending))
    if add:
        try:
            with engine.lock:
                if store.pending():
                    raise ValueError("Finish or stop active jobs before changing targets.")
                tools.manage_target("add", kind, target.strip(), confirmed)
            st.rerun()
        except (ValueError, OSError) as exc:
            st.error(str(exc) if isinstance(exc, ValueError) else "Target could not be saved.")
    for saved_kind, values in (("web", capabilities["web_origins"]), ("nmap", capabilities["nmap_targets"])):
        st.markdown("**" + ("Websites" if saved_kind == "web" else "Nmap IPs") + "**")
        if not values:
            st.caption("No targets saved.")
        for value in values:
            left, right = st.columns([4, 1])
            left.write(value)
            if right.button("Remove", key="remove_" + saved_kind + value, disabled=bool(pending)):
                try:
                    with engine.lock:
                        if store.pending():
                            raise ValueError("Finish or stop active jobs before changing targets.")
                        tools.manage_target("remove", saved_kind, value)
                    st.rerun()
                except (ValueError, OSError):
                    st.error("Target could not be removed. Finish active jobs and try again.")

image_ids = []
upload_ok = True
version = st.session_state.get("upload_version", 0)
if view in ("Chat", "Assessments"):
    version = st.session_state.get("upload_version", 0)
    with st.expander("Attach an image"):
        files = st.file_uploader("Attach images", type=["png", "jpg", "jpeg", "webp"], accept_multiple_files=True, disabled=busy, key="images_" + str(version))
    image_ids = []
    upload_ok = True
    if len(files) > 3:
        st.error("Attach at most three images.")
        upload_ok = False
    else:
        saved_uploads = st.session_state.setdefault("uploads", {})
        for file in files:
            digest = hashlib.sha256(file.getvalue()).hexdigest()
            try:
                if digest not in saved_uploads:
                    saved_uploads[digest] = app.uploads.save(SimpleNamespace(stream=io.BytesIO(file.getvalue())))
                record = saved_uploads[digest]
                image_ids.append(record["id"])
                st.image(store.get_upload(record["id"])["preview"], width=140)
            except ValueError as exc:
                st.error(str(exc)); upload_ok = False
    
if view == "Assessments":
    capabilities = tools.capabilities()
    names = [item["name"] for item in capabilities["tools"] if item["available"]]
    labels={"knowledge_search":"Search knowledge base", "web_headers":"HTTPS headers and TLS", "dns_lookup":"DNS lookup", "nmap_scan":"Nmap port check", "image_metadata":"Image information"}
    tool = st.selectbox("Tool", names, format_func=lambda value: labels[value])
    args = {}
    valid = True
    if tool == "knowledge_search":
        args = {"query": st.text_input("Search query")}
    elif tool in ("web_headers", "dns_lookup"):
        origins = capabilities["web_origins"]
        args = {"origin": st.selectbox("Approved website", origins) if origins else ""}
        valid = bool(origins)
    elif tool == "nmap_scan":
        targets = capabilities["nmap_targets"]
        args = {"target": st.selectbox("Approved IP", targets) if targets else "", "ports": st.multiselect("Ports", capabilities["nmap_ports"], default=capabilities["nmap_ports"])}
        valid = bool(targets and args["ports"])
    else:
        args = {"image_id": st.selectbox("Attached image", image_ids) if image_ids else ""}
        valid = bool(image_ids)
    approval = st.checkbox("I authorize this check within the configured scope.", key="tool_approval")
    if st.button("Run check", disabled=busy or not valid or not upload_ok or not approval):
        try:
            tools.validate(tool, args, image_ids)
            engine.submit(chat, {"kind": "tool", "tool": tool, "arguments": args, "image_ids": image_ids})
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))

if view in ("Chat", "Assessments"):
    for row in store.history(chat):
        with st.chat_message(row["role"]):
            with st.expander("Message actions"):
                st.code(row["content"], language=None)
            if row["model"] == "tool adapter" and "```json\n" in row["content"]:
                try:
                    result = json.loads(row["content"].split("```json\n", 1)[1].rsplit("```", 1)[0])
                    st.success("Check completed. Evidence is available below.")
                    if "passages" in result:
                        if not result["passages"]:
                            st.info("No matching knowledge passages.")
                        for passage in result["passages"]:
                            st.markdown("**" + passage["title"] + "**")
                            st.markdown(passage["text"], unsafe_allow_html=False)
                            st.caption("Source: " + passage["origin"])
                    elif "http_status" in result:
                        st.write("HTTP status:", result["http_status"])
                        st.write("TLS verified:", result["tls_verified"])
                        st.write("Certificate expires:", result.get("certificate_expires"))
                        with st.expander("Headers and technical details"):
                            st.json(result)
                    elif "addresses" in result:
                        st.write("Resolved IP addresses:", ", ".join(result["addresses"]))
                        st.caption(result.get("interpretation", ""))
                    else:
                        with st.expander("Technical result"):
                            st.json(result)
                except (ValueError, KeyError, TypeError):
                    st.markdown(row["content"], unsafe_allow_html=False)
            else:
                st.markdown(row["content"], unsafe_allow_html=False)
            for key in row["attachments"]:
                st.image(store.get_upload(key)["preview"], width=180)
            if row["refs"]:
                with st.expander("Retrieved references"):
                    for ref in row["refs"]:
                        st.text("[KB:" + ref["citation_id"] + "] " + ref["title"] + " — " + ref["origin"])
            if row["model"]:
                with st.expander("Response details"):
                    st.caption(row["model"])
    
    records = store.chat_evidence(chat)
    if records:
        with st.expander("Evidence downloads", expanded=False):
            for record in records:
                st.markdown("**" + record["tool"] + "**")
                st.caption("Evidence ID: " + record["id"] + " · " + record["created"])
                st.caption("SHA-256 of the complete JSON download")
                st.code(record["sha256"], language=None)
                path = tools.evidence_dir / (record["id"] + ".json")
                if path.is_file():
                    raw = path.read_bytes()
                    st.download_button("Download evidence", raw, file_name="evidence-" + record["id"] + ".json", mime="application/json", key="download_" + record["id"])
                    if st.button("Verify evidence", key="verify_" + record["id"]):
                        if hmac.compare_digest(hashlib.sha256(raw).hexdigest(), record["sha256"]):
                            st.success("Verified: download bytes match the saved SHA-256.")
                        else:
                            st.error("Hash mismatch: evidence differs from the saved record.")
                else:
                    st.warning("Evidence file is unavailable in this runtime.")
    
if active:
    @st.fragment(run_every="1s")
    def progress():
        job = store.job(active["id"])
        st.info("Job: " + job["status"])
        st.code("\n".join(item["message"] for item in job["events"]), language=None)
        if job["status"] in ("queued", "running"):
            if st.button("Stop job", key="stop_" + job["id"]):
                engine.cancel(job["id"])
        else:
            if job.get("error"):
                st.session_state.last_error = job["error"]
            st.rerun()
    progress()

if st.session_state.get("last_error"):
    st.error(st.session_state.pop("last_error"))
if view == "Chat":
    allow_tools = st.checkbox("Allow scoped tools for this message", disabled=busy)
    question = st.chat_input("Ask about security or attach an image above…", disabled=busy or not upload_ok, max_chars=12000)
    if question:
        try:
            engine.submit(chat, {"kind": "chat", "message": question, "image_ids": image_ids, "allow_tools": allow_tools})
            st.session_state.upload_version = version + 1
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))
    

if view == "Readiness":
    st.caption("Review protection settings and collect a small availability sample. This cannot certify DDoS resilience.")
    checks = ["CDN/provider DDoS protection verified in provider console", "Rate limits configured for expensive and authentication endpoints", "Request body limits and upstream timeouts configured", "Caching enabled where appropriate", "Traffic/error alerts and response contacts configured", "Recovery and backup procedure exercised"]
    answers = {item: st.selectbox(item, ["Unknown", "Verified", "Needs work"], key="readiness_"+str(i)) for i,item in enumerate(checks)}
    st.download_button("Download readiness review", json.dumps(answers, indent=2), "readiness-review.json", "application/json")
    with st.expander("Small availability sample"):
        st.caption("Maximum five HTTPS root requests at one per second, one connection at a time. Separate lab/staging approval required. Set LOAD_TEST_ORIGINS to comma-separated approved origins in owner configuration.")
        from app.readiness import sample
        from app.tools import canonical_origin
        try:
            origins = [canonical_origin(x.strip()) for x in os.environ.get("LOAD_TEST_ORIGINS", "").split(",") if x.strip()]
        except ValueError:
            origins = []
            st.error("Invalid LOAD_TEST_ORIGINS configuration.")
        chosen = st.selectbox("Approved lab/staging origin", origins) if origins else None
        confirmed = st.checkbox("I have permission for this low-rate sample on this lab/staging target.")
        if st.button("Collect sample", disabled=not chosen or not confirmed or busy):
            output = st.empty()
            try:
                result = sample(chosen, origins, event=lambda row: output.json(row))
                st.session_state.availability_result = result
            except (ValueError, OSError) as exc:
                st.error("Sample stopped: " + str(exc))
        if "availability_result" in st.session_state:
            result = st.session_state.availability_result
            st.json(result)
            st.download_button("Download availability sample", json.dumps(result, indent=2), "availability-sample.json", "application/json")

if view == "Code & terminal":
    st.caption("Run a Python cell or Linux shell command in a fresh container on your separate runner. Output streams below. Preinstalled tools are available after building the EC2 image. These code cells have no network, host files, or persistent terminal sessions.")
    from app.workbench import execute, health
    if st.button("Check EC2 runner connection"):
        try:
            status = health()
            if status.get("image_ready"):
                st.success("Runner reachable; tools image is present. Run a small cell to verify execution.")
            else:
                st.warning("Runner reachable, but the tools image needs to be built on EC2.")
            with st.expander("Runner capabilities"):
                st.json(status)
        except (ValueError, OSError):
            st.error("Could not verify the runner. Check its HTTPS endpoint, token, and EC2 service.")
    mode = st.radio("Execution mode", ["python", "shell"], format_func=lambda x: "Python cell" if x == "python" else "Linux terminal")
    code = st.text_area("Code" if mode == "python" else "Command", value="print('Hello from Linux')" if mode == "python" else "uname -a; id; pwd", height=220, key="cell_"+mode, max_chars=12000)
    configured = bool(os.environ.get("RUNNER_URL") and os.environ.get("RUNNER_TOKEN"))
    if not configured:
        st.info("Connect a runner using RUNNER_URL and RUNNER_TOKEN. See RUNNER_SETUP.md. There is no local execution fallback.")
    if st.button("Run cell" if mode == "python" else "Run command", disabled=not configured or not code or busy):
        output = st.empty(); text = ""
        try:
            for item in execute(mode, code):
                text += item.get("output", "")
                output.code(text or "Starting container…", language=None)
                if item.get("done"):
                    st.write("Result:", item["reason"], "Exit code:", item.get("exit_code"))
            st.session_state.cell_output = text
        except (ValueError, OSError) as exc:
            st.error("Runner unavailable or execution interrupted: " + type(exc).__name__)
        st.code(text, language=None)
    elif st.session_state.get("cell_output"):
        st.code(st.session_state.cell_output, language=None)

if view == "Tools setup":
    st.caption("Streamlit is the frontend. Your separate Ubuntu EC2 instance runs the containers and optional Burp desktop.")
    st.markdown("**1. Configure the connection**")
    st.code('RUNNER_URL = "https://your-runner-domain.example"\nRUNNER_TOKEN = "your-generated-runner-token"', language="toml")
    st.caption("Put these values in Streamlit deployment secrets, or chatbot/.env for local development. Never enter AWS access keys here.")
    st.markdown("**2. Build the tools image on EC2**")
    st.code("sudo bash runner/setup-ec2.sh", language="bash")
    st.write("Image packages: Python, Bash, Nmap, curl, dig, jq, requests, and Pillow. Installing a tool does not make it a chat adapter. Offline cells can inspect versions and process data; they cannot scan websites.")
    st.code("nmap --version\ncurl --version\ndig -v\njq --version", language="bash")
    st.markdown("**3. Add owner-approved packages**")
    st.write("Edit runner/python-packages.txt for Python libraries or runner/Dockerfile for Linux packages, then rebuild on EC2. No unrestricted pip/apt installation is available inside a code cell.")
    st.code("sudo docker build -t sentinel-tools:local runner", language="bash")
    with st.expander("Burp Suite · remote desktop"):
        st.write("Burp is a separate graphical application on EC2. It is not automatically controlled by the chatbot or launched inside a 15-second cell. Install Community Edition using PortSwigger's native Linux installer, or use Professional with your license.")
        st.code("sudo bash runner/setup-burp-desktop.sh\nsudo passwd burp-user", language="bash")
        st.write("Connect Windows Remote Desktop through an SSH or AWS Session Manager tunnel. Do not open port 3389 or Burp's proxy port publicly. Use Burp's browser on the remote desktop and set the authorized target scope in Burp itself.")
        st.link_button("Official Burp download", "https://portswigger.net/burp/releases")
    for filename in ("AWS_RUNNER_SETUP.md", "BURP_SETUP.md"):
        path = ROOT / filename
        if path.is_file():
            st.download_button("Download " + filename, path.read_text(), file_name=filename, mime="text/markdown")
