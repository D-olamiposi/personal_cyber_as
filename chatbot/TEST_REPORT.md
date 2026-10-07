# Verification report — 2026-09-30

## Automated backend and knowledge tests

29 chatbot/backend tests passed; 8 knowledge-base tests passed (37 total).

Verified behavior:
- Persistent chat history and retrieval references.
- Image decoding, conversion, attachment handling and vision request routing.
- Invalid image, SVG, path, identifier and request-type rejection.
- Owner-token login/logout, CSRF checks, Host validation and local-client restrictions.
- Per-request tool authorization and fixed argument schemas.
- Target/port scope rejection, including model-proposed out-of-scope actions.
- Mixed public/private DNS-answer rejection and validated-address pinning with original-host TLS SNI.
- Text/vision fallback on simulated API failures; completed refusal does not cause fallback.
- Cancellation, busy-conversation rejection, no-provider failure and evidence hashing/export.
- Nmap fixed command arguments, XML parsing, missing executable handling and process cancellation using a controlled process fixture.
- Knowledge import, overlapping passages, stable identifiers, provenance preservation, rebuild behavior and existing-index preservation after validation failure.

## Prior Chromium interface checks (recovered report)

The recovered archive reports that the real Flask routes and local JS assets were exercised in headless Chromium with a deterministic model fixture. No live LLM responses were fabricated or substituted into the shipped app.

Verified:
- Markdown tables and highlighted Python fenced code.
- Working code/message copy actions and clipboard contents.
- Image upload, preview and removal.
- Local knowledge-tool job execution and saved evidence links surviving page reload.
- Desktop 1440×1000 and mobile 390×844 layouts without horizontal overflow.
- Visible mobile send button during long conversations, and working mobile menu open/close.
- Injected script tags, event-handler images and unsafe URL fixtures cannot execute in rendered responses.
- Zero uncaught browser JavaScript errors in the smoke run.

The browser fixture was temporary test infrastructure and is not part of the production runtime.

## Not verified live

- Provider account access, quotas, billing or actual primary/fallback model responses: no owner API keys were supplied.
- Real Nmap binary execution: the development environment has no Nmap installation.
- Any live website, including Nikky Luxe: no assessment was run.
- Remote deployment, HTTPS proxy integration, multi-user operation or distributed execution.
- Exhaustive security coverage or retrieval expertise across the requested tool inventory. The current corpus is introductory and uses full-text retrieval.

Tests establish these bounded behaviors; they do not establish absence of all defects or all vulnerabilities in arbitrary targets.

## Recovery verification — 2026-09-30

The interrupted deliverable was recovered from its saved archive. All 29 backend tests and eight knowledge-base tests were rerun successfully. JavaScript syntax checking passed. A fresh headless Chromium run could not start because this environment has no Chromium executable; the prior browser results above were retained as historical results, not rerun claims. Live API calls, Nmap binary execution and target assessments remain unverified.

## Target management and evidence update — 2026-10-07

37 backend tests plus eight knowledge-base tests pass (45 total). Seven new backend tests exercise immediate authorization, persistence, duplicate normalization, owner/CSRF enforcement, invalid target rejection, separate Nmap scope, revocation, active-job conflicts, and failed-write rollback. Existing evidence tests compare download bytes with the persisted SHA-256. JavaScript syntax checking passes. The user's Groq SDK fix is retained. No live provider call or website scan was made during this update. Browser verification status is recorded separately below.

An additional mocked Groq SDK test confirms the API root URL, disabled SDK retries, and preserved tool payload. Fresh browser checks could not run: Chromium is not installed and its download failed. Desktop/mobile layout and clipboard/Web Crypto controls therefore need a browser check after installation; no fresh browser success is claimed.

## Streamlit conversion — 2026-10-07

The Streamlit AppTest flow verifies the owner login, target creation, local knowledge-tool submission, saved evidence display, and hash verification without live provider requests. 38 backend and eight knowledge-base tests pass (46 total), including enforcement of disabled Nmap execution. Browser pixel/layout and clipboard actions, hosted deployment, live provider calls and live Nmap execution have not been verified by this conversion.
