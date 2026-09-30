# Chatbot implementation contract

This directory specifies the next implementation work; it contains no running chatbot yet.

- Flask app with interactive HTML, streaming responses, conversation storage and job status.
- Sanitized Markdown, syntax highlighting, accessible code/message copy buttons and image upload.
- Upload checks by decoded format and dimensions, bounded bytes, private file storage and no executable content rendering.
- Configurable primary/fallback chat and vision providers; verify current provider model IDs before implementation. Groq and xAI Grok are separate providers. Keys stay server-side.
- Retrieval with provenance, semantic embeddings plus full-text search, reciprocal-rank fusion and optional reranker; empty evidence and uncertainty are explicit.
- Background job execution, cancellation, target scope and per-job budgets; no unrestricted model-generated shell execution.
- Typed tool adapters report installed version, capabilities and structured output. Tool catalog entries alone do not activate adapters.
- Application assessments prioritize source review, bounded HTTP observations and approved test accounts. Infrastructure scans need their own approved scope.
- Scope stays enforced outside the LLM. Tool output and retrieved content cannot expand authorization.
- No real credential/session-token collection campaigns, covert tracking workflows or unrestricted attack orchestration.
- Evidence includes target, version, arguments with secrets removed, timestamps, completion state and hashes. Findings distinguish confirmed from suspected.
- Local access defaults to loopback; authentication and CSRF defenses required before remote exposure.
- Validate retrieval quality, fallback behavior, upload rejection, Markdown XSS, scope rejection, cancellation and evidence persistence before claiming readiness.
