# Knowledge collection and quality control

Start with the primary documentation entrypoints in `manifests/source_catalog.json`. Verified entrypoints were checked on 2026-09-30; this does not establish a particular release version or ingestion rights. Preserve document version and last-reviewed date in sidecar metadata when available.

For each tool in `tool_catalog.json`, locate its current official documentation and release information. Verify availability before relying on older tutorials. Import relevant material only with the necessary rights, retaining its source and version. The five verified entrypoints are initial references, not a claim of comprehensive source collection.

A useful tool reference document should explain purpose, prerequisites, supported platform, input and output formats, interpretation limits, lab examples, failure modes, version differences and remediation implications. Keep model instructions separate from retrieved source content. Never ingest credentials or raw sensitive assessment evidence into the shared knowledge corpus.

Use the CLI importer for local text. Export HTML documentation to clean text, inspect extraction quality, and record the original URL; do not import navigation-only pages as substantive manuals. For PDF, inspect extracted text and tables first. For scanned PDFs and images, verified OCR is needed; the current importer accepts text only.

After import, rebuild and inspect representative query results. Test realistic prompts such as 'What does filtered mean in Nmap?', 'Can HTTP response headers rule out SSRF?', and 'How does a webhook avoid creating duplicate orders?'. A matched title is not enough: the passage must support the answer. Record missing coverage and add authoritative material instead of filling gaps with invented facts.

The build is offline and deterministic for identical source text, paths and provenance. It never installs tools, scans targets or downloads arbitrary URLs. URLs in catalog entries are references only.

Before integrating into the chatbot, evaluate a reviewed question set for relevance, citation correctness, unsupported claims and proper handling of missing evidence. The eight automated tests validate pipeline behavior, not cybersecurity expertise.
