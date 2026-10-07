# Implementation status

Implemented: Flask/Waitress backend, persistent conversations and jobs, source-labelled full-text retrieval, configurable text and vision chains, sanitized Markdown UI, code highlighting, message/code copy buttons, image uploads, cooperative cancellation, scope validation, bounded typed adapters, evidence and exports.

Adapters: local knowledge search, DNS lookup, HTTPS root-page headers/TLS, Nmap TCP-connect scan and attached-image metadata. Model output cannot create arbitrary commands or expand configured scope. Vision analysis is read-only.

Outstanding integration checks: owner API credentials/model access, real Nmap executable behavior on the execution host and any remote HTTPS proxy configuration. Full vendor-document ingestion, semantic/hybrid retrieval and additional tool adapters are not implemented. Consult README and TEST_REPORT for the exact scope of the deliverable.
