# Personal Cybersecurity Assistant

This workspace begins with a working, searchable knowledge base. The Flask chatbot and tool execution integrations are planned in `chatbot/`; they are not implemented in this archive. No targets have been scanned.

## Run the knowledge base
Requires Python 3.12+ with SQLite FTS5 enabled. No pip packages or API keys needed for this component.

```bash
cd personal-cyber-assistant
python knowledge_base/scripts/kb.py build
python knowledge_base/scripts/kb.py search "SSRF outbound requests"
python knowledge_base/scripts/kb.py search "Nmap" --limit 5
python knowledge_base/scripts/kb.py status
python -m unittest discover -s knowledge_base/tests -v
```

On Windows use `py -3.12` instead of `python` if needed. WSL can use `python3`.

## Add material
Save permitted UTF-8 `.md` or `.txt` material locally, then import it:

```bash
python knowledge_base/scripts/kb.py import /absolute/path/manual.md --title "My manual" --origin "https://example.org/manual" --license "permission recorded by owner"
python knowledge_base/scripts/kb.py build
```

Import copies the document and records its origin, hash, date and declared permission. The importer does not establish licensing rights. HTML/PDF need extraction before import; image OCR and binary formats are not implemented here. Keep secrets and real credentials out of the corpus.

## Honest coverage
The bundled notes are original starting material, not complete vendor manuals. `manifests/tool_catalog.json` includes the requested tools and aliases; each execution integration is explicitly unimplemented. `manifests/source_catalog.json` identifies initial primary sources, with verification status. Links are not equivalent to ingested content. No third-party manuals are bundled.

The current retriever uses SQLite full-text ranking. Semantic embeddings, hybrid fusion, reranking and model integrations belong to the chatbot implementation and are not claimed as completed. Empty retrieval must be handled as missing evidence rather than fabricated authority.

## Folder roles
- `knowledge_base/sources/`: imported material and original notes with sidecar provenance.
- `knowledge_base/processed/chunks.jsonl`: derived overlapping passages.
- `knowledge_base/indexes/knowledge.sqlite3`: rebuildable full-text index.
- `knowledge_base/manifests/`: source catalog, tool inventory and intended domain coverage.
- `chatbot/IMPLEMENTATION_CONTRACT.md`: requirements for the Flask engine and execution boundary.

Builds replace their derived files; source material is preserved. Run build while the future chatbot is stopped; cross-process build/read locking is not implemented.
