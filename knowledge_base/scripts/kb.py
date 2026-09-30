"""Local text ingestion and provenance-preserving FTS retrieval. Python stdlib only."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 5 * 1024 * 1024

def sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def passages(text: str, words: int = 220, overlap: int = 35):
    if words <= 0 or not 0 <= overlap < words:
        raise ValueError('Invalid chunk size or overlap')
    tokens = list(re.finditer(r'\S+', text))
    for start in range(0, len(tokens), words - overlap):
        end = min(start + words, len(tokens))
        yield text[tokens[start].start():tokens[end-1].end()], start, end
        if end == len(tokens):
            break

def documents(root: Path):
    source = (root / 'sources').resolve()
    for path in sorted(source.rglob('*')):
        if not path.is_file() or path.suffix.lower() not in {'.md', '.txt'}:
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(source):
            raise ValueError('Symlinks outside the corpus are not accepted')
        if path.stat().st_size > MAX_BYTES:
            raise ValueError(f'Document too large: {path.name}')
        text = path.read_text(encoding='utf-8')
        meta_path = Path(str(path) + '.meta.json')
        if not meta_path.is_file() or meta_path.is_symlink():
            raise ValueError(f'Missing regular provenance sidecar: {path.name}')
        meta = json.loads(meta_path.read_text(encoding='utf-8'))
        if not isinstance(meta, dict) or any(not isinstance(meta.get(k), str) or not meta[k].strip() for k in ('title', 'origin', 'license')):
            raise ValueError(f'Incomplete provenance: {path.name}')
        yield path.relative_to(root).as_posix(), text, meta

def build(root: Path) -> dict:
    # Validate and chunk everything before replacing the currently usable index.
    rows = []
    doc_count = 0
    for source, text, meta in documents(root):
        doc_count += 1
        digest = sha(text)
        for index, (body, start, end) in enumerate(passages(text)):
            rows.append({'id': sha(source + ':' + digest + ':' + str(index)),
                         'source': source, 'document_sha256': digest,
                         'chunk_index': index, 'word_start': start, 'word_end': end,
                         'title': meta['title'], 'origin': meta['origin'],
                         'metadata': meta, 'text': body})
    index_dir = root / 'indexes'
    processed_dir = root / 'processed'
    index_dir.mkdir(parents=True, exist_ok=True)
    processed_dir.mkdir(parents=True, exist_ok=True)
    fd, temp_db = tempfile.mkstemp(prefix='build-', suffix='.sqlite3', dir=index_dir)
    os.close(fd)
    fd, temp_json = tempfile.mkstemp(prefix='chunks-', suffix='.jsonl', dir=processed_dir)
    os.close(fd)
    try:
        with sqlite3.connect(temp_db) as db:
            db.execute('CREATE VIRTUAL TABLE chunks USING fts5(id UNINDEXED, source UNINDEXED, title, body, record UNINDEXED)')
            db.execute('CREATE TABLE build_info (record TEXT NOT NULL)')
            db.executemany('INSERT INTO chunks VALUES (?, ?, ?, ?, ?)',
                           [(r['id'], r['source'], r['title'], r['text'], json.dumps(r)) for r in rows])
            summary = {'documents': doc_count, 'chunks': len(rows), 'built_at': datetime.now(timezone.utc).isoformat(), 'retrieval': 'SQLite FTS5 BM25'}
            db.execute('INSERT INTO build_info VALUES (?)', (json.dumps(summary),))
        with open(temp_json, 'w', encoding='utf-8') as stream:
            for row in rows:
                stream.write(json.dumps(row, ensure_ascii=False) + '\n')
        os.replace(temp_db, index_dir / 'knowledge.sqlite3')
        os.replace(temp_json, processed_dir / 'chunks.jsonl')
        return summary
    finally:
        for path in (temp_db, temp_json):
            if os.path.exists(path):
                os.unlink(path)

def connection(root: Path):
    path = (root / 'indexes' / 'knowledge.sqlite3').resolve()
    if not path.is_file():
        raise ValueError('Index missing. Run build first.')
    return sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)

def search(root: Path, query: str, limit: int = 5) -> list:
    if not 1 <= limit <= 30:
        raise ValueError('Limit must be 1..30')
    # Treat user input as terms, not FTS operators or SQL.
    terms = list(dict.fromkeys(re.findall(r'\w+', query.lower(), re.UNICODE)))[:32]
    if not terms:
        return []
    expression = ' OR '.join('"' + term + '"' for term in terms)
    with connection(root) as db:
        matches = db.execute('SELECT record, bm25(chunks, 0, 0, 3, 1, 0) AS rank FROM chunks WHERE chunks MATCH ? ORDER BY rank, id LIMIT ?', (expression, limit)).fetchall()
    results=[]
    for record, rank in matches:
        row=json.loads(record)
        row['rank']=rank
        row['citation_id']=row['id'][:16]
        results.append(row)
    return results

def status(root: Path) -> dict:
    with connection(root) as db:
        return json.loads(db.execute('SELECT record FROM build_info').fetchone()[0])

def import_document(root: Path, path: Path, title: str, origin: str, license_note: str) -> dict:
    if path.suffix.lower() not in {'.md', '.txt'} or not path.is_file():
        raise ValueError('Import expects a local UTF-8 .md or .txt file')
    if path.stat().st_size > MAX_BYTES:
        raise ValueError('Document exceeds 5 MiB limit')
    if any(not item.strip() for item in (title, origin, license_note)):
        raise ValueError('Title, origin and license are required')
    text=path.read_text(encoding='utf-8')
    if not text.strip():
        raise ValueError('Document is empty')
    digest=sha(text)
    # Include provenance in the identity so identical text from distinct sources
    # does not silently inherit the earlier source attribution.
    identity=sha(json.dumps([digest,title,origin,license_note]))
    directory=root/'sources'/'imports'
    directory.mkdir(parents=True,exist_ok=True)
    dest=directory/(identity+'.md')
    sidecar=Path(str(dest)+'.meta.json')
    if dest.exists() and sidecar.exists():
        return {'source':dest.relative_to(root).as_posix(),'sha256':digest,'status':'already_imported'}
    metadata={'title':title,'origin':origin,'license':license_note,'kind':'imported_document','imported_at':datetime.now(timezone.utc).isoformat(),'sha256':digest}
    # A failed partial import is rejected by build rather than attributed falsely.
    dest.write_text(text,encoding='utf-8')
    sidecar.write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    return {'source':dest.relative_to(root).as_posix(),'sha256':digest,'status':'imported'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=DEFAULT_ROOT)
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('build')
    sub.add_parser('status')
    query=sub.add_parser('search')
    query.add_argument('query')
    query.add_argument('--limit',type=int,default=5)
    imp=sub.add_parser('import')
    imp.add_argument('path',type=Path)
    imp.add_argument('--title',required=True)
    imp.add_argument('--origin',required=True)
    imp.add_argument('--license',required=True)
    args=parser.parse_args()
    try:
        if args.command=='build':result=build(args.root)
        elif args.command=='status':result=status(args.root)
        elif args.command=='search':result=search(args.root,args.query,args.limit)
        else:result=import_document(args.root,args.path,args.title,args.origin,args.license)
        print(json.dumps(result,ensure_ascii=False,indent=2))
    except (ValueError,OSError,sqlite3.Error) as exc:
        parser.exit(1,f'Error: {exc}\n')

if __name__=='__main__':
    main()
