import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('kb',Path(__file__).resolve().parents[1]/'scripts/kb.py')
kb=importlib.util.module_from_spec(spec)
spec.loader.exec_module(kb)

class KnowledgeBaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)/'kb'
        self.root.mkdir()
        self.input=Path(self.tmp.name)/'manual.md'
        self.input.write_text('# Web assessment\nSSRF server-side requests and outbound destination validation.',encoding='utf-8')
        kb.import_document(self.root,self.input,'Web assessment','original','owner note')
    def tearDown(self):self.tmp.cleanup()
    def test_retrieval_preserves_evidence(self):
        kb.build(self.root)
        hits=kb.search(self.root,'SSRF')
        self.assertEqual(len(hits),1)
        self.assertEqual(hits[0]['origin'],'original')
        self.assertIn('destination validation',hits[0]['text'])
        self.assertEqual(hits[0]['document_sha256'],kb.sha(self.input.read_text()))
    def test_missing_and_unmatched_query(self):
        with self.assertRaises(ValueError):kb.search(self.root,'SSRF')
        kb.build(self.root)
        self.assertEqual(kb.search(self.root,'qwertyunknown'),[])
        self.assertEqual(kb.search(self.root,'"*()'),[])
    def test_import_is_idempotent_and_origin_specific(self):
        result=kb.import_document(self.root,self.input,'Web assessment','original','owner note')
        self.assertEqual(result['status'],'already_imported')
        kb.import_document(self.root,self.input,'Other source','distinct origin','owner note')
        self.assertEqual(kb.build(self.root)['documents'],2)
    def test_rebuild_removes_deleted_source(self):
        kb.build(self.root)
        for path in (self.root/'sources').rglob('*.md'):path.unlink()
        self.assertEqual(kb.build(self.root)['chunks'],0)
        self.assertEqual(kb.search(self.root,'SSRF'),[])
    def test_failed_build_preserves_index(self):
        kb.build(self.root)
        next((self.root/'sources').rglob('*.meta.json')).write_text('{}')
        with self.assertRaises(ValueError):kb.build(self.root)
        self.assertEqual(len(kb.search(self.root,'SSRF')),1)
    def test_overlap_and_exact_content(self):
        text=' '.join('word'+str(i) for i in range(500))
        chunks=list(kb.passages(text))
        self.assertEqual(len(chunks),3)
        self.assertEqual(chunks[0][2]-chunks[1][1],35)
        self.assertTrue(chunks[-1][0].endswith('word499'))
        with self.assertRaises(ValueError):list(kb.passages(text,10,10))
    def test_limits_and_bad_input(self):
        with self.assertRaises(ValueError):kb.search(self.root,'SSRF',31)
        with self.assertRaises(ValueError):kb.import_document(self.root,self.input,'','origin','license')
    def test_rebuild_stable_ids(self):
        kb.build(self.root)
        first=kb.search(self.root,'SSRF')[0]['id']
        kb.build(self.root)
        self.assertEqual(first,kb.search(self.root,'SSRF')[0]['id'])

if __name__=='__main__':unittest.main()
