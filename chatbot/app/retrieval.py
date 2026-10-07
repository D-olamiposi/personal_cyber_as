import importlib.util
from pathlib import Path

file=Path(__file__).resolve().parents[2]/'knowledge_base/scripts/kb.py'
spec=importlib.util.spec_from_file_location('cyber_kb',file)
kb=importlib.util.module_from_spec(spec)
spec.loader.exec_module(kb)

class Retriever:
    def __init__(self,root):self.root=root
    def search(self,query):return kb.search(self.root,query,5)
    def status(self):
        try:return kb.status(self.root)
        except Exception:return {'error':'Index missing or unreadable. Run the knowledge-base build command.'}
