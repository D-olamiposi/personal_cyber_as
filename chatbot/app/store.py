from contextlib import contextmanager
from datetime import datetime,timezone
import json
from pathlib import Path
import sqlite3
import uuid


def now():return datetime.now(timezone.utc).isoformat()
def identifier():return uuid.uuid4().hex

class Store:
    def __init__(self,directory:Path):
        directory.mkdir(parents=True,exist_ok=True)
        self.path=directory/'assistant.sqlite3'
        with self.db() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS chats(id TEXT PRIMARY KEY,title TEXT,created TEXT);
            CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY,chat TEXT,role TEXT,content TEXT,attachments TEXT,refs TEXT,model TEXT,created TEXT);
            CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,chat TEXT,status TEXT,payload TEXT,result TEXT,error TEXT,created TEXT,updated TEXT);
            CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,job TEXT,message TEXT,created TEXT);
            CREATE TABLE IF NOT EXISTS job_evidence(job TEXT,id TEXT PRIMARY KEY,tool TEXT,sha256 TEXT,created TEXT);
            CREATE TABLE IF NOT EXISTS uploads(id TEXT PRIMARY KEY,preview TEXT,original TEXT,metadata TEXT,created TEXT);
            CREATE INDEX IF NOT EXISTS messages_chat ON messages(chat,created);
            CREATE INDEX IF NOT EXISTS events_job ON events(job,seq);
            ''')
            db.execute("UPDATE jobs SET status='interrupted',error='Server restarted; job was not resumed.',updated=? WHERE status IN ('queued','running')",(now(),))
    @contextmanager
    def db(self):
        db=sqlite3.connect(self.path,timeout=10)
        db.row_factory=sqlite3.Row
        try:
            yield db
            db.commit()
        finally:db.close()
    def create_chat(self,title='New conversation'):
        key=identifier()
        with self.db() as db:db.execute('INSERT INTO chats VALUES(?,?,?)',(key,title[:80],now()))
        return key
    def chats(self):
        with self.db() as db:return [dict(r) for r in db.execute('SELECT * FROM chats ORDER BY created DESC')]
    def chat_exists(self,key):
        with self.db() as db:return db.execute('SELECT 1 FROM chats WHERE id=?',(key,)).fetchone() is not None
    def message(self,chat,role,content,attachments=None,refs=None,model=None):
        key=identifier()
        with self.db() as db:
            db.execute('INSERT INTO messages VALUES(?,?,?,?,?,?,?,?)',(key,chat,role,content,json.dumps(attachments or []),json.dumps(refs or []),model,now()))
            if role=='user':db.execute("UPDATE chats SET title=? WHERE id=? AND title='New conversation'",(content[:60],chat))
        return key
    def history(self,chat):
        with self.db() as db:rows=[dict(r) for r in db.execute('SELECT * FROM messages WHERE chat=? ORDER BY created,rowid',(chat,))]
        for row in rows:
            row['attachments']=json.loads(row['attachments']);row['refs']=json.loads(row['refs'])
        return rows
    def create_job(self,chat,payload):
        key=identifier();stamp=now()
        with self.db() as db:db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?)',(key,chat,'queued',json.dumps(payload),'{}','',stamp,stamp))
        return key
    def set_job(self,key,status,result=None,error=''):
        with self.db() as db:db.execute('UPDATE jobs SET status=?,result=?,error=?,updated=? WHERE id=?',(status,json.dumps(result or {}),error,now(),key))
    def job(self,key):
        with self.db() as db:
            r=db.execute('SELECT * FROM jobs WHERE id=?',(key,)).fetchone()
            if not r:return None
            result=dict(r)
            result['payload']=json.loads(result['payload']);result['result']=json.loads(result['result'])
            result['evidence']=[dict(x) for x in db.execute('SELECT id,tool,sha256,created FROM job_evidence WHERE job=? ORDER BY created',(key,))]
            result['events']=[dict(x) for x in db.execute('SELECT seq,message,created FROM events WHERE job=? ORDER BY seq',(key,))]
            return result
    def pending(self):
        with self.db() as db:return [dict(r) for r in db.execute("SELECT id,chat,status FROM jobs WHERE status IN ('queued','running')")]
    def event(self,key,message):
        with self.db() as db:db.execute('INSERT INTO events(job,message,created) VALUES(?,?,?)',(key,message[:300],now()))
    def upload(self,key,preview,original,metadata):
        with self.db() as db:db.execute('INSERT INTO uploads VALUES(?,?,?,?,?)',(key,str(preview),str(original),json.dumps(metadata),now()))
    def get_upload(self,key):
        with self.db() as db:
            r=db.execute('SELECT * FROM uploads WHERE id=?',(key,)).fetchone()
        if not r:raise ValueError('Image not found')
        row=dict(r);row['metadata']=json.loads(row['metadata']);return row

    def record_evidence(self,job,evidence):
        with self.db() as db:db.execute('INSERT INTO job_evidence VALUES(?,?,?,?,?)',(job,evidence['id'],evidence['tool'],evidence['sha256'],now()))
    def chat_evidence(self,chat):
        with self.db() as db:return [dict(r) for r in db.execute('SELECT e.id,e.tool,e.sha256,e.created FROM job_evidence e JOIN jobs j ON j.id=e.job WHERE j.chat=? ORDER BY e.created',(chat,))]
