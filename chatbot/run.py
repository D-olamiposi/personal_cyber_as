from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent/'.env')
from app.config import Settings
from app.web import create_app

if __name__=='__main__':
    settings=Settings.load()
    app=create_app(settings)
    port=int(os.environ.get('APP_PORT','5000'))
    print(f'Open http://{settings.host}:{port} — '+('owner token required' if settings.access_token else 'local access only'),flush=True)
    try:
        # Single process: persistent SQLite state plus bounded in-process jobs.
        # Waitress avoids the development server and reloader spawning duplicate runners.
        from waitress import serve
        serve(app,host=settings.host,port=port,threads=8)
    finally:app.extensions['engine'].close()
