from dataclasses import dataclass
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

CHATBOT=Path(__file__).resolve().parents[1]
PROJECT=CHATBOT.parent

@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    key: str
    model: str
    tools: bool
    token_field: str="max_completion_tokens"

@dataclass
class Settings:
    data_dir: Path
    kb_root: Path
    access_token: str
    host: str
    trusted_hosts: list[str]
    cookie_secure: bool
    providers: dict[str,list[Provider]]
    scopes: dict
    provider_timeout: int=30
    max_steps: int=4
    max_tool_calls: int=6
    max_jobs: int=8
    enable_nmap: bool=True

    @classmethod
    def load(cls,validate_web=True):
        data=Path(os.environ.get('APP_DATA_DIR',CHATBOT/'runtime')).resolve()
        provider_path=Path(os.environ.get('PROVIDERS_FILE',CHATBOT/'config/providers.json'))
        if not provider_path.exists():provider_path=CHATBOT/'config/providers.example.json'
        raw=json.loads(provider_path.read_text())
        providers={}
        for kind in ('text','vision'):
            providers[kind]=[]
            for p in raw.get(kind,[]):
                base=p['base_url'].rstrip('/')
                u=urlsplit(base)
                if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment:
                    raise ValueError('Provider URL must be an HTTPS API base without credentials or query')
                key=os.environ.get(p['key_env'],'').strip()
                model=os.environ.get(p['model_env'],'').strip()
                token_field=p.get('token_field','max_completion_tokens')
                if token_field not in ('max_tokens','max_completion_tokens'):raise ValueError('Unsupported provider token limit field')
                if key and model:
                    providers[kind].append(Provider(p['name'],base,key,model,bool(p.get('tools',False)),token_field))
        scope_path=Path(os.environ.get('SCOPES_FILE',CHATBOT/'config/scopes.json'))
        scopes=json.loads(scope_path.read_text()) if scope_path.exists() else {'web_origins':[],'nmap_targets':[],'nmap_ports':[80,443]}
        host=os.environ.get('APP_HOST','127.0.0.1')
        token=os.environ.get('APP_ACCESS_TOKEN','')
        secure=os.environ.get('APP_COOKIE_SECURE','false').lower()=='true'
        if validate_web and host not in ('127.0.0.1','localhost','::1') and (len(token)<24 or not secure):
            raise ValueError('Remote binding requires a 24+ character access token and secure cookies behind HTTPS')
        trusted=[x.strip() for x in os.environ.get('APP_TRUSTED_HOSTS','localhost,127.0.0.1,[::1]').split(',') if x.strip()]
        if validate_web and any(x not in ('localhost','127.0.0.1','[::1]') for x in trusted) and (len(token)<24 or not secure):
            raise ValueError('Nonlocal trusted hosts require an owner token and HTTPS secure cookies')
        if not trusted or any(x.startswith('.') or x=='*' for x in trusted):
            raise ValueError('Configure exact trusted hostnames')
        return cls(data,PROJECT/'knowledge_base',token,host,trusted,secure,providers,scopes)
