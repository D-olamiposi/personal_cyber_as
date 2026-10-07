"""OpenAI-compatible Chat Completions transport with bounded provider fallbacks."""
import json
import socket
import urllib.error
import urllib.request

class ProviderError(Exception):pass
class Cancelled(Exception):pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None

class ModelRouter:
    def __init__(self,settings):
        self.settings=settings
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def complete(self,messages,kind,event,cancel,tools=None):
        candidates=[p for p in self.settings.providers[kind] if not tools or p.tools]
        if not candidates:raise ProviderError(f'No configured {kind} provider. Set API keys and model IDs in chatbot/.env.')
        for provider in candidates:
            if cancel.is_set():raise Cancelled()
            event(f'Calling {provider.name} / {provider.model}')
            payload={'model':provider.model,'messages':messages,'stream':False,provider.token_field:4096}
            if tools:payload.update({'tools':tools,'tool_choice':'auto'})
            request=urllib.request.Request(provider.base_url+'/chat/completions',data=json.dumps(payload).encode(),headers={'Authorization':'Bearer '+provider.key,'Content-Type':'application/json'},method='POST')
            try:
                with self.opener.open(request,timeout=self.settings.provider_timeout) as response:
                    body=response.read(2_000_001)
                    if len(body)>2_000_000:raise ProviderError('Response exceeded local limit')
                    data=json.loads(body)
                message=data['choices'][0]['message']
                if not isinstance(message,dict):raise ValueError('Invalid message')
                if message.get('refusal'):
                    # A refusal is a completed response, not an availability failure.
                    return {'role':'assistant','content':message['refusal']},provider.name+'/'+provider.model
                content=message.get('content')
                calls=message.get('tool_calls')
                if not isinstance(content,(str,type(None))) or not isinstance(calls,(list,type(None))):raise ValueError('Invalid completion format')
                if not content and not calls:raise ValueError('Empty completion')
                if cancel.is_set():raise Cancelled()
                return {'role':'assistant','content':content,'tool_calls':calls} if calls else {'role':'assistant','content':content},provider.name+'/'+provider.model
            except urllib.error.HTTPError as exc:
                # Do not expose provider bodies, which may contain prompts or credentials.
                event(f'{provider.name} returned HTTP {exc.code}; trying configured fallback.')
            except (urllib.error.URLError,TimeoutError,socket.timeout,OSError,json.JSONDecodeError,KeyError,ValueError,ProviderError):
                event(f'{provider.name} unavailable or returned an invalid response; trying configured fallback.')
        raise ProviderError('All configured providers failed. Review account access, model IDs, quota and connectivity.')
