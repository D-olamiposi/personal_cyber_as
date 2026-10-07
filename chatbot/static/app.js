'use strict';
const $=id=>document.getElementById(id);
const csrf=document.querySelector('meta[name="csrf-token"]').content;
let currentChat=null,activeJob=null,attachments=[],statusData=null;
let toastTimer;
function toast(message){$('toast').textContent=message;$('toast').classList.remove('hidden');clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').classList.add('hidden'),4500);}
async function api(path,options={}){
  const headers={...(options.headers||{}),'X-CSRF-Token':csrf};
  if(options.body&&!(options.body instanceof FormData)){headers['Content-Type']='application/json';options.body=JSON.stringify(options.body);}
  const response=await fetch(path,{...options,headers,credentials:'same-origin'});
  const data=await response.json();
  if(!response.ok)throw new Error(data.error||'Request failed');
  return data;
}
async function copy(text,button){
  try{await navigator.clipboard.writeText(text);}catch{
    const area=document.createElement('textarea');area.value=text;area.className='sr-only';document.body.append(area);area.select();
    const ok=document.execCommand('copy');area.remove();if(!ok){toast('Clipboard unavailable. Select the text to copy it.');return;}
  }
  const old=button.textContent;button.textContent='Copied';setTimeout(()=>button.textContent=old,1300);
}
function safeLink(value){try{const u=new URL(value);return ['https:','http:'].includes(u.protocol)?u.href:null;}catch{return null;}}
function markdown(container,text){
  const raw=marked.parse(text,{gfm:true,breaks:false});
  container.innerHTML=DOMPurify.sanitize(raw,{FORBID_TAGS:['img','svg','math','iframe','form','input','button','style','video','audio','object'],FORBID_ATTR:['style','srcset'],ALLOW_DATA_ATTR:false});
  container.querySelectorAll('a').forEach(link=>{const href=safeLink(link.getAttribute('href'));if(href){link.href=href;link.target='_blank';link.rel='noopener noreferrer';}else link.removeAttribute('href');});
  container.querySelectorAll('pre').forEach(pre=>{
    const code=pre.querySelector('code');if(!code)return;
    const content=code.textContent;const label=[...code.classList].find(x=>x.startsWith('language-'))?.slice(9)||'code';
    const box=document.createElement('div');box.className='code-box';const top=document.createElement('div');top.className='code-top';
    const name=document.createElement('span');name.textContent=label;
    const button=document.createElement('button');button.type='button';button.textContent='Copy code';button.addEventListener('click',()=>copy(content,button));top.append(name,button);
    pre.replaceWith(box);box.append(top,pre);hljs.highlightElement(code);
  });
}
function renderMessage(row){
  const article=document.createElement('article');article.className='message '+row.role;
  const bar=document.createElement('div');bar.className='message-bar';const avatar=document.createElement('span');avatar.className='avatar';avatar.textContent=row.role==='user'?'Y':'S';
  const name=document.createElement('strong');name.textContent=row.role==='user'?'YOU':'SENTINEL';
  const button=document.createElement('button');button.type='button';button.className='quiet';button.textContent='Copy message';button.addEventListener('click',()=>copy(row.content,button));bar.append(avatar,name,button);article.append(bar);
  if(row.attachments?.length){const images=document.createElement('div');images.className='message-images';for(const key of row.attachments){if(!/^[a-f0-9]{32}$/.test(key))continue;const img=document.createElement('img');img.src='/api/images/'+key;img.alt='Attached image';img.loading='lazy';images.append(img);}article.append(images);}
  const content=document.createElement('div');content.className='content';if(row.role==='assistant')markdown(content,row.content);else content.textContent=row.content;article.append(content);
  if(row.refs?.length){const refs=document.createElement('details');refs.className='sources';const summary=document.createElement('summary');summary.textContent='Retrieved references · '+row.refs.length;refs.append(summary);for(const ref of row.refs){const p=document.createElement('p');p.textContent='[KB:'+ref.citation_id+'] '+ref.title+' — ';const url=safeLink(ref.origin);if(url){const a=document.createElement('a');a.href=url;a.textContent=ref.origin;a.target='_blank';a.rel='noopener noreferrer';p.append(a);}else p.append(document.createTextNode(ref.origin));refs.append(p);}article.append(refs);}
  if(row.model){const model=document.createElement('p');model.className='model-label';model.textContent=row.model;article.append(model);}
  $('messages').append(article);
}
function renderEvidence(records){
  if(!records?.length)return;
  const list=document.createElement('details');list.className='sources evidence-list';list.open=true;
  const title=document.createElement('summary');title.textContent='Recorded assessment evidence · '+records.length;list.append(title);
  for(const record of records){
    if(!/^[a-f0-9]{32}$/.test(record.id))continue;
    const card=document.createElement('div');card.className='evidence-card';
    const link=document.createElement('a');link.href='/api/evidence/'+record.id;link.textContent='Download '+record.tool+' evidence';link.download='';card.append(link);
    const stamp=document.createElement('p');stamp.textContent='Evidence ID: '+record.id+' · '+record.created;card.append(stamp);
    if(/^[a-f0-9]{64}$/.test(record.sha256)){
      const label=document.createElement('p');label.textContent='SHA-256 of downloaded JSON';
      const hash=document.createElement('code');hash.className='evidence-hash';hash.textContent=record.sha256;
      const buttons=document.createElement('div');buttons.className='evidence-actions';
      const copyButton=document.createElement('button');copyButton.type='button';copyButton.className='quiet';copyButton.textContent='Copy SHA-256';copyButton.addEventListener('click',()=>copy(record.sha256,copyButton));
      const verify=document.createElement('button');verify.type='button';verify.className='quiet';verify.textContent='Verify download';
      const result=document.createElement('p');result.setAttribute('role','status');
      verify.addEventListener('click',async()=>{
        verify.disabled=true;result.textContent='Checking downloaded bytes…';
        try{
          if(!window.crypto?.subtle)throw Error('Verification needs a secure browser connection.');
          const response=await fetch(link.href,{credentials:'same-origin',cache:'no-store'});
          if(!response.ok)throw Error('Evidence download failed.');
          const digest=await crypto.subtle.digest('SHA-256',await response.arrayBuffer());
          const actual=[...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,'0')).join('');
          result.textContent=actual===record.sha256?'Verified: downloaded bytes match the saved SHA-256.':'Mismatch: downloaded bytes differ from the saved SHA-256.';
          result.classList.toggle('error',actual!==record.sha256);
        }catch(error){result.textContent=error.message;result.classList.add('error');}
        finally{verify.disabled=false;}
      });
      buttons.append(copyButton,verify);card.append(label,hash,buttons,result);
    }
    list.append(card);
  }
  $('messages').append(list);
}
async function loadChats(){const data=await api('/api/chats');$('chat-list').replaceChildren();for(const chat of data.chats){const button=document.createElement('button');button.textContent=chat.title;button.classList.toggle('active',chat.id===currentChat);button.addEventListener('click',()=>{if(activeJob){toast('Stop or finish the current job before switching conversations.');return;}selectChat(chat.id).catch(e=>toast(e.message));});$('chat-list').append(button);}return data.chats;}
async function selectChat(id){currentChat=id;localStorage.setItem('sentinel-chat',id);toggleSidebar(false);const data=await api('/api/chats/'+id);$('messages').replaceChildren();if(!data.messages.length)$('messages').append(welcome.cloneNode(true));for(const row of data.messages)renderMessage(row);renderEvidence(data.evidence);bindSuggestions();await loadChats();if(data.jobs?.length)watchJob(data.jobs[0].id);scrollBottom();}
function scrollBottom(){window.scrollTo({top:document.body.scrollHeight,behavior:'smooth'});}
const welcome=$('welcome').cloneNode(true);
function bindSuggestions(){document.querySelectorAll('[data-prompt]').forEach(button=>button.addEventListener('click',()=>{$('message').value=button.dataset.prompt;$('message').focus();}));}
function renderAttachments(){
  $('attachments').replaceChildren();for(const image of attachments){const chip=document.createElement('div');chip.className='attachment';const img=document.createElement('img');img.src=image.url;img.alt='Pending image';const label=document.createElement('span');label.textContent=image.metadata.width+' × '+image.metadata.height;const button=document.createElement('button');button.className='quiet';button.type='button';button.textContent='✕';button.setAttribute('aria-label','Remove attached image');button.addEventListener('click',()=>{attachments=attachments.filter(x=>x.id!==image.id);renderAttachments();});chip.append(img,label,button);$('attachments').append(chip);}updateToolFields();
}
async function addImages(files){
  for(const file of files){if(attachments.length>=3){toast('Attach at most three images.');break;}const form=new FormData();form.append('image',file);const image=await api('/api/images',{method:'POST',body:form});attachments.push(image);renderAttachments();}
}
function busy(value){$('send').disabled=value;$('new-chat').disabled=value;$('run-tool').disabled=value;$('image-input').disabled=value;$('allow-tools').disabled=value;}
async function watchJob(id){
  if(activeJob===id)return;activeJob=id;busy(true);$('job-panel').classList.remove('hidden');$('job-title').textContent='Working';let failures=0;
  while(activeJob===id){
    try{
      const job=await api('/api/jobs/'+id);failures=0;
      $('job-log').textContent=job.events.map(x=>x.message).join('\n');$('job-log').scrollTop=$('job-log').scrollHeight;
      if(['completed','failed','cancelled','interrupted'].includes(job.status)){
        activeJob=null;busy(false);$('job-title').textContent=job.status==='completed'?'Completed':job.status;
        const data=await api('/api/chats/'+currentChat);$('messages').replaceChildren();for(const row of data.messages)renderMessage(row);renderEvidence(data.evidence);
        if(job.status==='completed'){
          setTimeout(()=>$('job-panel').classList.add('hidden'),3500);
        }else{toast(job.error||'Job did not complete.');$('job-log').textContent+='\n'+(job.error||'');}
        await loadChats();scrollBottom();return;
      }
    }catch(error){failures++;$('job-title').textContent='Connection interrupted — retrying';if(failures===3)toast(error.message);}
    await new Promise(resolve=>setTimeout(resolve,1000));
  }
}
async function refreshStatus(){
  statusData=await api('/api/status');const text=statusData.models.text;
  $('side-status').textContent=text.length?'Models configured':'API keys needed';
  const scopes=statusData.capabilities;
  $('notice').textContent=text.length?('Connected to '+text[0].name+' · '+(statusData.knowledge.documents??0)+' knowledge documents · tools '+(scopes.web_origins.length||scopes.nmap_targets.length?'scoped':'await scope configuration')):'Add provider API keys and model IDs to chatbot/.env, then restart. Local tools and knowledge search remain available.';
  if(statusData.knowledge.error)$('notice').textContent+=' · '+statusData.knowledge.error;
  $('scope-summary').textContent='Web origins: '+(scopes.web_origins.join(', ')||'none configured')+'\nNmap IPs: '+(scopes.nmap_targets.join(', ')||'none configured')+'\nApproved ports: '+scopes.nmap_ports.join(', ')+'\nNmap: '+(scopes.tools.find(t=>t.name==='nmap_scan').available?'installed':'not installed');
  $('tool-origin').replaceChildren();for(const origin of scopes.web_origins){const option=document.createElement('option');option.value=origin;option.textContent=origin;$('tool-origin').append(option);}
  $('tool-target').replaceChildren();for(const target of scopes.nmap_targets){const option=document.createElement('option');option.value=target;option.textContent=target;$('tool-target').append(option);}
  $('tool-ports').value=scopes.nmap_ports.join(',');updateToolFields();renderTargets();
}
function updateToolFields(){const name=$('tool-name').value;$('query-group').classList.toggle('hidden',name!=='knowledge_search');$('origin-group').classList.toggle('hidden',!['web_headers','dns_lookup'].includes(name));$('nmap-group').classList.toggle('hidden',name!=='nmap_scan');$('image-group').classList.toggle('hidden',name!=='image_metadata');$('tool-image').replaceChildren();for(const image of attachments){const option=document.createElement('option');option.value=image.id;option.textContent=image.metadata.format+' · '+image.metadata.width+' × '+image.metadata.height;$('tool-image').append(option);}}
$('composer').addEventListener('submit',async event=>{
  event.preventDefault();if(activeJob)return;const message=$('message').value.trim();if(!message)return;
  try{busy(true);const job=await api('/api/chat',{method:'POST',body:{chat_id:currentChat,message,image_ids:attachments.map(x=>x.id),allow_tools:$('allow-tools').checked}});$('welcome')?.remove();renderMessage({role:'user',content:message,attachments:attachments.map(x=>x.id)});$('message').value='';attachments=[];renderAttachments();$('allow-tools').checked=false;watchJob(job.job_id);scrollBottom();}catch(error){busy(false);toast(error.message);}
});
$('message').addEventListener('keydown',event=>{if(event.key==='Enter'&&!event.shiftKey&&!event.isComposing){event.preventDefault();$('composer').requestSubmit();}});
$('new-chat').addEventListener('click',async()=>{try{attachments=[];renderAttachments();const data=await api('/api/chats',{method:'POST',body:{}});await selectChat(data.id);}catch(e){toast(e.message);}});
$('image-input').addEventListener('change',async event=>{try{await addImages(event.target.files);}catch(e){toast(e.message);}event.target.value='';});
$('message').addEventListener('paste',event=>{const files=[...event.clipboardData.items].filter(x=>x.kind==='file'&&x.type.startsWith('image/')).map(x=>x.getAsFile());if(files.length){event.preventDefault();addImages(files).catch(e=>toast(e.message));}});
$('paste').addEventListener('click',async()=>{try{const text=await navigator.clipboard.readText();$('message').setRangeText(text,$('message').selectionStart,$('message').selectionEnd,'end');$('message').focus();}catch{toast('Use Ctrl+V or your device’s paste command in the message field.');}});
$('cancel-job').addEventListener('click',async()=>{if(activeJob){try{await api('/api/jobs/'+activeJob+'/cancel',{method:'POST',body:{}});}catch(e){toast(e.message);}}});
$('export').addEventListener('click',()=>{if(currentChat)window.location.assign('/api/chats/'+currentChat+'/export');});
function toggleSidebar(show){$('sidebar').classList.toggle('open',show);$('sidebar-backdrop').classList.toggle('hidden',!show);}
$('menu').addEventListener('click',()=>toggleSidebar(!$('sidebar').classList.contains('open')));
$('close-sidebar').addEventListener('click',()=>toggleSidebar(false));
$('sidebar-backdrop').addEventListener('click',()=>toggleSidebar(false));
$('open-tools').addEventListener('click',()=>{if(activeJob){toast('Wait for the current job or stop it.');return;}$('tool-error').textContent='';$('tool-confirm').checked=false;$('tools-dialog').showModal();});
$('close-tools').addEventListener('click',()=>$('tools-dialog').close());$('tool-name').addEventListener('change',updateToolFields);
$('tool-form').addEventListener('submit',async event=>{
  event.preventDefault();if(activeJob)return;
  const tool=$('tool-name').value;let args;
  if(tool==='knowledge_search')args={query:$('tool-query').value.trim()};
  else if(tool==='nmap_scan'){const strings=$('tool-ports').value.split(',').map(x=>x.trim());if(strings.some(x=>!/^\d{1,5}$/.test(x))){$('tool-error').textContent='Enter integer ports separated by commas.';return;}args={target:$('tool-target').value,ports:strings.map(Number)};}
  else if(tool==='image_metadata')args={image_id:$('tool-image').value};else args={origin:$('tool-origin').value};
  try{const job=await api('/api/tools',{method:'POST',body:{chat_id:currentChat,tool,arguments:args,image_ids:attachments.map(x=>x.id),confirmed:$('tool-confirm').checked}});$('tools-dialog').close();watchJob(job.job_id);scrollBottom();}catch(e){$('tool-error').textContent=e.message;}
});
$('login-form').addEventListener('submit',async event=>{event.preventDefault();try{await api('/api/login',{method:'POST',body:{token:$('owner-token').value}});$('owner-token').value='';$('login-dialog').close();await boot();}catch(e){$('login-error').textContent=e.message;}});
$('login-dialog').addEventListener('cancel',event=>event.preventDefault());
$('signout').addEventListener('click',async()=>{try{await api('/api/logout',{method:'POST',body:{}});window.location.reload();}catch(e){toast(e.message);}});
async function boot(){const session=await api('/api/session');if(!session.authenticated){$('login-dialog').showModal();return;}$('signout').classList.toggle('hidden',!session.login_required);await refreshStatus();const chats=await loadChats();let selected=localStorage.getItem('sentinel-chat');if(!chats.some(c=>c.id===selected))selected=chats[0]?.id;if(!selected)selected=(await api('/api/chats',{method:'POST',body:{}})).id;await selectChat(selected);}
if(!window.marked||!window.DOMPurify||!window.hljs){$('notice').textContent='Required local UI libraries are missing. See static/vendor/README.md.';}else boot().catch(error=>{$('notice').textContent=error.message;});
if(window.ResizeObserver)new ResizeObserver(entries=>document.documentElement.style.setProperty('--composer-height',entries[0].target.getBoundingClientRect().height+'px')).observe(document.querySelector('.composer-area'));

function renderTargets(){
  const box=$('saved-targets');box.replaceChildren();
  if(!statusData)return;
  for(const [kind,title,values] of [['web','Websites',statusData.capabilities.web_origins],['nmap','Nmap IPs',statusData.capabilities.nmap_targets]]){
    const heading=document.createElement('h3');heading.textContent=title;box.append(heading);
    if(!values.length){const empty=document.createElement('p');empty.textContent='No targets saved.';box.append(empty);}
    for(const value of values){
      const row=document.createElement('div');row.className='target-row';const name=document.createElement('span');name.textContent=value;
      const remove=document.createElement('button');remove.type='button';remove.className='quiet';remove.textContent='Remove';remove.setAttribute('aria-label','Remove '+value);
      remove.addEventListener('click',async()=>{remove.disabled=true;try{await api('/api/targets',{method:'POST',body:{action:'remove',kind,value}});await refreshStatus();toast('Target removed.');}catch(error){$('target-error').textContent=error.message;remove.disabled=false;}});
      row.append(name,remove);box.append(row);
    }
  }
}
$('open-targets').addEventListener('click',()=>{$('target-error').textContent='';renderTargets();$('targets-dialog').showModal();});
$('close-targets').addEventListener('click',()=>$('targets-dialog').close());
$('target-kind').addEventListener('change',()=>{
  const network=$('target-kind').value==='nmap';$('target-value').value='';$('target-confirm').checked=false;
  $('target-value').placeholder=network?'192.168.1.20':'https://your-website.example';
  $('target-help').textContent=network?'Approve a literal infrastructure IP separately. Website ownership does not grant permission to scan shared hosting IPs. Ports use your configured Nmap list.':'Use the HTTPS origin only, without a page path.';
});
$('target-form').addEventListener('submit',async event=>{
  event.preventDefault();$('target-error').textContent='';$('save-target').disabled=true;
  try{
    await api('/api/targets',{method:'POST',body:{action:'add',kind:$('target-kind').value,value:$('target-value').value.trim(),confirmed:$('target-confirm').checked}});
    await refreshStatus();$('target-value').value='';$('target-confirm').checked=false;toast('Target saved. Ready for checks.');
  }catch(error){$('target-error').textContent=error.message;}
  finally{$('save-target').disabled=false;}
});
