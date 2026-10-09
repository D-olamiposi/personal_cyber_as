import os,sys,tempfile,time
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'chatbot'))
from streamlit.testing.v1 import AppTest
os.environ['APP_ACCESS_TOKEN']='test-owner-token-0123456789abcdef'
os.environ['APP_DATA_DIR']=tempfile.mkdtemp()
for name in ['GROQ_API_KEY','XAI_API_KEY']:os.environ.pop(name,None)
at=AppTest.from_file(str(root/'streamlit_app.py'),default_timeout=20).run()
assert not at.exception,at.exception
assert any('private workspace' in x.value for x in at.title)
at.text_input[0].set_value(os.environ['APP_ACCESS_TOKEN'])
at.button[0].click().run()
assert not at.exception,at.exception
assert not any(x.label=='Target type' for x in at.selectbox)
next(x for x in at.radio if x.label=='Workspace').set_value('Targets').run()
# Add a target through the real form.
next(x for x in at.text_input if x.label=='Target').set_value('https://streamlit-test.example')
next(x for x in at.checkbox if x.label.startswith('I own')).check()
next(x for x in at.button if x.label=='Add target').click().run()
assert not at.exception,at.exception
assert any('streamlit-test.example' in x.value for x in at.markdown)
# Run the local knowledge adapter; no provider requests.
next(x for x in at.radio if x.label=='Workspace').set_value('Assessments').run()
next(x for x in at.radio if x.label=='Workspace').set_value('Assessments').run()
next(x for x in at.text_input if x.label=='Search query').set_value('SSRF')
next(x for x in at.checkbox if x.label.startswith('I authorize')).check().run()
next(x for x in at.button if x.label=='Run check').click().run()
time.sleep(.2);at.run()
assert not at.exception,at.exception
assert any(x.label=='Evidence downloads' for x in at.expander)
next(x for x in at.button if x.label=='Verify evidence').click().run()
assert any('Verified:' in x.value for x in at.success)
assert not at.exception,at.exception
next(x for x in at.radio if x.label=='Workspace').set_value('Readiness').run()
assert not at.exception,at.exception
assert any(x.label=='Collect sample' and x.disabled for x in at.button)
next(x for x in at.radio if x.label=='Workspace').set_value('Code & terminal').run()
assert not at.exception,at.exception
assert any(x.label=='Run cell' and x.disabled for x in at.button)
next(x for x in at.radio if x.label=='Execution mode').set_value('shell').run()
assert not at.exception,at.exception
assert any(x.label=='Run command' and x.disabled for x in at.button)
next(x for x in at.radio if x.label=='Workspace').set_value('Tools setup').run()
assert not at.exception,at.exception
assert any(x.label=='Burp Suite · remote desktop' for x in at.expander)
print('EC2 and Burp setup view: PASS')
print('New readiness and code/terminal views with unconfigured execution disabled: PASS')
print('Streamlit login, targets, background local tool, evidence and hash verification: PASS')
import streamlit as st
st.cache_resource.clear()
