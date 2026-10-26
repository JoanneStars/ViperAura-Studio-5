"""ViperAura Studio: local-only dashboard for authorized lab assessments."""
import os
from collections import Counter
import pandas as pd
import streamlit as st
from engine import scan_target, enrich_run, history, get_run, compare_runs, ai_explanation, REPORTS
from reporting import generate_report

st.set_page_config(page_title='ViperAura Studio', page_icon='🐍', layout='wide', initial_sidebar_state='expanded')
st.markdown('''<style>
:root {color-scheme:dark}
.stApp {background:linear-gradient(140deg,#10081e 0%,#1a0c2b 55%,#0e1022 100%); color:#f6efff}
.block-container {max-width:1380px;padding-top:2rem}
h1,h2,h3 {color:#f6eaff!important;font-family:system-ui,sans-serif!important}
.stApp p,.stApp label {font-size:1rem}
div[data-testid="stMetric"] {background:#241237;border:1px solid #7043a9;border-radius:16px;padding:19px}
div[data-testid="stMetricValue"] {color:#f2b6ff;font-size:2rem}
div[data-testid="stSidebar"] {background:#180d2a}
div.stButton>button[kind="primary"] {background:linear-gradient(90deg,#6d36bb,#ac4bd5);color:white;border:0;font-weight:700}
.va-hero {border:1px solid #8051c0;background:linear-gradient(120deg,#28113e,#3a1551 55%,#1d123f);border-radius:22px;padding:24px 30px;margin-bottom:20px}
.va-title {font-weight:900;letter-spacing:.045em;line-height:1.03;font-size:clamp(38px,6vw,78px);background:linear-gradient(90deg,#b78aff,#edabff,#a278ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.va-sub {font-weight:600;color:#ebd4ff;font-size:1.1rem;margin-top:10px;letter-spacing:.04em}
.va-note {color:#d1b9e9;font-size:.92rem;margin-top:7px}
</style>''',unsafe_allow_html=True)
st.markdown('''<div class="va-hero"><div class="va-title">🐍 VIPERAURA</div>
<div class="va-sub">STUDIO 5.0 &nbsp; / &nbsp; INTELLIGENT NETWORK EXPOSURE ASSESSMENT</div>
<div class="va-note">Fast discovery • Evidence-first security reviews • Optional AI explanations • PDF reports</div></div>''', unsafe_allow_html=True)

with st.sidebar:
    st.header('Scan control')
    target=st.text_input('Authorized lab IP',value='127.0.0.1',help='Single private or loopback IPv4/IPv6 address only')
    mode=st.radio('Scan mode',options=['turbo','smart','deep'],format_func=lambda m:{'turbo':'⚡ Turbo — top 100 ports','smart':'🔎 Smart — fast + versions','deep':'🛡️ Deep — top 1,000 + versions'}[m],index=1)
    st.caption('Turbo prioritizes speed; Smart adds service versions; Deep is more comprehensive but slower.')
    authorized=st.checkbox('I own this host or have explicit permission to scan it')
    use_nvd=st.checkbox('Research possible CVEs using NVD (opt-in)',value=False)
    make_ai=st.checkbox('Generate an AI explanation (API key required)',value=False)
    launch=st.button('⚡ Start authorized scan',type='primary',disabled=not authorized,use_container_width=True)
    st.divider()
    st.caption('Designed for local use. Do not publish this dashboard to the internet or scan unauthorized systems.')

if launch:
    try:
        with st.status('Running authorized assessment...',expanded=True) as status:
            st.write(f'Mode: {mode} • Target: {target}')
            run_id,findings=scan_target(target,consent=authorized,mode=mode)
            st.write(f'Discovered {len(findings)} open services')
            if use_nvd:
                res=enrich_run(run_id)
                st.write(f"NVD: {res['candidates']} unverified candidate links, {len(res['errors'])} lookup errors")
            explanation=None
            if make_ai:
                try:
                    explanation=ai_explanation(run_id)
                    st.session_state['ai_text']=explanation
                    st.session_state['ai_run']=run_id
                except Exception as e: st.warning(f'Optional AI unavailable: {e}')
            path=generate_report(run_id,ai_text=explanation)
            st.session_state['run_id']=run_id
            status.update(label='Assessment complete',state='complete')
        st.success(f'Completed. PDF: {path.name}')
    except Exception as exc: st.error(f'Assessment failed: {exc}')

runs=history()
if not runs:
    st.info('No scans saved yet. Select a mode in the left sidebar and scan a lab device you control.')
    st.stop()
ids=[r['id'] for r in runs]
preferred=st.session_state.get('run_id')
selected=st.selectbox('Review assessment history',ids,index=ids.index(preferred) if preferred in ids else 0,
    format_func=lambda rid:next(f"{r['started']} | {r['target']} | {r['status']} | {rid[:8]}" for r in runs if r['id']==rid))
run, findings=get_run(selected)
count=Counter(f['severity'] for f in findings)
st.subheader('Security overview')
a,b,c,d=st.columns(4)
a.metric('OPEN SERVICES',len(findings));b.metric('HIGH EXPOSURE',count['HIGH']);c.metric('MEDIUM EXPOSURE',count['MEDIUM']);d.metric('INFORMATIONAL',count['INFO'])
left,right=st.columns([2,1])
with left:
    st.subheader('Discovered services')
    table=[{'Port':f"{f['port']}/{f['protocol']}",'Service':f['service'],'Product':f['product'],'Version':f['version'],
            'Exposure':f['severity'],'Review item':f['issue'],'Recommendation':f['recommendation']} for f in findings]
    if table: st.dataframe(pd.DataFrame(table),hide_index=True,use_container_width=True)
    else: st.info('No open services detected within this scan scope. This is not proof that no vulnerabilities exist.')
with right:
    st.subheader('Exposure mix')
    st.bar_chart(pd.DataFrame({'Severity':['HIGH','MEDIUM','LOW','INFO'],'Count':[count[k] for k in ['HIGH','MEDIUM','LOW','INFO']]}).set_index('Severity'),color='#bd75ed')

with st.expander('Potential CVE research (NOT confirmed vulnerabilities)'):
    any_cve=False
    for f in findings:
        for cv in f['cves']:
            any_cve=True
            st.markdown(f"**{f['port']}/{f['protocol']} — {f['product']} {f['version']}**: [{cv['cve_id']}](https://nvd.nist.gov/vuln/detail/{cv['cve_id']}) | Published CVSS: {cv['cvss']} | **UNVERIFIED**")
    if not any_cve: st.info('No NVD research candidates stored. Opt in when scanning a service with a detectable product and version.')

st.subheader('Reports and AI')
r1,r2=st.columns(2)
with r1:
    if st.button('Regenerate PDF report'):
        generate_report(selected,ai_text=st.session_state.get('ai_text') if st.session_state.get('ai_run')==selected else None)
    report_path=REPORTS / f'ViperAura_{selected[:10]}.pdf'
    if report_path.exists():
        st.download_button('⬇ Download security report',report_path.read_bytes(),file_name=report_path.name,mime='application/pdf')
with r2:
    if st.button('✨ Generate AI remediation summary'):
        try:
            st.session_state['ai_text']=ai_explanation(selected)
            st.session_state['ai_run']=selected
        except Exception as e:st.error(f'AI unavailable: {e}')
    if st.session_state.get('ai_run')==selected and st.session_state.get('ai_text'):
        st.markdown(st.session_state['ai_text'])
        st.caption('AI narrative is assistive; do not mistake it for an independently verified vulnerability assessment.')

if len(ids)>1:
    st.subheader('Compare assessments')
    older=st.selectbox('Baseline scan',ids,index=1,format_func=lambda r:r[:10])
    newer=st.selectbox('Current scan',ids,index=0,format_func=lambda r:r[:10])
    if older!=newer:
        diff=compare_runs(older,newer)
        st.write(f"**New:** {len(diff['new'])} | **Removed:** {len(diff['removed'])} | **Unchanged:** {diff['unchanged']}")
        if diff['new']: st.write('New service endpoints:',diff['new'])
        if diff['removed']: st.write('Removed service endpoints:',diff['removed'])

st.caption('ViperAura Studio — network exposure assessment, not an exploitation framework. Results are evidence-limited.')
