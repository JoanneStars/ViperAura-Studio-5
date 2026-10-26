import sqlite3
import pytest
from engine import validate_target,classify,scan_target,get_run,compare_runs,nvd_candidates
from reporting import generate_report

@pytest.mark.parametrize('ip',['127.0.0.1','192.168.1.10','10.0.0.3','172.16.5.8'])
def test_valid(ip):assert validate_target(ip)==ip
@pytest.mark.parametrize('ip',['8.8.8.8','192.168.1.0/24','example.com','1.1.1.1;whoami','224.0.0.1','0.0.0.0'])
def test_invalid(ip):
    with pytest.raises(ValueError):validate_target(ip)
def test_rule_not_claim_confirmed():assert classify('ssh')[0]=='INFO'
class FakeScanner:
    def scan(self,hosts,arguments,ports=None):
        assert hosts=='127.0.0.1'
        assert '--top-ports 100' in arguments or (ports=='22' and '-sV' in arguments)
    def all_hosts(self):return ['127.0.0.1']
    def __getitem__(self,host):return FakeHost()
class FakeHost:
    def all_protocols(self):return ['tcp']
    def __getitem__(self,proto):return {22:{'name':'ssh','state':'open','product':'OpenSSH','version':'9.2'},80:{'name':'http','state':'closed'}}
def test_end_to_end(tmp_path):
    db=tmp_path/'test.db'
    with pytest.raises(PermissionError):scan_target('127.0.0.1',db=db,scanner_factory=FakeScanner)
    a,findings=scan_target('127.0.0.1',True,db=db,scanner_factory=FakeScanner)
    b,_=scan_target('127.0.0.1',True,db=db,scanner_factory=FakeScanner)
    assert len(findings)==1 and findings[0]['port']==22
    assert len(get_run(a,db)[1])==1
    assert compare_runs(a,b,db)=={'new':[],'removed':[],'unchanged':1}
    file=generate_report(a,db=db,outdir=tmp_path/'reports')
    assert file.exists() and file.stat().st_size>1000
class FakeResponse:
    def raise_for_status(self):pass
    def json(self):return {'vulnerabilities':[{'cve':{'id':'CVE-2020-0001','descriptions':[{'lang':'en','value':'Research lead only'}],'metrics':{'cvssMetricV31':[{'cvssData':{'baseScore':6.5,'baseSeverity':'MEDIUM'}}]}}}]}
class FakeSession:
    def get(self,*args,**kwargs):
        assert kwargs['params']['keywordSearch']=='OpenSSH 9.2'
        return FakeResponse()
def test_nvd_marked_unverified():
    results=nvd_candidates('OpenSSH','9.2',session=FakeSession())
    assert results[0]['lookup']=='KEYWORD_CANDIDATE_UNVERIFIED'
    assert results[0]['cvss']==6.5

def test_invalid_mode(tmp_path):
    with pytest.raises(ValueError):scan_target('127.0.0.1',True,db=tmp_path/'x.db',scanner_factory=FakeScanner,mode='unsafe')

def test_turbo_mode(tmp_path):
    run, findings=scan_target('127.0.0.1',True,db=tmp_path/'x.db',scanner_factory=FakeScanner,mode='turbo')
    assert len(findings)==1
