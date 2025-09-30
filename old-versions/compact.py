import winrm
import os
import json
import re
import yaml
from groq import Groq
from dotenv import load_dotenv
import time
from typing import Dict, List, Optional
from dataclasses import dataclass

#
# ─── CORE WINRM & CONFIG CLASSES ───────────────────────────────────────────────
#

class WinRMConnection:
    """Handles WinRM connection and command execution"""
    def __init__(self, host: str, username: str, password: str):
        self.host = host
        self.username = username
        self.password = password
        self.session = None
        self.connect()
    
    def connect(self):
        try:
            endpoint = f'http://{self.host}:5985/wsman'
            self.session = winrm.Session(endpoint, auth=(self.username, self.password))
            print(f"✅ Connected to {self.host}")
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            raise
    
    def run_command(self, command: str) -> Dict:
        if not self.session:
            raise Exception("No active session")
        try:
            result = self.session.run_cmd(command)
            return {
                'status': result.status_code,
                'stdout': result.std_out.decode('latin-1').strip(),
                'stderr': result.std_err.decode('latin-1').strip(),
                'success': result.status_code == 0
            }
        except Exception as e:
            return {
                'status': -1,
                'stdout': '',
                'stderr': str(e),
                'success': False
            }

class SecurityChecker:
    """Safety checks for commands"""
    BLOCKED_COMMANDS = [
        'del', 'format', 'shutdown', 'restart', 'rm -rf', 
        'reg delete', 'bcdedit', 'diskpart', 'cipher /w'
    ]
    
    @staticmethod
    def is_safe_command(command: str) -> bool:
        cl = command.lower()
        return not any(blocked in cl for blocked in SecurityChecker.BLOCKED_COMMANDS)

class YAMLConfigLoader:
    """Loads enumeration and privilege methods from YAML or defaults"""
    def __init__(self, enum_file: str='enum.yaml', priv_file: str='priv.yaml'):
        self.enum_file = enum_file
        self.priv_file = priv_file
        self.enum_methods: List[Dict] = []
        self.priv_methods: List[Dict] = []
        self.load_configs()
    
    def load_configs(self):
        try:
            if os.path.exists(self.enum_file):
                with open(self.enum_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    self.enum_methods = data.get('methods', data) if data else []
                print(f"✅ Loaded {len(self.enum_methods)} enumeration methods")
            else:
                print(f"⚠️  {self.enum_file} not found, using defaults")
                self.enum_methods = self._get_default_enum_methods()
            
            if os.path.exists(self.priv_file):
                with open(self.priv_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    self.priv_methods = data.get('methods', data) if data else []
                print(f"✅ Loaded {len(self.priv_methods)} privilege methods")
            else:
                print(f"⚠️  {self.priv_file} not found, using defaults")
                self.priv_methods = self._get_default_priv_methods()
        
        except Exception as e:
            print(f"❌ Error loading configs: {e}")
            self.enum_methods = self._get_default_enum_methods()
            self.priv_methods = self._get_default_priv_methods()
    
    def _get_default_enum_methods(self) -> List[Dict]:
        return [
            {"name":"Current User","category":"user_info","description":"Get current user info","command":"whoami","indicators":["\\"],"priority":1},
            {"name":"User Privileges","category":"privileges","description":"Check user privileges","command":"whoami /priv","indicators":["SeDebugPrivilege","SeTakeOwnershipPrivilege","SeBackupPrivilege"],"priority":1},
            {"name":"User Groups","category":"group_membership","description":"Check group memberships","command":"whoami /groups","indicators":["Administrators","BUILTIN\\Administrators"],"priority":1},
            {"name":"System Information","category":"system_info","description":"Get system info","command":"systeminfo","indicators":["OS Name","OS Version"],"priority":2},
        ]
    
    def _get_default_priv_methods(self) -> List[Dict]:
        return [
            {"name":"Service Enumeration","category":"service_enum","description":"List services","command":"sc query","indicators":["SERVICE_NAME"],"priority":2},
            {"name":"Scheduled Tasks","category":"scheduled_tasks","description":"List tasks","command":"schtasks /query /fo LIST /v","indicators":["TaskName","Run As User"],"priority":3},
            {"name":"Startup Programs","category":"registry","description":"Check Run key","command":"reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","indicators":["REG_SZ","REG_EXPAND_SZ"],"priority":3},
        ]
    
    def get_all_methods(self, method_type: str='enum') -> List[Dict]:
        return self.enum_methods if method_type=='enum' else self.priv_methods
    
    def get_methods_by_category(self, category: str, method_type: str='enum') -> List[Dict]:
        methods = self.get_all_methods(method_type)
        return [m for m in methods if m.get('category')==category]

#
# ─── RECON MODULE ────────────────────────────────────────────────────────────────
#

class ReconModule:
    """Runs enumeration commands from YAMLConfigLoader"""
    def __init__(self, config_loader: YAMLConfigLoader):
        self.config_loader = config_loader
    
    def run_enumeration_by_category(self, connection: WinRMConnection, category: str) -> Dict:
        results = {}
        methods = self.config_loader.get_methods_by_category(category, 'enum')
        for m in methods:
            name = m['name'].lower().replace(' ','_')
            print(f"🔍 {m['name']}...")
            res = connection.run_command(m['command'])
            results[name] = {**res, 'method': m}
            if res['success']:
                inds = [i for i in m.get('indicators',[]) if i.lower() in res['stdout'].lower()]
                if inds: print(f"  ✅ Indicators: {inds}")
        return results

    def run_full_enumeration(self, connection: WinRMConnection, max_attempts: int=20) -> Dict:
        results = {"successful":[], "failed":[], "findings":{}, "categories_covered": set(), "total_attempts":0}
        methods = sorted(self.config_loader.get_all_methods('enum'), key=lambda x:x.get('priority',5))
        for i,m in enumerate(methods):
            if i>=max_attempts: break
            cmd = m['command']
            print(f"🔎 [{i+1}] {m['name']}: {cmd}")
            if not SecurityChecker.is_safe_command(cmd):
                results['failed'].append({"method":m,"reason":"blocked"})
                continue
            r = connection.run_command(cmd)
            results['total_attempts']+=1
            results['categories_covered'].add(m['category'])
            if r['success']:
                results['successful'].append({"method":m,"result":r})
                inds = [i for i in m.get('indicators',[]) if i.lower() in r['stdout'].lower()]
                if inds:
                    results['findings'].setdefault(m['category'],[]).append({"method":m,"indicators":inds,"output":r['stdout']})
            else:
                results['failed'].append({"method":m,"result":r})
            time.sleep(0.3)
        return results

#
# ─── CONTEXT & VECTOR ANALYSIS ──────────────────────────────────────────────────
#

@dataclass
class EscalationVector:
    name: str
    category: str
    confidence: float
    indicators: List[str]
    method: Dict
    reasoning: str

class ContextAnalyzer:
    """Extracts structured findings from raw enum output"""
    def __init__(self):
        self.privilege_patterns = {
            'SeDebugPrivilege': r'SeDebugPrivilege\s+.*?Enabled',
            'SeImpersonatePrivilege': r'SeImpersonatePrivilege\s+.*?Enabled',
            'SeBackupPrivilege': r'SeBackupPrivilege\s+.*?Enabled',
        }
        self.service_patterns = {
            'unquoted_path_service': r'BINARY_PATH_NAME\s*:\s*[^"]*\.exe',
        }
        self.task_patterns = {
            'system_task': r'Run As User:\s*SYSTEM',
        }
        self.registry_patterns = {
            'autorun_entry': r'REG_SZ\s+([^\s]+\.exe)',
        }
        self.file_patterns = {
            'writable_system_file': r'(Everyone|Users).*?Full Control.*?([A-Z]:\\Windows\\System32\\.*?\.exe)',
        }
    
    def build_context_map(self, enum_results: Dict) -> Dict:
        ctx = {
            'privileges':{},
            'services':[],
            'tasks':[],
            'registry_keys':[],
            'files':[],
            'groups':[],
        }
        for entry in enum_results.get('successful', []):
            m = entry['method']; out = entry['result']['stdout']
            cat = m['category']
            if 'priv' in cat:
                for k,p in self.privilege_patterns.items():
                    if re.search(p, out, re.IGNORECASE):
                        ctx['privileges'][k] = True
            if 'service' in cat:
                for name,pat in self.service_patterns.items():
                    for match in re.findall(pat, out, re.IGNORECASE):
                        ctx['services'].append(name)
            if 'scheduled_tasks' in cat:
                if re.search(self.task_patterns['system_task'], out, re.IGNORECASE):
                    ctx['tasks'].append('system_task')
            if 'registry' in cat:
                for match in re.findall(self.registry_patterns['autorun_entry'], out, re.IGNORECASE):
                    ctx['registry_keys'].append('autorun_entry')
            if 'file_permissions' in cat or 'icacls' in m['command']:
                for _,fp in re.findall(self.file_patterns['writable_system_file'], out, re.IGNORECASE):
                    ctx['files'].append('writable_system_file')
        return ctx

class EscalationVectorAnalyzer:
    """Matches context against rule-set to pick vectors"""
    def __init__(self):
        self.rules = {
            'token_impersonation': {
                'required_privileges':['SeImpersonatePrivilege'],
                'confidence_base':0.9,'priority':1,'description':'SeImpersonatePrivilege abuse'
            },
            'debug_privilege_abuse': {
                'required_privileges':['SeDebugPrivilege'],
                'confidence_base':0.8,'priority':2,'description':'SeDebugPrivilege abuse'
            },
            'service_binary_hijacking': {
                'required_services':['unquoted_path_service'],
                'confidence_base':0.8,'priority':2,'description':'Unquoted service path'
            },
            'scheduled_task_hijacking': {
                'required_tasks':['system_task'],
                'confidence_base':0.7,'priority':3,'description':'SYSTEM task hijack'
            },
            'registry_persistence': {
                'required_registry':['autorun_entry'],
                'confidence_base':0.6,'priority':4,'description':'Autorun registry'
            },
            'file_overwrite': {
                'required_files':['writable_system_file'],
                'confidence_base':0.7,'priority':3,'description':'Overwrite system file'
            },
        }
    
    def analyze_vectors(self, ctx: Dict) -> List[EscalationVector]:
        vecs = []
        for name,rule in self.rules.items():
            conf = 0.0
            # privileges
            reqp = rule.get('required_privileges',[])
            if reqp:
                matches = sum(1 for p in reqp if ctx['privileges'].get(p))
                conf += rule['confidence_base'] * (matches/len(reqp))
            # services
            reqs = rule.get('required_services',[])
            if reqs:
                matches = sum(1 for s in reqs if s in ctx['services'])
                conf += rule['confidence_base'] * (matches/len(reqs))
            # tasks
            reqt = rule.get('required_tasks',[])
            if reqt:
                matches = sum(1 for t in reqt if t in ctx['tasks'])
                conf += rule['confidence_base'] * (matches/len(reqt))
            # registry
            reqr = rule.get('required_registry',[])
            if reqr:
                matches = sum(1 for r in reqr if r in ctx['registry_keys'])
                conf += rule['confidence_base'] * (matches/len(reqr))
            # files
            reqf = rule.get('required_files',[])
            if reqf:
                matches = sum(1 for f in reqf if f in ctx['files'])
                conf += rule['confidence_base'] * (matches/len(reqf))
            if conf>0:
                inds = []
                for key in ['privileges','services','tasks','registry_keys','files']:
                    for item in (reqp if key=='privileges' else
                                 reqs if key=='services' else
                                 reqt if key=='tasks' else
                                 reqr if key=='registry_keys' else
                                 reqf):
                        if (key=='privileges' and ctx['privileges'].get(item)) or \
                           (key!='privileges' and item in ctx[key]):
                            inds.append(f"{key}:{item}")
                vecs.append(EscalationVector(
                    name=name,
                    category=name,
                    confidence=min(conf,1.0),
                    indicators=inds,
                    method={},
                    reasoning=rule['description']
                ))
        vecs.sort(key=lambda v:(-v.confidence, self.rules[v.name]['priority']))
        return vecs

#
# ─── ENHANCED BATCH MODULE ──────────────────────────────────────────────────────
#

class EnhancedBatchModule:
    """Context-aware privilege escalation"""
    def __init__(self, connection, security, recon, config_loader):
        self.connection = connection
        self.security = security
        self.recon = recon
        self.config_loader = config_loader
        self.context_analyzer = ContextAnalyzer()
        self.vector_analyzer = EscalationVectorAnalyzer()
    
    def run_context_aware_privilege_escalation(self, enum_results: Dict, max_attempts: int = 10) -> Dict:
        print("\n🧠 Context-Aware Privilege Escalation")
        ctx = self.context_analyzer.build_context_map(enum_results)
        vectors = self.vector_analyzer.analyze_vectors(ctx)
        print(f"  → Found {len(vectors)} vectors")
        
        results = {"total_attempts":0,"successful":[],"failed":[],"escalation_successful":False,"vectors":vectors}
        if not vectors:
            return self._fallback(max_attempts)
        
        for vec in vectors[:max_attempts]:
            # pick matching methods
            methods = [m for m in self.config_loader.get_all_methods('priv')
                       if vec.name in m.get('name','').lower() or m.get('category')==vec.name]
            if not methods:
                continue
            m = sorted(methods, key=lambda x:x.get('priority',5))[0]
            cmd = m['command']
            if not self.security.is_safe_command(cmd):
                results['failed'].append({'vector':vec.name,'reason':'blocked'})
                continue
            print(f"▶️  Trying {vec.name} via {m['name']}: {cmd}")
            r = self.connection.run_command(cmd)
            results['total_attempts']+=1
            if r['success'] and self._generic_admin_check(r):
                print("🏆 Escalation succeeded!")
                results['successful'].append({'vector':vec.name,'method':m,'result':r})
                results['escalation_successful']=True
                return results
            elif r['success']:
                results['successful'].append({'vector':vec.name,'method':m,'result':r})
            else:
                results['failed'].append({'vector':vec.name,'method':m,'result':r})
        return self._fallback(max_attempts)
    
    def _fallback(self, max_attempts:int) -> Dict:
        print("\n⚠️  Fallback to traditional escalation")
        methods = sorted(self.config_loader.get_all_methods('priv'), key=lambda x:x.get('priority',5))[:max_attempts]
        results={"total_attempts":0,"successful":[],"failed":[],"escalation_successful":False}
        for m in methods:
            cmd=m['command']
            if not self.security.is_safe_command(cmd):
                results['failed'].append({'method':m,'reason':'blocked'}); continue
            print(f"▶️  Fallback try {m['name']}: {cmd}")
            r=self.connection.run_command(cmd)
            results['total_attempts']+=1
            if r['success'] and self._generic_admin_check(r):
                print("🏆 Fallback succeeded!")
                results['successful'].append({'method':m,'result':r})
                results['escalation_successful']=True
                return results
            elif r['success']:
                results['successful'].append({'method':m,'result':r})
            else:
                results['failed'].append({'method':m,'result':r})
        print("❌ No escalation achieved")
        return results
    
    def _generic_admin_check(self, r:Dict) -> bool:
        o=r.get('stdout','').lower()
        inds=['administrators','nt authority\\system','sedebugprivilege']
        return any(i in o for i in inds)

#
# ─── AI ASSISTANT ───────────────────────────────────────────────────────────────
#

class AIAssistant:
    """Wraps Groq for command suggestions"""
    def __init__(self, api_key:str):
        self.client = Groq(api_key=api_key)
        self.model = "qwen/qwen3-32b"
    
    def get_suggestion(self, context:str, objective:str) -> Dict:
        system = """You are a Windows pentest command generator...
Respond with JSON {"command": "...", "reason": "..."} only."""
        messages = [
            {"role":"system","content":system},
            {"role":"user","content":f"Objective: {objective}\nContext: {context}\nJSON response:"}
        ]
        try:
            comp = self.client.chat.completions.create(
                model=self.model, messages=messages,
                temperature=0.0, max_completion_tokens=150
            )
            txt = comp.choices[0].message.content
            # aggressive JSON parse
            match = re.search(r'\{.*\}', txt, re.DOTALL)
            if match:
                return json.loads(match.group(0))
        except:
            pass
        return {"command":"whoami /priv","reason":"fallback"}

#
# ─── AGENT ENTRYPOINT ──────────────────────────────────────────────────────────
#

class PentestAgent:
    def __init__(self, config_file:str='.env', enum_file:str='enum.yaml', priv_file:str='priv.yaml'):
        load_dotenv(config_file)
        self.config_loader = YAMLConfigLoader(enum_file, priv_file)
        self.connection = WinRMConnection(
            host=os.getenv('TARGET_HOST'),
            username=os.getenv('TARGET_USER'),
            password=os.getenv('TARGET_PASS')
        )
        self.recon = ReconModule(self.config_loader)
        self.security = SecurityChecker()
        self.batch = EnhancedBatchModule(self.connection, self.security, self.recon, self.config_loader)
        self.ai = AIAssistant(os.getenv('GROQ_API_KEY'))
    
    def run(self):
        print("🚀 Starting Pentest Agent")
        enum_results = self.recon.run_full_enumeration(self.connection, max_attempts=15)
        # you can still analyze or print findings here...
        escal_results = self.batch.run_context_aware_privilege_escalation(enum_results, max_attempts=10)
        if escal_results.get('escalation_successful'):
            print("✅ Overall escalation succeeded")
        else:
            print("❌ Overall escalation failed")
    
    def run_interactive_mode(self):
        print("Interactive mode not shown for brevity")

def main():
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument('--mode',choices=['auto','interactive'],default='auto')
    p.add_argument('--enum-file',default='enum.yaml')
    p.add_argument('--priv-file',default='priv.yaml')
    p.add_argument('--config',default='.env')
    args=p.parse_args()
    agent=PentestAgent(args.config, args.enum_file, args.priv_file)
    if args.mode=='auto':
        agent.run()
    else:
        agent.run_interactive_mode()

if __name__=='__main__':
    main()
