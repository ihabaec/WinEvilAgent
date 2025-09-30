import re
import json
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from collections import defaultdict

@dataclass
class EscalationVector:
    """Represents a potential privilege escalation vector"""
    name: str
    category: str
    confidence: float
    indicators: List[str]
    method: Dict
    reasoning: str

class ContextAnalyzer:
    """Analyzes enumeration results to build actionable context"""
    
    def __init__(self):
        self.privilege_patterns = {
            'SeDebugPrivilege': r'SeDebugPrivilege\s+.*?Enabled',
            'SeImpersonatePrivilege': r'SeImpersonatePrivilege\s+.*?Enabled',
            'SeTakeOwnershipPrivilege': r'SeTakeOwnershipPrivilege\s+.*?Enabled',
            'SeBackupPrivilege': r'SeBackupPrivilege\s+.*?Enabled',
            'SeRestorePrivilege': r'SeRestorePrivilege\s+.*?Enabled',
            'SeLoadDriverPrivilege': r'SeLoadDriverPrivilege\s+.*?Enabled',
            'SeSystemtimePrivilege': r'SeSystemtimePrivilege\s+.*?Enabled',
        }
        
        self.service_patterns = {
            'unquoted_paths': r'BINARY_PATH_NAME\s*:\s*[^"]*\s+[^"]*\.exe',
            'writable_service_binary': r'SERVICE_NAME:\s*(\w+)',
            'service_permissions': r'SERVICE_NAME:\s*(\w+).*?START_TYPE.*?AUTO_START'
        }
        
        self.group_patterns = {
            'administrators': r'BUILTIN\\Administrators|Administrators.*?Group',
            'backup_operators': r'BUILTIN\\Backup Operators|Backup Operators.*?Group',
            'print_operators': r'BUILTIN\\Print Operators|Print Operators.*?Group',
            'server_operators': r'BUILTIN\\Server Operators|Server Operators.*?Group'
        }
        
        self.task_patterns = {
            'system_tasks': r'Run As User:\s*SYSTEM',
            'writable_task_binary': r'Task To Run:\s*([^\\]*\\)*([^\\]+\.exe)',
            'user_tasks': r'Run As User:\s*([^\\]+\\)?(\w+)'
        }
        
        self.registry_patterns = {
            'autorun_entries': r'REG_SZ\s+([^\s]+\.exe)',
            'run_keys': r'Run\s+REG_SZ\s+([^\s]+)',
            'startup_entries': r'Startup.*?REG_SZ\s+([^\s]+\.exe)'
        }
        
        self.file_patterns = {
            'writable_system_files': r'(Everyone|Users).*?Full Control.*?([A-Z]:\\Windows\\System32\\.*?\.exe)',
            'dll_hijacking': r'(Everyone|Users).*?Write.*?([A-Z]:\\.*?\.dll)',
            'weak_permissions': r'(Everyone|Users|Authenticated Users).*?(Full Control|Write)'
        }

    def build_context_map(self, enum_results: Dict) -> Dict:
        """Build a comprehensive context map from enumeration results"""
        context_map = {
            'privileges': {},
            'services': [],
            'groups': [],
            'tasks': [],
            'registry_keys': [],
            'files': [],
            'network': [],
            'processes': [],
            'raw_findings': {},
            'confidence_scores': {}
        }
        
        # Process successful enumeration results
        for result_key, result_data in enum_results.get('successful', []):
            if isinstance(result_data, dict) and 'result' in result_data:
                output = result_data['result']['stdout']
                method_info = result_data.get('method', {})
                category = method_info.get('category', 'unknown')
                
                # Analyze based on method category
                if category == 'privileges' or 'priv' in method_info.get('command', '').lower():
                    self._analyze_privileges(output, context_map)
                elif category == 'group_membership' or 'groups' in method_info.get('command', '').lower():
                    self._analyze_groups(output, context_map)
                elif category == 'service_enum' or 'service' in method_info.get('command', '').lower():
                    self._analyze_services(output, context_map)
                elif category == 'scheduled_tasks' or 'schtasks' in method_info.get('command', '').lower():
                    self._analyze_tasks(output, context_map)
                elif category == 'registry' or 'reg query' in method_info.get('command', '').lower():
                    self._analyze_registry(output, context_map)
                elif category == 'file_permissions' or 'icacls' in method_info.get('command', '').lower():
                    self._analyze_file_permissions(output, context_map)
                elif category == 'process_enum' or 'tasklist' in method_info.get('command', '').lower():
                    self._analyze_processes(output, context_map)
                elif category == 'network_enum' or 'netstat' in method_info.get('command', '').lower():
                    self._analyze_network(output, context_map)
                
                # Store raw findings for reference
                context_map['raw_findings'][result_key] = {
                    'output': output,
                    'method': method_info,
                    'category': category
                }
        
        # Process explicit findings with indicators
        for category, findings in enum_results.get('findings', {}).items():
            for finding in findings:
                output = finding['output']
                indicators = finding.get('indicators', [])
                
                # Store indicators for confidence scoring
                context_map['confidence_scores'][category] = len(indicators)
                
                # Re-analyze with known indicators
                if category == 'privileges':
                    self._analyze_privileges(output, context_map, indicators)
                elif category == 'services':
                    self._analyze_services(output, context_map, indicators)
                # Add more category-specific analysis as needed
        
        return context_map
    
    def _analyze_privileges(self, output: str, context_map: Dict, indicators: List[str] = None):
        """Analyze privilege enumeration output"""
        for priv_name, pattern in self.privilege_patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                context_map['privileges'][priv_name] = {
                    'enabled': True,
                    'found_in': 'privilege_enum',
                    'confidence': 0.9 if indicators and any(priv_name in ind for ind in indicators) else 0.7
                }
        
        # Look for specific privilege indicators
        if indicators:
            for indicator in indicators:
                if 'Privilege' in indicator and 'Enabled' in output:
                    context_map['privileges'][indicator] = {
                        'enabled': True,
                        'found_in': 'indicator_match',
                        'confidence': 0.95
                    }
    
    def _analyze_groups(self, output: str, context_map: Dict, indicators: List[str] = None):
        """Analyze group membership output"""
        for group_name, pattern in self.group_patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                context_map['groups'].append({
                    'name': group_name,
                    'type': 'builtin',
                    'confidence': 0.9,
                    'found_in': 'group_enum'
                })
        
        # Check for administrator group specifically
        if re.search(r'BUILTIN\\Administrators', output, re.IGNORECASE):
            context_map['groups'].append({
                'name': 'administrators',
                'type': 'admin',
                'confidence': 0.95,
                'found_in': 'group_enum'
            })
    
    def _analyze_services(self, output: str, context_map: Dict, indicators: List[str] = None):
        """Analyze service enumeration output"""
        # Look for unquoted service paths
        unquoted_matches = re.findall(self.service_patterns['unquoted_paths'], output, re.IGNORECASE)
        for match in unquoted_matches:
            context_map['services'].append({
                'name': 'unquoted_path_service',
                'path': match,
                'vulnerability': 'unquoted_service_path',
                'confidence': 0.8,
                'found_in': 'service_enum'
            })
        
        # Look for service names that might be vulnerable
        service_matches = re.findall(self.service_patterns['writable_service_binary'], output, re.IGNORECASE)
        for service_name in service_matches:
            context_map['services'].append({
                'name': service_name,
                'vulnerability': 'potential_service_binary_hijacking',
                'confidence': 0.6,
                'found_in': 'service_enum'
            })
    
    def _analyze_tasks(self, output: str, context_map: Dict, indicators: List[str] = None):
        """Analyze scheduled tasks output"""
        # Look for SYSTEM tasks
        system_tasks = re.findall(self.task_patterns['system_tasks'], output, re.IGNORECASE)
        for task in system_tasks:
            context_map['tasks'].append({
                'type': 'system_task',
                'run_as': 'SYSTEM',
                'vulnerability': 'scheduled_task_hijacking',
                'confidence': 0.7,
                'found_in': 'task_enum'
            })
        
        # Look for writable task binaries
        task_binaries = re.findall(self.task_patterns['writable_task_binary'], output, re.IGNORECASE)
        for binary in task_binaries:
            context_map['tasks'].append({
                'type': 'writable_task_binary',
                'binary': binary,
                'vulnerability': 'task_binary_hijacking',
                'confidence': 0.6,
                'found_in': 'task_enum'
            })
    
    def _analyze_registry(self, output: str, context_map: Dict, indicators: List[str] = None):
        """Analyze registry output"""
        # Look for autorun entries
        autorun_matches = re.findall(self.registry_patterns['autorun_entries'], output, re.IGNORECASE)
        for entry in autorun_matches:
            context_map['registry_keys'].append({
                'type': 'autorun_entry',
                'path': entry,
                'vulnerability': 'registry_persistence',
                'confidence': 0.5,
                'found_in': 'registry_enum'
            })
    
    def _analyze_file_permissions(self, output: str, context_map: Dict, indicators: List[str] = None):
        """Analyze file permissions output"""
        # Look for writable system files
        writable_files = re.findall(self.file_patterns['writable_system_files'], output, re.IGNORECASE)
        for permissions, file_path in writable_files:
            context_map['files'].append({
                'type': 'writable_system_file',
                'path': file_path,
                'permissions': permissions,
                'vulnerability': 'file_overwrite',
                'confidence': 0.8,
                'found_in': 'file_enum'
            })
    
    def _analyze_processes(self, output: str, context_map: Dict, indicators: List[str] = None):
        """Analyze running processes"""
        # Look for high-privilege processes
        lines = output.split('\n')
        for line in lines:
            if 'SYSTEM' in line or 'Administrator' in line:
                parts = line.split()
                if len(parts) >= 2:
                    context_map['processes'].append({
                        'name': parts[0],
                        'pid': parts[1] if len(parts) > 1 else 'unknown',
                        'user': 'SYSTEM' if 'SYSTEM' in line else 'Administrator',
                        'confidence': 0.6,
                        'found_in': 'process_enum'
                    })
    
    def _analyze_network(self, output: str, context_map: Dict, indicators: List[str] = None):
        """Analyze network information"""
        # Look for listening ports
        lines = output.split('\n')
        for line in lines:
            if 'LISTENING' in line:
                parts = line.split()
                if len(parts) >= 2:
                    context_map['network'].append({
                        'type': 'listening_port',
                        'address': parts[1],
                        'confidence': 0.5,
                        'found_in': 'network_enum'
                    })

class EscalationVectorAnalyzer:
    """Analyzes context to identify the most promising escalation vectors"""
    
    def __init__(self):
        self.escalation_rules = self._load_escalation_rules()
    
    def _load_escalation_rules(self) -> Dict:
        """Load escalation rules - in practice, this could be from a YAML file"""
        return {
            'token_impersonation': {
                'required_privileges': ['SeImpersonatePrivilege', 'SeAssignPrimaryTokenPrivilege'],
                'required_groups': [],
                'confidence_base': 0.9,
                'priority': 1,
                'description': 'Token impersonation via SeImpersonatePrivilege'
            },
            'debug_privilege_abuse': {
                'required_privileges': ['SeDebugPrivilege'],
                'required_groups': [],
                'confidence_base': 0.8,
                'priority': 2,
                'description': 'Process injection via SeDebugPrivilege'
            },
            'backup_privilege_abuse': {
                'required_privileges': ['SeBackupPrivilege', 'SeRestorePrivilege'],
                'required_groups': [],
                'confidence_base': 0.7,
                'priority': 3,
                'description': 'File system access via backup privileges'
            },
            'service_binary_hijacking': {
                'required_privileges': [],
                'required_groups': [],
                'required_services': ['unquoted_path_service', 'writable_service_binary'],
                'confidence_base': 0.8,
                'priority': 2,
                'description': 'Service binary hijacking'
            },
            'scheduled_task_hijacking': {
                'required_privileges': [],
                'required_groups': [],
                'required_tasks': ['system_task', 'writable_task_binary'],
                'confidence_base': 0.7,
                'priority': 3,
                'description': 'Scheduled task hijacking'
            },
            'registry_persistence': {
                'required_privileges': [],
                'required_groups': [],
                'required_registry': ['autorun_entry'],
                'confidence_base': 0.6,
                'priority': 4,
                'description': 'Registry-based persistence and escalation'
            },
            'file_overwrite': {
                'required_privileges': [],
                'required_groups': [],
                'required_files': ['writable_system_file'],
                'confidence_base': 0.7,
                'priority': 3,
                'description': 'System file overwrite'
            },
            'group_privilege_abuse': {
                'required_privileges': [],
                'required_groups': ['administrators', 'backup_operators', 'print_operators'],
                'confidence_base': 0.9,
                'priority': 1,
                'description': 'Direct group privilege abuse'
            }
        }
    
    def analyze_vectors(self, context_map: Dict) -> List[EscalationVector]:
        """Analyze context and return prioritized escalation vectors"""
        vectors = []
        
        for vector_name, rules in self.escalation_rules.items():
            confidence = self._calculate_confidence(context_map, rules)
            
            if confidence > 0.0:  # Only include vectors with some confidence
                indicators = self._extract_indicators(context_map, rules)
                
                vector = EscalationVector(
                    name=vector_name,
                    category=self._get_vector_category(vector_name),
                    confidence=confidence,
                    indicators=indicators,
                    method={},  # Will be populated later
                    reasoning=self._generate_reasoning(context_map, rules, vector_name)
                )
                vectors.append(vector)
        
        # Sort by confidence (descending) and priority (ascending)
        vectors.sort(key=lambda v: (-v.confidence, self.escalation_rules[v.name]['priority']))
        
        return vectors
    
    def _calculate_confidence(self, context_map: Dict, rules: Dict) -> float:
        """Calculate confidence score for an escalation vector"""
        confidence = 0.0
        base_confidence = rules.get('confidence_base', 0.5)
        
        # Check required privileges
        required_privs = rules.get('required_privileges', [])
        if required_privs:
            priv_matches = 0
            for priv in required_privs:
                if priv in context_map['privileges'] and context_map['privileges'][priv].get('enabled', False):
                    priv_matches += 1
            if priv_matches > 0:
                confidence += base_confidence * (priv_matches / len(required_privs))
        
        # Check required groups
        required_groups = rules.get('required_groups', [])
        if required_groups:
            group_names = [g['name'] for g in context_map['groups']]
            group_matches = sum(1 for group in required_groups if group in group_names)
            if group_matches > 0:
                confidence += base_confidence * (group_matches / len(required_groups))
        
        # Check required services
        required_services = rules.get('required_services', [])
        if required_services:
            service_vulns = [s['vulnerability'] for s in context_map['services']]
            service_matches = sum(1 for service in required_services if service in service_vulns)
            if service_matches > 0:
                confidence += base_confidence * (service_matches / len(required_services))
        
        # Check required tasks
        required_tasks = rules.get('required_tasks', [])
        if required_tasks:
            task_types = [t['type'] for t in context_map['tasks']]
            task_matches = sum(1 for task in required_tasks if task in task_types)
            if task_matches > 0:
                confidence += base_confidence * (task_matches / len(required_tasks))
        
        # Check required registry entries
        required_registry = rules.get('required_registry', [])
        if required_registry:
            registry_types = [r['type'] for r in context_map['registry_keys']]
            registry_matches = sum(1 for reg in required_registry if reg in registry_types)
            if registry_matches > 0:
                confidence += base_confidence * (registry_matches / len(required_registry))
        
        # Check required files
        required_files = rules.get('required_files', [])
        if required_files:
            file_types = [f['type'] for f in context_map['files']]
            file_matches = sum(1 for file in required_files if file in file_types)
            if file_matches > 0:
                confidence += base_confidence * (file_matches / len(required_files))
        
        return min(confidence, 1.0)  # Cap at 1.0
    
    def _extract_indicators(self, context_map: Dict, rules: Dict) -> List[str]:
        """Extract specific indicators that support this vector"""
        indicators = []
        
        # Add privilege indicators
        for priv in rules.get('required_privileges', []):
            if priv in context_map['privileges']:
                indicators.append(f"Privilege: {priv}")
        
        # Add group indicators
        for group in rules.get('required_groups', []):
            group_names = [g['name'] for g in context_map['groups']]
            if group in group_names:
                indicators.append(f"Group: {group}")
        
        # Add service indicators
        for service in rules.get('required_services', []):
            service_vulns = [s['vulnerability'] for s in context_map['services']]
            if service in service_vulns:
                indicators.append(f"Service: {service}")
        
        return indicators
    
    def _get_vector_category(self, vector_name: str) -> str:
        """Map vector name to category"""
        category_map = {
            'token_impersonation': 'token_abuse',
            'debug_privilege_abuse': 'privilege_abuse',
            'backup_privilege_abuse': 'privilege_abuse',
            'service_binary_hijacking': 'service_abuse',
            'scheduled_task_hijacking': 'task_abuse',
            'registry_persistence': 'registry_abuse',
            'file_overwrite': 'file_abuse',
            'group_privilege_abuse': 'group_abuse'
        }
        return category_map.get(vector_name, 'unknown')
    
    def _generate_reasoning(self, context_map: Dict, rules: Dict, vector_name: str) -> str:
        """Generate human-readable reasoning for this vector"""
        reasoning_parts = []
        
        if rules.get('required_privileges'):
            found_privs = [priv for priv in rules['required_privileges'] if priv in context_map['privileges']]
            if found_privs:
                reasoning_parts.append(f"Found required privileges: {', '.join(found_privs)}")
        
        if rules.get('required_groups'):
            group_names = [g['name'] for g in context_map['groups']]
            found_groups = [group for group in rules['required_groups'] if group in group_names]
            if found_groups:
                reasoning_parts.append(f"Member of required groups: {', '.join(found_groups)}")
        
        if rules.get('required_services'):
            service_vulns = [s['vulnerability'] for s in context_map['services']]
            found_services = [service for service in rules['required_services'] if service in service_vulns]
            if found_services:
                reasoning_parts.append(f"Found vulnerable services: {', '.join(found_services)}")
        
        if not reasoning_parts:
            return f"Vector {vector_name} identified based on enumeration findings"
        
        return "; ".join(reasoning_parts)

# Enhanced BatchModule methods to integrate context analysis
class EnhancedBatchModule:
    """Enhanced batch module with context-aware escalation"""
    
    def __init__(self, connection, security, recon, config_loader):
        self.connection = connection
        self.security = security
        self.recon = recon
        self.config_loader = config_loader
        self.context_analyzer = ContextAnalyzer()
        self.vector_analyzer = EscalationVectorAnalyzer()
    
    def run_context_aware_privilege_escalation(self, enum_results: Dict, max_attempts: int = 10) -> Dict:
        """Run context-aware privilege escalation"""
        print("\n🧠 Starting Context-Aware Privilege Escalation...")
        print("=" * 60)
        
        # Build context map from enumeration results
        context_map = self.context_analyzer.build_context_map(enum_results)
        
        # Analyze escalation vectors
        vectors = self.vector_analyzer.analyze_vectors(context_map)
        
        print(f"\n📊 Context Analysis Summary:")
        print(f"   • Privileges found: {len(context_map['privileges'])}")
        print(f"   • Groups found: {len(context_map['groups'])}")
        print(f"   • Services analyzed: {len(context_map['services'])}")
        print(f"   • Tasks analyzed: {len(context_map['tasks'])}")
        print(f"   • Escalation vectors identified: {len(vectors)}")
        
        if not vectors:
            print("❌ No escalation vectors identified from context analysis")
            return self._fallback_to_traditional_escalation(max_attempts)
        
        print(f"\n🎯 Top Escalation Vectors:")
        for i, vector in enumerate(vectors[:5], 1):
            print(f"   {i}. {vector.name} (Confidence: {vector.confidence:.2f})")
            print(f"      Reasoning: {vector.reasoning}")
            print(f"      Indicators: {', '.join(vector.indicators)}")
        
        # Execute escalation attempts based on vectors
        results = {
            "total_attempts": 0,
            "successful": [],
            "failed": [],
            "context_map": context_map,
            "vectors": vectors,
            "escalation_successful": False
        }
        
        for vector in vectors[:max_attempts]:
            print(f"\n🔥 Attempting: {vector.name}")
            print(f"   Confidence: {vector.confidence:.2f}")
            print(f"   Reasoning: {vector.reasoning}")
            
            # Find matching methods from config
            matching_methods = self._find_methods_for_vector(vector)
            
            if not matching_methods:
                print(f"   ❌ No matching methods found for vector: {vector.name}")
                continue
            
            # Execute the best matching method
            method = matching_methods[0]  # Take the highest priority method
            
            print(f"   📝 Executing method: {method['name']}")
            print(f"   💻 Command: {method['command']}")
            
            if not self.security.is_safe_command(method['command']):
                print("   ❌ Command blocked by safety check")
                results["failed"].append({
                    "vector": vector.name,
                    "method": method,
                    "reason": "blocked_by_safety_check"
                })
                continue
            
            result = self.connection.run_command(method['command'])
            results["total_attempts"] += 1
            
            if result['success']:
                print("   ✅ Command executed successfully")
                
                # Check if escalation was successful
                if self._check_escalation_success(result, vector, method):
                    print("   🏆 PRIVILEGE ESCALATION SUCCESSFUL!")
                    results["escalation_successful"] = True
                    results["successful"].append({
                        "vector": vector.name,
                        "method": method,
                        "result": result
                    })
                    return results
                else:
                    print("   ℹ️  Command successful but escalation not confirmed")
                    results["successful"].append({
                        "vector": vector.name,
                        "method": method,
                        "result": result
                    })
            else:
                print("   ❌ Command failed")
                print(f"   Error: {result['stderr'][:100]}...")
                results["failed"].append({
                    "vector": vector.name,
                    "method": method,
                    "result": result
                })
        
        return results
    
    def _find_methods_for_vector(self, vector: EscalationVector) -> List[Dict]:
        """Find privilege escalation methods that match a vector"""
        all_methods = self.config_loader.get_all_methods('priv')
        matching_methods = []
        
        for method in all_methods:
            method_category = method.get('category', '')
            method_name = method.get('name', '').lower()
            
            # Direct category matching
            if vector.category == method_category:
                matching_methods.append(method)
                continue
            
            # Keyword matching for specific vectors
            if vector.name == 'token_impersonation' and any(keyword in method_name for keyword in ['token', 'impersonate', 'potato']):
                matching_methods.append(method)
            elif vector.name == 'service_binary_hijacking' and any(keyword in method_name for keyword in ['service', 'binary', 'hijack']):
                matching_methods.append(method)
            elif vector.name == 'scheduled_task_hijacking' and any(keyword in method_name for keyword in ['task', 'schedule', 'hijack']):
                matching_methods.append(method)
            elif vector.name == 'debug_privilege_abuse' and any(keyword in method_name for keyword in ['debug', 'process', 'inject']):
                matching_methods.append(method)
        
        # Sort by priority
        matching_methods.sort(key=lambda m: m.get('priority', 5))
        return matching_methods
    
    def _check_escalation_success(self, result: Dict, vector: EscalationVector, method: Dict) -> bool:
        """Check if escalation was successful based on vector type"""
        if not result['success']:
            return False
        
        output = result['stdout'].lower()
        
        # Vector-specific success indicators
        if vector.name == 'token_impersonation':
            return any(indicator in output for indicator in ['system', 'nt authority\\system', 'privilege escalation'])
        elif vector.name == 'group_privilege_abuse':
            return any(indicator in output for indicator in ['administrators', 'admin', 'elevated'])
        elif vector.name in ['service_binary_hijacking', 'scheduled_task_hijacking']:
            return any(indicator in output for indicator in ['system', 'success', 'elevated'])
        
        # Generic admin checks
        admin_indicators = ['administrators', 'builtin\\administrators', 'nt authority\\system', 'sedebugprivilege']
        return any(indicator in output for indicator in admin_indicators)
    
    def _fallback_to_traditional_escalation(self, max_attempts: int) -> Dict:
        """Fallback to traditional escalation if context analysis fails"""
        print("\n⚠️  Falling back to traditional privilege escalation...")
        
        # Use existing traditional escalation logic
        priv_methods = self.config_loader.get_all_methods('priv')
        sorted_methods = sorted(priv_methods, key=lambda x: x.get('priority', 5))
        
        results = {
            "total_attempts": 0,
            "successful": [],
            "failed": [],
            "fallback_mode": True
        }
        
        for method in sorted_methods[:max_attempts]:
            print(f"\n🔧 Executing: {method['name']}")
            
            if not self.security.is_safe_command(method['command']):
                print("❌ Command blocked by safety check")
                continue
            
            result = self.connection.run_command(method['command'])
            results["total_attempts"] += 1
            
            if result['success']:
                print("✅ Command executed successfully")
                results["successful"].append({"method": method, "result": result})
                
                # Check for admin privileges
                if self._check_admin