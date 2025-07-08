import winrm
import os
import json
import re
import yaml
from groq import Groq
from dotenv import load_dotenv
import time
from typing import Dict, List, Optional

class WinRMConnection:
    """Handles WinRM connection and command execution"""
    
    def __init__(self, host: str, username: str, password: str):
        self.host = host
        self.username = username
        self.password = password
        self.session = None
        self.connect()
    
    def connect(self):
        """Establish WinRM connection"""
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
        """Check if command is safe to execute"""
        command_lower = command.lower()
        for blocked in SecurityChecker.BLOCKED_COMMANDS:
            if blocked in command_lower:
                return False
        return True

class YAMLConfigLoader:
    """Loads and manages YAML configuration files"""
    
    def __init__(self, enum_file: str = 'enum.yaml', priv_file: str = 'priv.yaml'):
        self.enum_file = enum_file
        self.priv_file = priv_file
        self.enum_methods = []
        self.priv_methods = []
        self.load_configs()
    
    def load_configs(self):
        """Load enumeration and privilege escalation methods from YAML files"""
        try:
            # Load enumeration methods
            if os.path.exists(self.enum_file):
                with open(self.enum_file, 'r', encoding='utf-8') as f:
                    enum_data = yaml.safe_load(f)
                    if isinstance(enum_data, dict) and 'methods' in enum_data:
                        self.enum_methods = enum_data['methods']
                    elif isinstance(enum_data, list):
                        self.enum_methods = enum_data
                    print(f"✅ Loaded {len(self.enum_methods)} enumeration methods from {self.enum_file}")
            else:
                print(f"⚠️  Enumeration file {self.enum_file} not found, using defaults")
                self.enum_methods = self._get_default_enum_methods()
            
            # Load privilege escalation methods
            if os.path.exists(self.priv_file):
                with open(self.priv_file, 'r', encoding='utf-8') as f:
                    priv_data = yaml.safe_load(f)
                    if isinstance(priv_data, dict) and 'methods' in priv_data:
                        self.priv_methods = priv_data['methods']
                    elif isinstance(priv_data, list):
                        self.priv_methods = priv_data
                    print(f"✅ Loaded {len(self.priv_methods)} privilege escalation methods from {self.priv_file}")
            else:
                print(f"⚠️  Privilege escalation file {self.priv_file} not found, using defaults")
                self.priv_methods = self._get_default_priv_methods()
                
        except yaml.YAMLError as e:
            print(f"❌ YAML parsing error: {e}")
            print("Using default methods...")
            self.enum_methods = self._get_default_enum_methods()
            self.priv_methods = self._get_default_priv_methods()
        except Exception as e:
            print(f"❌ Error loading config files: {e}")
            print("Using default methods...")
            self.enum_methods = self._get_default_enum_methods()
            self.priv_methods = self._get_default_priv_methods()
    
    def _get_default_enum_methods(self) -> List[Dict]:
        """Default enumeration methods if YAML file is not found"""
        return [
            {
                "name": "Current User",
                "category": "user_info",
                "description": "Get current user information",
                "command": "whoami",
                "indicators": ["\\"],
                "priority": 1
            },
            {
                "name": "User Privileges",
                "category": "privileges",
                "description": "Check current user privileges",
                "command": "whoami /priv",
                "indicators": ["SeDebugPrivilege", "SeTakeOwnershipPrivilege", "SeBackupPrivilege"],
                "priority": 1
            },
            {
                "name": "User Groups",
                "category": "group_membership",
                "description": "Check user group memberships",
                "command": "whoami /groups",
                "indicators": ["Administrators", "BUILTIN\\Administrators"],
                "priority": 1
            },
            {
                "name": "System Information",
                "category": "system_info",
                "description": "Get basic system information",
                "command": "systeminfo",
                "indicators": ["OS Name", "OS Version"],
                "priority": 2
            }
        ]
    
    def _get_default_priv_methods(self) -> List[Dict]:
        """Default privilege escalation methods if YAML file is not found"""
        return [
            {
                "name": "Service Enumeration",
                "category": "service_enum",
                "description": "Enumerate running services",
                "command": "sc query",
                "indicators": ["SERVICE_NAME"],
                "priority": 2
            },
            {
                "name": "Scheduled Tasks",
                "category": "scheduled_tasks",
                "description": "Enumerate scheduled tasks",
                "command": "schtasks /query /fo LIST /v",
                "indicators": ["TaskName", "Run As User"],
                "priority": 3
            },
            {
                "name": "Startup Programs",
                "category": "registry",
                "description": "Check startup programs in registry",
                "command": "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "indicators": ["REG_SZ", "REG_EXPAND_SZ"],
                "priority": 3
            }
        ]
    
    def get_methods_by_category(self, category: str, method_type: str = 'enum') -> List[Dict]:
        """Get methods filtered by category"""
        methods = self.enum_methods if method_type == 'enum' else self.priv_methods
        return [method for method in methods if method.get('category') == category]
    
    def get_all_methods(self, method_type: str = 'enum') -> List[Dict]:
        """Get all methods of specified type"""
        return self.enum_methods if method_type == 'enum' else self.priv_methods
    
    def get_methods_by_priority(self, max_priority: int = 3, method_type: str = 'enum') -> List[Dict]:
        """Get methods filtered by priority (lower number = higher priority)"""
        methods = self.enum_methods if method_type == 'enum' else self.priv_methods
        return [method for method in methods if method.get('priority', 5) <= max_priority]

class ReconModule:
    """Reconnaissance commands using YAML configuration"""
    
    def __init__(self, config_loader: YAMLConfigLoader):
        self.config_loader = config_loader
    
    def get_basic_info(self, connection: WinRMConnection) -> Dict:
        """Get basic system information using configured methods"""
        enum_methods = self.config_loader.get_methods_by_priority(max_priority=2, method_type='enum')
        results = {}
        
        for method in enum_methods:
            method_name = method['name'].lower().replace(' ', '_')
            print(f"Running {method['name']}...")
            
            result = connection.run_command(method['command'])
            results[method_name] = {
                **result,
                'method_info': method
            }
        
        return results
    
    def run_enumeration_by_category(self, connection: WinRMConnection, category: str) -> Dict:
        """Run enumeration methods for a specific category"""
        methods = self.config_loader.get_methods_by_category(category, 'enum')
        results = {}
        
        print(f"\n🔍 Running {category} enumeration...")
        for method in methods:
            method_name = method['name'].lower().replace(' ', '_')
            print(f"  • {method['name']}: {method['description']}")
            
            result = connection.run_command(method['command'])
            results[method_name] = {
                **result,
                'method_info': method
            }
            
            if result['success']:
                # Check for indicators
                found_indicators = []
                for indicator in method.get('indicators', []):
                    if indicator.lower() in result['stdout'].lower():
                        found_indicators.append(indicator)
                
                if found_indicators:
                    print(f"    ✅ Found indicators: {', '.join(found_indicators)}")
                else:
                    print(f"    ℹ️  Command executed successfully")
            else:
                print(f"    ❌ Command failed: {result['stderr'][:50]}...")
        
        return results

class AIAssistant:
    """Handles AI model interactions via Groq with improved prompting"""
    
    def __init__(self, api_key: str):
        self.client = Groq(api_key=api_key)
        self.model = "qwen/qwen3-32b" # Or another suitable model
        self.conversation_history = []
    
    def get_suggestion(self, context: str, objective: str) -> Dict:
        """Get AI suggestion for next command with improved prompting"""
        
        # Build a more comprehensive system prompt with stronger JSON enforcement
        # Modified prompt to include the ROOTED file creation goal
        system_prompt = """You are a Windows penetration testing command generator. 
Your ultimate GOAL is to first gain administrator privileges on the target system, and then, once administrator, create a file named 'ROOTED' in the 'C:\\Windows\\System32\\' directory.

CRITICAL: You must respond with ONLY a JSON object. NO explanations, NO reasoning, NO additional text outside the JSON.
Your JSON must contain two keys: "command" (the Windows command to execute) and "reason" (a brief explanation for the command).

Format: {"command": "windows_command", "reason": "brief_explanation"}

Common Windows commands for penetration testing:
- File operations: echo "content" > path\\file.txt, type file.txt
- User info: whoami, whoami /priv, whoami /groups, net user, net localgroup
- System info: systeminfo, hostname, ver, driverquery
- Network: ipconfig, arp -a, route print, netstat -ano
- Processes: tasklist, wmic process get caption,executablepath,commandline
- Services: sc query, net start, wmic service get name,displayname,pathname,startmode
- Directory: dir, tree, cd
- Registry: reg query
- Scheduled tasks: schtasks /query /fo LIST /v

Prioritize commands that lead to privilege escalation or provide more information for it.
Once you believe you have administrator privileges, the next command should be 'echo ROOTED > C:\\Windows\\System32\\rooted'.

RESPOND WITH JSON ONLY - NO OTHER TEXT."""

        messages = [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                # Truncate context if too long to stay within token limits
                "content": f"Objective: {objective}\nContext: {context[-2000:] if len(context) > 2000 else context}\n\nJSON response:"
            }
        ]
        
        try:
            completion = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.0,
                max_completion_tokens=150, # Increased token limit for slightly longer commands/reasons
                top_p=1.0,
                stream=False,
                stop=None
            )
            
            content = completion.choices[0].message.content.strip()
            print(f"[DEBUG] AI Response: {content}")
            
            # More aggressive JSON extraction
            parsed_response = self._extract_json_aggressively(content)
            
            if parsed_response:
                return parsed_response
            else:
                print(f"[DEBUG] Failed to parse AI JSON. Falling back...")
                return self._smart_fallback_command(objective, context)
                
        except Exception as e:
            print(f"[DEBUG] API Error: {e}")
            return self._smart_fallback_command(objective, context)
    
    def _extract_json_aggressively(self, content: str) -> Optional[Dict]:
        """Aggressively extract JSON from response"""
        # Remove all non-JSON text patterns that commonly appear around the JSON
        patterns_to_remove = [
            r"<think>.*?</think>",
            r"```json",
            r"```",
            r"JSON response:",
            r"Response:",
            r"Here.*?:",
            r"The.*?is:",
            r"```\s*json\s*", # Catches ```json with potential spaces
            r"\/\/.*", # Remove single line comments
            r"/\*.*?\*/", # Remove multi-line comments
            r"[^\{]*(\{.*?\})[^}]*", # Attempt to capture only the JSON part
        ]
        
        for pattern in patterns_to_remove:
            content = re.sub(pattern, "", content, flags=re.DOTALL | re.IGNORECASE)
        
        content = content.strip()
        
        # Try to find JSON brackets
        start = content.find('{')
        end = content.rfind('}')
        
        if start != -1 and end != -1 and end > start:
            json_str = content[start:end+1]
            
            try:
                parsed = json.loads(json_str)
                # Ensure it's a dict and has the expected keys
                if isinstance(parsed, dict) and 'command' in parsed and 'reason' in parsed:
                    return parsed
            except json.JSONDecodeError as jde:
                print(f"[DEBUG] JSONDecodeError: {jde} for string: {json_str[:100]}...")
                pass # Fall through to regex or smart fallback
        
        # Try to construct JSON from key-value patterns if direct JSON parsing fails
        command_match = re.search(r'["\']command["\']\s*:\s*["\']([^"\']+)["\']', content, re.IGNORECASE)
        reason_match = re.search(r'["\']reason["\']\s*:\s*["\']([^"\']+)["\']', content, re.IGNORECASE)
        
        if command_match and reason_match:
            print(f"[DEBUG] Extracted JSON using regex fallback: Cmd='{command_match.group(1)}', Reason='{reason_match.group(1)}'")
            return {
                "command": command_match.group(1),
                "reason": reason_match.group(1)
            }
        
        return None
    
    def _smart_fallback_command(self, objective: str, context: str) -> Dict:
        """Enhanced fallback with better objective parsing"""
        objective_lower = objective.lower()
        
        # Privilege escalation attempts
        if any(word in objective_lower for word in ["admin", "administrator", "escalate", "privilege", "root"]):
            if "rooted" in objective_lower and "c:\\windows\\system32\\rooted" in objective_lower:
                # If objective explicitly mentions creating the ROOTED file and gaining admin
                # This is a specific trigger for the final command
                if "administrator" in context.lower() or "sedebugprivilege" in context.lower():
                     return {
                        "command": 'echo ROOTED > C:\\Windows\\System32\\rooted',
                        "reason": "Admin privileges achieved, creating ROOTED marker file."
                    }
            return {
                "command": "whoami /priv",
                "reason": "Check current user privileges for potential escalation paths or verify admin status."
            }
        
        # File operations (more generic for file creation)
        if "create" in objective_lower and "file" in objective_lower:
            target_path_match = re.search(r'in\s+([a-zA-Z]:\\(?:[a-zA-Z0-9_\-\s]+\\)*)', objective_lower)
            target_path = target_path_match.group(1) if target_path_match else 'C:\\temp\\'
            
            filename = "test_file.txt"
            filename_match = re.search(r'file\s+named\s+([\w\d\._-]+)', objective_lower)
            if filename_match:
                filename = filename_match.group(1)
            
            content = "test content"
            content_match = re.search(r'with\s+content\s+["\']?([^"\']+?)["\']?(?:\s|$)', objective_lower)
            if content_match:
                content = content_match.group(1).strip()

            return {
                "command": f'echo "{content}" > {target_path}{filename}',
                "reason": f"Creating specified file '{filename}' in '{target_path}'"
            }
        
        # Default fallback commands based on objective keywords
        fallback_commands = {
            "whoami": {"command": "whoami", "reason": "Shows current user context"},
            "privilege": {"command": "whoami /priv", "reason": "Shows user privileges and rights"},
            "list": {"command": "dir", "reason": "Lists current directory contents"},
            "network": {"command": "netstat -an", "reason": "Shows network connections"},
            "process": {"command": "tasklist", "reason": "Shows running processes"},
            "system": {"command": "systeminfo", "reason": "Shows system information"},
            "service": {"command": "sc query", "reason": "Shows running services"},
            "users": {"command": "net user", "reason": "Lists local user accounts"},
            "group": {"command": "net localgroup", "reason": "Shows local groups"},
            "registry": {"command": "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion", "reason": "Query Windows version registry key"}
        }
        
        for keyword, cmd_info in fallback_commands.items():
            if keyword in objective_lower:
                return cmd_info
        
        # Generic fallback
        return {
            "command": "whoami", # A safe default to get some info
            "reason": "Attempting to gather basic system information due to unclear objective."
        }


class BatchModule:
    """Handles batch operations using YAML configuration"""
    
    def __init__(self, connection: WinRMConnection, security: SecurityChecker, recon: ReconModule, config_loader: YAMLConfigLoader):
        self.connection = connection
        self.security = security
        self.recon = recon
        self.config_loader = config_loader
    
    def run_enumeration_batch(self, max_attempts: int = 20) -> Dict:
        """Run automated enumeration using YAML configuration"""
        print("\n🔍 Starting automated enumeration batch mode...")
        print("=" * 60)
        
        results = {
            "total_attempts": 0,
            "successful": [],
            "failed": [],
            "findings": {},
            "categories_covered": set()
        }
        
        enum_methods = self.config_loader.get_all_methods('enum')
        sorted_methods = sorted(enum_methods, key=lambda x: x.get('priority', 5))
        
        for i, method in enumerate(sorted_methods):
            if i >= max_attempts:
                break
            
            print(f"\n[{i+1}/{min(len(sorted_methods), max_attempts)}] {method['name']}")
            print(f"Category: {method['category']}, Priority: {method['priority']}")
            print(f"Description: {method['description']}")
            print(f"Command: {method['command']}")
            
            if not self.security.is_safe_command(method['command']):
                print("❌ Command blocked by safety check")
                results["failed"].append({"method": method, "reason": "blocked_by_safety_check"})
                continue
            
            result = self.connection.run_command(method['command'])
            results["total_attempts"] += 1
            results["categories_covered"].add(method['category'])
            
            if result['success']:
                print("✅ Command executed successfully")
                
                # Check for indicators
                found_indicators = []
                for indicator in method.get('indicators', []):
                    if indicator.lower() in result['stdout'].lower():
                        found_indicators.append(indicator)
                
                if found_indicators:
                    print(f"🎯 Found indicators: {', '.join(found_indicators)}")
                    if method['category'] not in results["findings"]:
                        results["findings"][method['category']] = []
                    results["findings"][method['category']].append({
                        "method": method,
                        "indicators": found_indicators,
                        "output": result['stdout']
                    })
                
                output_preview = result['stdout'][:200] + "..." if len(result['stdout']) > 200 else result['stdout']
                print(f"Output preview: {output_preview}")
                results["successful"].append({"method": method, "result": result})
            else:
                print("❌ Command failed")
                print(f"Error: {result['stderr'][:100]}..." if result['stderr'] else "No error output")
                results["failed"].append({"method": method, "result": result})
            
            time.sleep(0.5)
        
        return results
    
    def run_privilege_escalation_batch(self, max_attempts: int = 15) -> Dict:
        """Run automated privilege escalation using YAML configuration"""
        print("\n🔥 Starting automated privilege escalation batch mode...")
        print("=" * 60)
        
        results = {
            "total_attempts": 0,
            "successful": [],
            "failed": [],
            "potential_vectors": [],
            "current_privileges": "unknown"
        }
        
        # Run enumeration first to gather context
        enum_results = self.run_enumeration_batch(max_attempts=10)
        
        # Get privilege escalation methods
        priv_methods = self.config_loader.get_all_methods('priv')
        
        # Analyze enumeration results to prioritize privilege escalation methods
        prioritized_methods = self._analyze_and_prioritize_methods(priv_methods, enum_results)
        
        for i, method in enumerate(prioritized_methods):
            if i >= max_attempts:
                break
                
            print(f"\n[{i+1}/{min(len(prioritized_methods), max_attempts)}] {method['name']}")
            print(f"Category: {method['category']}, Priority Score: {method.get('score', method['priority'])}")
            print(f"Description: {method['description']}")
            print(f"Command: {method['command']}")
            
            if not self.security.is_safe_command(method['command']):
                print("❌ Command blocked by safety check")
                results["failed"].append({"method": method, "reason": "blocked_by_safety_check"})
                continue
            
            result = self.connection.run_command(method['command'])
            results["total_attempts"] += 1
            
            if result['success']:
                print("✅ Command executed successfully")
                
                # Check for indicators
                found_indicators = []
                for indicator in method.get('indicators', []):
                    if indicator.lower() in result['stdout'].lower():
                        found_indicators.append(indicator)
                
                if found_indicators:
                    print(f"🎯 Found indicators: {', '.join(found_indicators)}")
                    results["potential_vectors"].append({
                        "method": method,
                        "result": result,
                        "indicators": found_indicators
                    })
                
                if self._check_admin_privileges(result, method):
                    print("🏆 PRIVILEGE ESCALATION SUCCESSFUL!")
                    results["successful"].append({"method": method, "result": result})
                    results["current_privileges"] = "administrator"
                    return results
                
                output_preview = result['stdout'][:200] + "..." if len(result['stdout']) > 200 else result['stdout']
                print(f"Output preview: {output_preview}")
                results["successful"].append({"method": method, "result": result})
            else:
                print("❌ Command failed")
                print(f"Error: {result['stderr'][:100]}..." if result['stderr'] else "No error output")
                results["failed"].append({"method": method, "result": result})
            
            time.sleep(0.5)
        
        return results
    
    def _analyze_and_prioritize_methods(self, methods: List[Dict], enum_results: Dict) -> List[Dict]:
        """Analyze enumeration results and prioritize privilege escalation methods"""
        prioritized_methods = []
        
        for method in methods:
            method_copy = method.copy()
            method_copy["score"] = method.get("priority", 5)  # Base score from priority
            
            # Adjust score based on enumeration findings
            category = method.get("category", "")
            
            # Check if enumeration found relevant indicators for this method
            if category in enum_results.get("findings", {}):
                method_copy["score"] -= 1  # Higher priority if we found relevant enum data
            
            # Specific category adjustments
            if category == "service_enum" and "service_enum" in enum_results.get("categories_covered", set()):
                method_copy["score"] -= 1
            elif category == "scheduled_tasks" and any("task" in cat for cat in enum_results.get("categories_covered", set())):
                method_copy["score"] -= 1
            elif category == "registry" and "registry" in enum_results.get("categories_covered", set()):
                method_copy["score"] -= 1
            
            prioritized_methods.append(method_copy)
        
        # Sort by score (lower is better)
        return sorted(prioritized_methods, key=lambda x: x["score"])
    
    def _check_admin_privileges(self, result: Dict, method: Optional[Dict] = None) -> bool:
        """Check if command result indicates admin privileges"""
        if not result['success']:
            return False
        
        output = result['stdout'].lower()
        admin_indicators = [
            "administrators", "builtin\\administrators", "sedebugprivilege",
            "setakeownershipprivilege", "sebackupprivilege", "serestoreprivilege",
            # Add more robust indicators
            "group policy", # for GPO related checks
            "account operators", # for certain AD related checks
            "elevated" # common in UAC bypass outputs or elevated command prompts
        ]
        
        # Check specific output for whoami /priv and whoami /groups
        if "whoami /priv" in (method['command'].lower() if method else '') or "whoami /groups" in (method['command'].lower() if method else ''):
            if "administrators" in output or "sedebugprivilege" in output:
                return True
        
        # Generic check for admin indicators in any command output
        return any(indicator in output for indicator in admin_indicators)
    
    def analyze_results(self, results: Dict) -> Dict:
        """Analyze batch results and provide recommendations"""
        print("\n📊 Batch Analysis Results:")
        print("=" * 40)
        
        analysis = {
            "summary": {
                "total_attempts": results["total_attempts"],
                "successful_commands": len(results["successful"]),
                "failed_commands": len(results["failed"]),
                "potential_vectors": len(results.get("potential_vectors", [])),
                "categories_covered": len(results.get("categories_covered", set()))
            },
            "recommendations": []
        }
        
        print(f"Total attempts: {analysis['summary']['total_attempts']}")
        print(f"Successful commands: {analysis['summary']['successful_commands']}")
        print(f"Failed commands: {analysis['summary']['failed_commands']}")
        
        if "potential_vectors" in results:
            print(f"Potential vectors found: {analysis['summary']['potential_vectors']}")
        
        if "categories_covered" in results:
            print(f"Categories covered: {analysis['summary']['categories_covered']}")
            print(f"Categories: {', '.join(results['categories_covered'])}")
        
        # Show findings if available
        if "findings" in results and results["findings"]:
            print("\n🎯 Key Findings by Category:")
            for category, findings in results["findings"].items():
                print(f"\n{category.upper()}:")
                for finding in findings:
                    print(f"  • {finding['method']['name']}")
                    print(f"    Indicators: {', '.join(finding['indicators'])}")
        
        # Show potential vectors if available
        if results.get("potential_vectors"):
            print("\n🎯 Potential privilege escalation vectors found:")
            for i, vector in enumerate(results["potential_vectors"]):
                print(f"\n{i+1}. {vector['method']['name']}")
                print(f"   Category: {vector['method']['category']}")
                print(f"   Indicators: {', '.join(vector['indicators'])}")
                
                # Generate recommendations based on category
                category = vector['method']['category']
                if category == 'unquoted_service_paths':
                    analysis['recommendations'].append("Investigate unquoted service paths for DLL hijacking")
                elif category == 'scheduled_tasks':
                    analysis['recommendations'].append("Check scheduled tasks for privilege escalation opportunities")
                elif category == 'registry':
                    analysis['recommendations'].append("Examine registry entries for persistence or escalation")
                elif category == 'file_permissions':
                    analysis['recommendations'].append("Exploit weak file permissions for privilege escalation")
                elif category == 'service_enum':
                    analysis['recommendations'].append("Analyze service configurations for weak permissions")
        
        if analysis['recommendations']:
            print("\n💡 Recommendations:")
            for i, rec in enumerate(analysis['recommendations']):
                print(f"{i+1}. {rec}")
        
        return analysis

class PentestAgent:
    def __init__(self, config_file: str = '.env', enum_file: str = 'enum.yaml', priv_file: str = 'priv.yaml'):
        load_dotenv(config_file)
        
        # Initialize YAML config loader
        self.config_loader = YAMLConfigLoader(enum_file, priv_file)
        
        # Initialize other components
        self.connection = WinRMConnection(
            host=os.getenv('TARGET_HOST'),
            username=os.getenv('TARGET_USER'),
            password=os.getenv('TARGET_PASS')
        )
        self.ai = AIAssistant(os.getenv('GROQ_API_KEY'))
        self.recon = ReconModule(self.config_loader)
        self.security = SecurityChecker()
        self.batch = BatchModule(self.connection, self.security, self.recon, self.config_loader)
        
        self.context = ""
        self.step_count = 0
        self.max_steps = 10
        self.successful_commands = []
        self.failed_commands = []
    
    def run(self):
        print("🚀 Starting Enhanced Penetration Testing Agent with YAML Configuration")
        print("=" * 70)
        
        # Show loaded configuration summary
        print(f"📋 Configuration Summary:")
        print(f"   • Enumeration methods: {len(self.config_loader.enum_methods)}")
        print(f"   • Privilege escalation methods: {len(self.config_loader.priv_methods)}")
        
        # Show categories
        enum_categories = set(method.get('category', 'unknown') for method in self.config_loader.enum_methods)
        priv_categories = set(method.get('category', 'unknown') for method in self.config_loader.priv_methods)
        
        print(f"   • Enumeration categories: {', '.join(enum_categories)}")
        print(f"   • Privilege escalation categories: {', '.join(priv_categories)}")
        
        try:
            # Run enumeration first
            print("\n" + "="*60)
            enum_results = self.batch.run_enumeration_batch(max_attempts=15)
            self.batch.analyze_results(enum_results)
            
            # AI-driven escalation loop instead of static batch
            print("\n" + "="*60)
            print("🧠 Initiating AI-driven Privilege Escalation Loop...")
            self.run_ai_priv_escalation(enum_results)
            
            print("\n✅ Agent execution completed")
            
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()

    def _serialize_enum(self, enum_results: Dict) -> str:
        """
        Serializes relevant enumeration findings into a single string for AI context.
        Prioritizes 'findings' but includes 'successful' outputs if no specific findings.
        """
        parts = []

        # Add key findings with indicators
        if "findings" in enum_results and enum_results["findings"]:
            parts.append("--- KEY FINDINGS ---")
            for category, findings in enum_results["findings"].items():
                parts.append(f"\nCategory: {category.upper()}")
                for f in findings:
                    indicators_str = ', '.join(f['indicators']) if f['indicators'] else 'None'
                    output_preview = f['output'][:200].replace('\n', ' ') + "..." if len(f['output']) > 200 else f['output'].replace('\n', ' ')
                    parts.append(f"- Method: {f['method']['name']} | Indicators: [{indicators_str}] | Output: {output_preview}")
        
        # Add a selection of successful command outputs if findings are sparse
        # To avoid sending too much data, pick a few key ones or just the most recent
        if enum_results["successful"] and not parts: # Only add if no explicit findings were added
            parts.append("--- GENERAL ENUMERATION OUTPUTS (PREVIEW) ---")
            # Limit to top 5 successful commands for brevity
            for i, res in enumerate(enum_results["successful"][:5]):
                output_preview = res['result']['stdout'][:200].replace('\n', ' ') + "..." if len(res['result']['stdout']) > 200 else res['result']['stdout'].replace('\n', ' ')
                parts.append(f"- Method: {res['method']['name']} | Command: {res['method']['command']} | Output: {output_preview}")

        if not parts:
            return "No specific enumeration findings or relevant successful commands to report."

        return "\n".join(parts)
    
    def run_ai_priv_escalation(self, enum_results: Dict):
        """Loop: AI suggests, we execute, until admin, then drop ROOTED file."""
        initial_context = self._serialize_enum(enum_results)
        history = []
        current_privileges = "low" # Track assumed privilege level
        
        print("\n✨ AI-Driven Privilege Escalation Loop Started ✨")
        print("Initial Context (serialized enum results):\n" + "="*40 + f"\n{initial_context}\n" + "="*40)

        # First, check current privileges based on initial enumeration
        whoami_priv_result = self.connection.run_command("whoami /priv")
        if self.batch._check_admin_privileges(whoami_priv_result, {"command": "whoami /priv"}):
            print("✅ Initial check: Admin privileges already detected!")
            current_privileges = "administrator"
        else:
            print("ℹ️  Initial check: Admin privileges NOT detected. Proceeding with escalation.")
        
        # Main loop for privilege escalation
        while current_privileges != "administrator":
            combined_context = "\n".join([initial_context] + history)
            objective = "Gain administrator privileges on the target system."
            
            # If we think we might be admin, change the objective to verify
            if "administrators" in combined_context.lower() or "sedebugprivilege" in combined_context.lower():
                objective = "Verify administrator privileges. If confirmed, create the ROOTED marker file at C:\\Windows\\System32\\rooted."
                print(f"\n[AI Objective] Changing objective: {objective}")

            suggestion = self.ai.get_suggestion(
                context=combined_context,
                objective=objective
            )
            
            cmd = suggestion.get("command")
            reason = suggestion.get("reason", "No reason provided.")

            if not cmd:
                print("❌ AI returned no command. Breaking loop.")
                break

            print(f"\n[AI Suggestion] Command: {cmd} ({reason})")
            
            if not self.security.is_safe_command(cmd):
                print(f"❌ Command '{cmd}' blocked by safety check. Skipping.")
                history.append(f"Command: {cmd} | Status: BLOCKED | Reason: Safety Check")
                time.sleep(1)
                continue
            
            result = self.connection.run_command(cmd)
            
            output_preview = result['stdout'][:150].replace('\n', ' ') + "..." if len(result['stdout']) > 150 else result['stdout'].replace('\n', ' ')
            error_preview = result['stderr'][:100].replace('\n', ' ') + "..." if len(result['stderr']) > 100 else result['stderr'].replace('\n', ' ')

            history.append(f"Command: {cmd} | Success: {result['success']} | Output: {output_preview} | Stderr: {error_preview}")
            
            print(f"Command execution result: Success={result['success']}")
            print(f"Output preview: {output_preview}")
            if result['stderr']:
                print(f"Error output: {error_preview}")

            # Check for admin privileges after each command
            if self.batch._check_admin_privileges(result, {"command": cmd}):
                print("🏆 Admin privileges confirmed!")
                current_privileges = "administrator"
                break # Exit the loop, admin achieved
            elif "ROOTED" in cmd and result['success']: # Specific check if AI tried to create ROOTED file
                print("🎉 ROOTED file command executed successfully!")
                current_privileges = "administrator" # Assume success if ROOTED command went through
                break
            
            time.sleep(1)
            
        # Final goal: write ROOTED file if admin privileges are confirmed
        if current_privileges == "administrator":
            final_cmd = 'echo ROOTED > C:\\Windows\\System32\\rooted'
            print(f"\nAttempting final goal: {final_cmd}")
            final_result = self.connection.run_command(final_cmd)
            if final_result['success']:
                print("🎉 ROOTED marker file created successfully!")
            else:
                print(f"❌ Failed to create ROOTED marker file: {final_result['stderr']}")
        else:
            print("\n❌ Failed to achieve administrator privileges after AI-driven loop.")

    def run_interactive_mode(self):
        """Interactive mode for manual testing"""
        print("\n🎮 Starting Interactive Mode")
        print("Commands: 'enum <category>', 'priv <category>', 'list', 'quit', 'ai_escalate'")
        print("=" * 50)
        
        while True:
            try:
                user_input = input("\n> ").strip().lower()
                
                if user_input in ['quit', 'exit', 'q']:
                    print("👋 Goodbye!")
                    break
                
                elif user_input == 'list':
                    self._show_available_methods()
                
                elif user_input.startswith('enum'):
                    parts = user_input.split()
                    if len(parts) > 1:
                        category = parts[1]
                        results = self.recon.run_enumeration_by_category(self.connection, category)
                        self._display_results(results)
                    else:
                        # Run all enumeration
                        results = self.batch.run_enumeration_batch(max_attempts=10)
                        self.batch.analyze_results(results)
                
                elif user_input.startswith('priv'):
                    parts = user_input.split()
                    if len(parts) > 1:
                        category = parts[1]
                        methods = self.config_loader.get_methods_by_category(category, 'priv')
                        self._run_methods_manually(methods)
                    else:
                        # Run all privilege escalation
                        results = self.batch.run_privilege_escalation_batch(max_attempts=10)
                        self.batch.analyze_results(results)
                
                elif user_input == 'ai_escalate':
                    print("\nStarting AI-driven escalation in interactive mode...")
                    initial_enum_results = self.batch.run_enumeration_batch(max_attempts=15)
                    self.run_ai_priv_escalation(initial_enum_results)
                
                elif user_input.startswith('run'):
                    # Custom command execution
                    parts = user_input.split(maxsplit=1)
                    if len(parts) > 1:
                        command = parts[1]
                        if self.security.is_safe_command(command):
                            result = self.connection.run_command(command)
                            self._display_single_result(command, result)
                        else:
                            print("❌ Command blocked by safety check")
                    else:
                        print("❌ Please provide a command to run")
                
                else:
                    print("❓ Unknown command. Use 'list' to see available options.")
                    
            except KeyboardInterrupt:
                print("\n\n⚠️  Interrupted by user")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def _show_available_methods(self):
        """Show available methods from YAML configuration"""
        print("\n📋 Available Methods:")
        print("\n🔍 ENUMERATION METHODS:")
        
        enum_categories = {}
        for method in self.config_loader.enum_methods:
            category = method.get('category', 'unknown')
            if category not in enum_categories:
                enum_categories[category] = []
            enum_categories[category].append(method)
        
        for category, methods in enum_categories.items():
            print(f"\n  {category.upper()}:")
            for method in methods:
                print(f"    • {method['name']} (Priority: {method.get('priority', 'N/A')})")
                print(f"      Command: {method['command']}")
        
        print("\n🔥 PRIVILEGE ESCALATION METHODS:")
        
        priv_categories = {}
        for method in self.config_loader.priv_methods:
            category = method.get('category', 'unknown')
            if category not in priv_categories:
                priv_categories[category] = []
            priv_categories[category].append(method)
        
        for category, methods in priv_categories.items():
            print(f"\n  {category.upper()}:")
            for method in methods:
                print(f"    • {method['name']} (Priority: {method.get('priority', 'N/A')})")
                print(f"      Command: {method['command']}")
        
        print("\n💡 Usage Examples:")
        print("  • enum user_info     - Run user information enumeration")
        print("  • priv service_enum  - Run service enumeration for privilege escalation")
        print("  • ai_escalate        - Start AI-driven privilege escalation loop")
        print("  • run whoami         - Execute custom command")
        print("  • list               - Show this help")
        print("  • quit               - Exit interactive mode")
    
    def _run_methods_manually(self, methods: List[Dict]):
        """Run specific methods manually"""
        if not methods:
            print("❌ No methods found for this category")
            return
        
        for method in methods:
            print(f"\n🔧 Running: {method['name']}")
            print(f"Description: {method['description']}")
            print(f"Command: {method['command']}")
            
            if not self.security.is_safe_command(method['command']):
                print("❌ Command blocked by safety check")
                continue
            
            result = self.connection.run_command(method['command'])
            
            if result['success']:
                print("✅ Command executed successfully")
                
                # Check for indicators
                found_indicators = []
                for indicator in method.get('indicators', []):
                    if indicator.lower() in result['stdout'].lower():
                        found_indicators.append(indicator)
                
                if found_indicators:
                    print(f"🎯 Found indicators: {', '.join(found_indicators)}")
                
                # Show output preview
                output_preview = result['stdout'][:300] + "..." if len(result['stdout']) > 300 else result['stdout']
                print(f"Output:\n{output_preview}")
            else:
                print("❌ Command failed")
                print(f"Error: {result['stderr']}")
    
    def _display_results(self, results: Dict):
        """Display results in a formatted way"""
        print("\n📊 Results:")
        for method_name, result in results.items():
            method_info = result.get('method_info', {})
            print(f"\n• {method_info.get('name', method_name)}")
            
            if result['success']:
                print("  ✅ Success")
                if 'indicators' in result:
                    print(f"  🎯 Indicators: {', '.join(result['indicators'])}")
                
                output_preview = result['stdout'][:150] + "..." if len(result['stdout']) > 150 else result['stdout']
                print(f"  Output: {output_preview}")
            else:
                print("  ❌ Failed")
                print(f"  Error: {result['stderr']}")
    
    def _display_single_result(self, command: str, result: Dict):
        """Display a single command result"""
        print(f"\n🔧 Command: {command}")
        if result['success']:
            print("✅ Success")
            print(f"Output:\n{result['stdout']}")
        else:
            print("❌ Failed")
            print(f"Error: {result['stderr']}")

def main():
    """Main entry point with enhanced options"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Penetration Testing Agent')
    parser.add_argument('--mode', choices=['auto', 'interactive', 'create-samples'], 
                       default='auto', help='Execution mode')
    parser.add_argument('--enum-file', default='enum.yaml', 
                       help='Path to enumeration YAML file')
    parser.add_argument('--priv-file', default='priv.yaml', 
                       help='Path to privilege escalation YAML file')
    parser.add_argument('--config', default='.env', 
                       help='Path to environment configuration file')
    
    args = parser.parse_args()
    
    try:
        agent = PentestAgent(
            config_file=args.config,
            enum_file=args.enum_file,
            priv_file=args.priv_file
        )
        
        if args.mode == 'auto':
            agent.run()
        elif args.mode == 'interactive':
            agent.run_interactive_mode()
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Execution interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()