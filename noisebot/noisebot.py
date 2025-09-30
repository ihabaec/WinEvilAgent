#!/usr/bin/env python3
"""
NoiseBot (FULL, NTLM) — Windows "SOC noise" generator over WinRM

⚠️ LAB-ONLY. Generates benign-but-detectable telemetry on Windows hosts to
exercise Elastic/Kibana rules and your SOC pipeline (Elastic → Cortex → MISP → TheHive).

This single file includes:
- Robust WinRM connection using HTTP+NTLM with retry/backoff (matches your prior setup)
- Core techniques (process masquerade, PowerShell encoded, certutil download,
  SMB auth failures, WMI exec, service create/delete, registry run key,
  scheduled task, DNS bursts, staging archive)
- User-behavior techniques (Downloads + MOTW, ZIP download+extract+open,
  mshta/regsvr32/rundll32 benign patterns, Office .docm open, .lnk creation+run,
  fake installer in Downloads)
- EICAR test file technique (download ZIP, set MOTW, extract, optional read)

Scenario-driven, randomized/bursty pacing, per-tech caps, safety denylist.

Quickstart
  pip install pywinrm pyyaml
  python noisebot_full_ntlm.py --host 192.168.56.21 --user LAB\\analyst --password 'Passw0rd!' \
      --scenario scenario.yaml --duration 1800
"""

import re
import time
import yaml
import uuid
import random
import argparse
import datetime as dt
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

try:
    import winrm  # type: ignore
except ImportError:
    winrm = None

# ------------------------- WinRM (NTLM + retry) -------------------------

class WinRMConnection:
    """WinRM connection & command execution with NTLM and retries, plus .ps()."""
    def __init__(self, host: str, username: str, password: str, port: int = 5985):
        if winrm is None:
            raise RuntimeError("pywinrm not installed. pip install pywinrm")
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.session = None
        self.connect()

    def connect(self):
        try:
            endpoint = f'http://{self.host}:{self.port}/wsman'
            self.session = winrm.Session(endpoint, auth=(self.username, self.password), transport='ntlm')
            print(f"✅ Connected to {self.host}:{self.port} via NTLM")
        except Exception as e:
            print(f"❌ Connection failed to {self.host}:{self.port}: {e}")
            raise

    def run_command(self, command: str, retries: int = 3, delay: int = 2) -> Dict[str, Any]:
        if not self.session:
            return {'status': -1, 'stdout': '', 'stderr': 'No active WinRM session.', 'success': False}
        last_stdout, last_stderr, last_status = '', '', -1
        for attempt in range(retries):
            try:
                result = self.session.run_cmd(command)
                last_status = result.status_code
                last_stdout = result.std_out.decode('latin-1', 'ignore').strip()
                last_stderr = result.std_err.decode('latin-1', 'ignore').strip()
                if last_status == 0:
                    return {'status': last_status, 'stdout': last_stdout, 'stderr': last_stderr, 'success': True}
                if attempt < retries - 1:
                    time.sleep(delay)
                    delay *= 2
            except winrm.exceptions.WinRMOperationTimeoutError as e:
                last_stderr = str(e)
                if attempt < retries - 1:
                    time.sleep(delay)
                    delay *= 2
            except winrm.exceptions.WinRMTransportError as e:
                last_stderr = str(e)
                if attempt < retries - 1:
                    time.sleep(delay)
                    delay *= 2
            except Exception as e:
                return {'status': -1, 'stdout': '', 'stderr': str(e), 'success': False}
        return {'status': last_status, 'stdout': last_stdout, 'stderr': last_stderr or 'Command failed after multiple retries.', 'success': False}

    def ps(self, code: str) -> Dict[str, Any]:
        # Escape quotes/backslashes for inline -Command
        safe = code.replace('\\', r'\\').replace('"', r'`"')
        cmd = f"powershell -NoProfile -ExecutionPolicy Bypass -Command \"{safe}\""
        return self.run_command(cmd)

# ------------------------- Safety & Tagging -------------------------

class SafetyGuard:
    DENY = [
        'bcdedit', 'diskpart', 'cipher /w', 'format', 'schtasks /change',
        'vssadmin delete', 'wmic shadowcopy delete', 'takeown /f %systemroot%',
        'icacls %systemroot%', 'reg delete HKLM\\SYSTEM', 'reg delete HKLM\\SAM'
    ]
    def allowed(self, cmd: str) -> bool:
        c = cmd.lower()
        return not any(x in c for x in self.DENY)

class TelemetryTagger:
    def __init__(self, run_id: str, scenario_name: str):
        self.run_id = run_id
        self.scenario = scenario_name
    def env_ps(self) -> str:
        return f"$env:RUN_ID='{self.run_id}'; $env:SCENARIO='{self.scenario}';"

# ------------------------- Technique Base -------------------------

class Technique:
    name = "base"
    weight = 1
    cap_key = None
    def __init__(self, conn: WinRMConnection, tagger: TelemetryTagger, safety: SafetyGuard):
        self.c = conn; self.tagger = tagger; self.safety = safety
        self._ensure_tmp()
    def _ensure_tmp(self):
        ps = self.tagger.env_ps() + r"New-Item -ItemType Directory -Force -Path 'C:\\Windows\\Temp\\indegate_noise' | Out-Null"
        self.c.ps(ps)
    def _safe_run(self, ps: str) -> Dict[str, Any]:
        if not self.safety.allowed(ps):
            return {'success': False, 'status': -1, 'stdout': '', 'stderr': 'blocked_by_safety', 'blocked': True}
        return self.c.ps(self.tagger.env_ps() + ps)
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

# ------------------------- Core Techniques -------------------------

class TechProcessMasquerade(Technique):
    name = 'process_masquerade'
    cap_key = 'process_masquerade'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        images = params.get('images') or ['mimikatz.exe']
        fake = random.choice(images)
        tmp = r"C:\\Windows\\Temp\\indegate_noise"
        src = r"C:\\Windows\\System32\\notepad.exe"
        dst = f"{tmp}\\{fake}"
        ps = (
            f"Copy-Item -Force '{src}' '{dst}';\n"
            f"$si = New-Object System.Diagnostics.ProcessStartInfo;\n"
            f"$si.FileName = '{dst}';\n"
            f"$si.Arguments = '--run-id ' + $env:RUN_ID;\n"
            f"$si.WindowStyle = 'Hidden';\n"
            f"[System.Diagnostics.Process]::Start($si) | Out-Null;\n"
            f"Start-Sleep -Milliseconds 500;\n"
            f"Get-Process | Where-Object {{$_.Path -eq '{dst}'}} | Stop-Process -Force -ErrorAction SilentlyContinue;\n"
            f"Remove-Item -Force -ErrorAction SilentlyContinue '{dst}';\n"
        )
        return self._safe_run(ps)

class TechPowerShellEncoded(Technique):
    name = 'powershell_encoded'
    cap_key = 'powershell_encoded'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        cmd = params.get('command') or "Write-Output ('INDEGATE_'+$env:RUN_ID); Start-Sleep 1"
        cmd_esc = cmd.replace('"', '`"')
        ps = (
            f"$bytes = [Text.Encoding]::Unicode.GetBytes(\"{cmd_esc}\");\n"
            f"$enc = [Convert]::ToBase64String($bytes);\n"
            f"Start-Process -WindowStyle Hidden powershell.exe -ArgumentList ('-NoProfile -EncodedCommand ' + $enc) | Out-Null\n"
        )
        return self._safe_run(ps)

class TechDownloadCertutil(Technique):
    name = 'download_certutil'
    cap_key = 'download_certutil'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get('url', 'http://127.0.0.1:8080/benign.bin')
        ps = f"certutil -urlcache -split -f '{url}' 'C:\\Windows\\Temp\\indegate_noise\\payload_$env:RUN_ID.bin' | Out-Null"
        return self._safe_run(ps)

class TechSMBAuthFail(Technique):
    name = 'smb_auth_fail'
    cap_key = 'smb_auth_fail'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        users = params.get('users') or ['decoy']
        domain = params.get('domain', 'LAB')
        target = params.get('target', '127.0.0.1')
        attempts_rng = params.get('attempts_per_burst', '2-3')
        lo, hi = _parse_range(attempts_rng)
        attempts = random.randint(lo, hi)
        ps_lines = ["$ErrorActionPreference='SilentlyContinue'"]
        for _ in range(attempts):
            u = random.choice(users)
            ps_lines.append(f"cmd /c 'net use \\\\{target}\\\\IPC$ /user:{domain}\\\\{u} wrongpass' 2>&1 | Out-Null")
        return self._safe_run(";".join(ps_lines))

class TechWMIExecLocal(Technique):
    name = 'wmi_exec_local'
    cap_key = 'wmi_exec_local'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        ps = r"wmic process call create 'cmd.exe /c echo %RUN_ID% > %TEMP%\wmi_%RUN_ID%.txt' | Out-Null"
        return self._safe_run(ps)

class TechServiceCreateDelete(Technique):
    name = 'service_create_delete'
    cap_key = 'service_create_delete'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        ps = r"sc.exe create $env:RUN_ID binPath= 'cmd.exe /c timeout 1' start= demand | Out-Null; sc.exe start $env:RUN_ID | Out-Null; sc.exe delete $env:RUN_ID | Out-Null"
        return self._safe_run(ps)

class TechRegistryRunKey(Technique):
    name = 'registry_runkey'
    cap_key = 'registry_runkey'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        ps = r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v $env:RUN_ID /t REG_SZ /d 'cmd.exe /c echo $env:RUN_ID>>%TEMP%\runkey_$env:RUN_ID.txt' /f; Start-Sleep 1; reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v $env:RUN_ID /f"
        return self._safe_run(ps)

class TechSchTaskOnce(Technique):
    name = 'schtask_once'
    cap_key = 'schtask_once'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        ps = r"schtasks /Create /SC ONCE /ST 23:59 /TN INDEGATE_$env:RUN_ID /TR 'cmd.exe /c echo $env:RUN_ID>>%TEMP%\schtask_$env:RUN_ID.txt' /F; schtasks /Run /TN INDEGATE_$env:RUN_ID; schtasks /Delete /TN INDEGATE_$env:RUN_ID /F"
        return self._safe_run(ps)

class TechDNSBurst(Technique):
    name = 'dns_burst'
    cap_key = 'dns_burst'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        count = int(params.get('count', 10))
        zone = params.get('zone', 'aaaaaaaaaaaaaaaa.example.invalid')
        ps = [f"for ($i=0; $i -lt {count}; $i++) {{ nslookup (Get-Random).ToString() + '-' + $env:RUN_ID + '.{zone}' | Out-Null }}"]
        return self._safe_run(";".join(ps))

class TechStagingArchive(Technique):
    name = 'staging_archive'
    cap_key = 'staging_archive'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        ps = r"tar -cf C:\\Windows\\Temp\\indegate_noise\\loot_$env:RUN_ID.tar C:\\Windows\\Temp\\indegate_noise\*.txt 2>$null"
        return self._safe_run(ps)

# -------------------- User-Behavior Techniques --------------------

class TechDownloadToDownloadsMOTW(Technique):
    name = 'download_to_downloads_motw'
    cap_key = 'download_to_downloads_motw'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get('url', 'http://127.0.0.1:8080/suspicious.exe')
        user_prof = params.get('userprofile', r"$env:USERPROFILE")
        dst_dir = rf"{user_prof}\\Downloads"
        fname_choices = params.get('filenames', [
            'invoice_0932.pdf.exe','setup_update.exe','payment_advice.scr','resume.docx.exe','scan_2024-12-01.pdf.exe'
        ])
        fname = random.choice(fname_choices)
        ps = (
            f"New-Item -ItemType Directory -Force -Path '{dst_dir}' | Out-Null;\n"
            f"$dst = Join-Path '{dst_dir}' '{fname}';\n"
            f"(New-Object Net.WebClient).DownloadFile('{url}', $dst);\n"
            f"Set-Content -Path ($dst+':Zone.Identifier') -Value '[ZoneTransfer]\nZoneId=3' -Force;\n"
            f"Copy-Item -Force 'C:\\Windows\\System32\\notepad.exe' $dst;\n"
            f"Start-Process -WindowStyle Hidden $dst -ArgumentList ('--run-id ' + $env:RUN_ID) | Out-Null\n"
        )
        return self._safe_run(ps)

class TechZipDownloadAndExtract(Technique):
    name = 'zip_download_and_extract'
    cap_key = 'zip_download_and_extract'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get('url', 'http://127.0.0.1:8080/archive.zip')
        user_prof = params.get('userprofile', r"$env:USERPROFILE")
        dst_dir = rf"{user_prof}\\Downloads"
        ps = (
            f"New-Item -ItemType Directory -Force -Path '{dst_dir}' | Out-Null;\n"
            f"$zip = Join-Path '{dst_dir}' ('docs_'+$env:RUN_ID+'.zip');\n"
            f"(New-Object Net.WebClient).DownloadFile('{url}', $zip);\n"
            f"Set-Content -Path ($zip+':Zone.Identifier') -Value '[ZoneTransfer]\nZoneId=3' -Force;\n"
            f"$extract = Join-Path '{dst_dir}' ('extracted_'+$env:RUN_ID);\n"
            f"Expand-Archive -Force -LiteralPath $zip -DestinationPath $extract;\n"
            f"$first = Get-ChildItem $extract -Recurse -File | Select-Object -First 1;\n"
            f"if ($first) {{ Start-Process -WindowStyle Hidden $first.FullName | Out-Null }}\n"
        )
        return self._safe_run(ps)

class TechMshtaBenign(Technique):
    name = 'mshta_benign'
    cap_key = 'mshta_benign'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get('url', 'http://127.0.0.1:8080/benign.hta')
        ps = f"mshta.exe '{url}'"
        return self._safe_run(ps)

class TechRegsvr32Benign(Technique):
    name = 'regsvr32_benign'
    cap_key = 'regsvr32_benign'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get('url', 'http://127.0.0.1:8080/safe.sct')
        ps = f"regsvr32 /s /n /u /i:{url} scrobj.dll"
        return self._safe_run(ps)

class TechRundll32Benign(Technique):
    name = 'rundll32_benign'
    cap_key = 'rundll32_benign'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        ps = r"rundll32.exe shell32.dll,Control_RunDLL desk.cpl"
        return self._safe_run(ps)

class TechOfficeOpenDocm(Technique):
    name = 'office_open_docm'
    cap_key = 'office_open_docm'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        user_prof = params.get('userprofile', r"$env:USERPROFILE")
        dst_dir = rf"{user_prof}\\Downloads"
        ps = (
            f"New-Item -ItemType Directory -Force -Path '{dst_dir}' | Out-Null;\n"
            f"$doc = Join-Path '{dst_dir}' ('invoice_'+$env:RUN_ID+'.docm');\n"
            f"Set-Content -Path $doc -Value 'benign content';\n"
            f"$word = (Get-Command WINWORD.EXE -ErrorAction SilentlyContinue).Path;\n"
            f"if ($word) {{ Start-Process -WindowStyle Hidden $word -ArgumentList $doc | Out-Null }}\n"
        )
        return self._safe_run(ps)

class TechCreateSuspiciousLNK(Technique):
    name = 'create_suspicious_lnk'
    cap_key = 'create_suspicious_lnk'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        user_prof = params.get('userprofile', r"$env:USERPROFILE")
        dst_dir = rf"{user_prof}\\Downloads"
        ps = (
            f"$WshShell = New-Object -ComObject WScript.Shell;\n"
            f"$lnkPath = Join-Path '{dst_dir}' ('payment_'+$env:RUN_ID+'.lnk');\n"
            f"$lnk = $WshShell.CreateShortcut($lnkPath);\n"
            f"$lnk.TargetPath = 'cmd.exe';\n"
            f"$lnk.Arguments  = '/c echo INDEGATE_' + $env:RUN_ID + ' > %TEMP%\\lnk_' + $env:RUN_ID + '.txt';\n"
            f"$lnk.IconLocation = 'shell32.dll,13';\n"
            f"$lnk.Save();\n"
            f"Start-Process -WindowStyle Hidden $lnkPath | Out-Null\n"
        )
        return self._safe_run(ps)

class TechFakeInstallerRun(Technique):
    name = 'fake_installer_run'
    cap_key = 'fake_installer_run'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        user_prof = params.get('userprofile', r"$env:USERPROFILE")
        dst_dir = rf"{user_prof}\\Downloads"
        ps = (
            f"New-Item -ItemType Directory -Force -Path '{dst_dir}' | Out-Null;\n"
            f"$dst = Join-Path '{dst_dir}' ('setup_'+$env:RUN_ID+'.exe');\n"
            f"Copy-Item -Force 'C:\\Windows\\System32\\notepad.exe' $dst;\n"
            f"Set-Content -Path ($dst+':Zone.Identifier') -Value '[ZoneTransfer]\nZoneId=3' -Force;\n"
            f"Start-Process -WindowStyle Hidden $dst -ArgumentList '/S --run-id '+$env:RUN_ID | Out-Null\n"
        )
        return self._safe_run(ps)

# -------------------- EICAR Test Technique --------------------

class TechEICARZipDownloadExtract(Technique):
    name = 'eicar_zip_download_extract'
    cap_key = 'eicar_zip_download_extract'
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get('url', 'https://www.ikarussecurity.com/wp-content/downloads/eicar_com.zip')
        user_prof = params.get('userprofile', r"$env:USERPROFILE")
        open_after = bool(params.get('open_after_extract', True))
        dst_dir = rf"{user_prof}\\Downloads"
        ps = (
            f"$ErrorActionPreference='SilentlyContinue';\n"
            f"New-Item -ItemType Directory -Force -Path '{dst_dir}' | Out-Null;\n"
            f"$zip = Join-Path '{dst_dir}' ('eicar_'+$env:RUN_ID+'.zip');\n"
            f"(New-Object Net.WebClient).DownloadFile('{url}', $zip);\n"
            f"Set-Content -Path ($zip+':Zone.Identifier') -Value '[ZoneTransfer]\nZoneId=3' -Force;\n"
            f"$extract = Join-Path '{dst_dir}' ('eicar_'+$env:RUN_ID);\n"
            f"Expand-Archive -Force -LiteralPath $zip -DestinationPath $extract;\n"
            f"$eicar = Get-ChildItem $extract -Recurse -File -Include eicar.com,eicar.com.txt | Select-Object -First 1;\n"
            f"if ($eicar) {{ Get-Item $eicar.FullName | Out-Null; }}\n"
            f"if ($eicar -and {str(open_after).lower()}) {{ Get-Content -Path $eicar.FullName -TotalCount 1 -ErrorAction SilentlyContinue | Out-Null; }}\n"
        )
        return self._safe_run(ps)

# -------------------------- Registry -----------------------------

TECHNIQUE_REGISTRY = {
    # Core
    TechProcessMasquerade.name: TechProcessMasquerade,
    TechPowerShellEncoded.name: TechPowerShellEncoded,
    TechDownloadCertutil.name: TechDownloadCertutil,
    TechSMBAuthFail.name: TechSMBAuthFail,
    TechWMIExecLocal.name: TechWMIExecLocal,
    TechServiceCreateDelete.name: TechServiceCreateDelete,
    TechRegistryRunKey.name: TechRegistryRunKey,
    TechSchTaskOnce.name: TechSchTaskOnce,
    TechDNSBurst.name: TechDNSBurst,
    TechStagingArchive.name: TechStagingArchive,
    # User-behavior
    TechDownloadToDownloadsMOTW.name: TechDownloadToDownloadsMOTW,
    TechZipDownloadAndExtract.name: TechZipDownloadAndExtract,
    TechMshtaBenign.name: TechMshtaBenign,
    TechRegsvr32Benign.name: TechRegsvr32Benign,
    TechRundll32Benign.name: TechRundll32Benign,
    TechOfficeOpenDocm.name: TechOfficeOpenDocm,
    TechCreateSuspiciousLNK.name: TechCreateSuspiciousLNK,
    TechFakeInstallerRun.name: TechFakeInstallerRun,
    # EICAR
    TechEICARZipDownloadExtract.name: TechEICARZipDownloadExtract,
}

# -------------------------- Orchestrator ----------------------------

def _parse_range(s: str) -> Tuple[int, int]:
    if isinstance(s, (list, tuple)) and len(s) == 2:
        return int(s[0]), int(s[1])
    m = re.match(r"^(\d+)-(\d+)$", str(s).strip())
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if a > b: a, b = b, a
        return a, b
    v = int(str(s))
    return v, v

@dataclass
class Scenario:
    name: str
    seed: int = 0
    alert_rate_sla_per_hour: str = "30-60"
    cooldown_seconds: str = "5-20"
    burst_probability: float = 0.2
    burst_size_range: str = "2-3"
    caps: Dict[str, int] = field(default_factory=dict)
    techniques: List[Dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def from_yaml(path: Optional[str]) -> 'Scenario':
        if not path:
            data = {
                'name': 'default',
                'seed': 42,
                'alert_rate_sla_per_hour': '40-70',
                'cooldown_seconds': '6-18',
                'burst': {'probability': 0.2, 'size_range': '2-3'},
                'caps': {
                    'smb_auth_fail': 10,
                    'service_create_delete': 6,
                    'dns_burst': 6,
                    'powershell_encoded': 24,
                    'process_masquerade': 18,
                    'download_to_downloads_motw': 16,
                    'zip_download_and_extract': 10,
                    'mshta_benign': 8,
                    'regsvr32_benign': 8,
                    'office_open_docm': 8,
                    'create_suspicious_lnk': 10,
                    'fake_installer_run': 8,
                    'eicar_zip_download_extract': 4,
                },
                'techniques': [
                    {'name': 'process_masquerade', 'weight': 4, 'params': {'images': ['mimikatz.exe','procdump.exe']}},
                    {'name': 'powershell_encoded', 'weight': 5},
                    {'name': 'download_certutil', 'weight': 3, 'params': {'url': 'http://127.0.0.1:8080/benign.bin'}},
                    {'name': 'smb_auth_fail', 'weight': 3, 'params': {'users': ['decoy1','decoy2'], 'domain': 'LAB', 'target': '127.0.0.1', 'attempts_per_burst': '2-3'}},
                    {'name': 'wmi_exec_local', 'weight': 2},
                    {'name': 'service_create_delete', 'weight': 2},
                    {'name': 'registry_runkey', 'weight': 2},
                    {'name': 'schtask_once', 'weight': 2},
                    {'name': 'dns_burst', 'weight': 2},
                    {'name': 'staging_archive', 'weight': 1},
                    {'name': 'download_to_downloads_motw', 'weight': 3, 'params': {'filenames': ['invoice_0932.pdf.exe','payment_advice.scr','setup_update.exe']}},
                    {'name': 'zip_download_and_extract', 'weight': 3, 'params': {'url': 'http://127.0.0.1:8080/archive.zip'}},
                    {'name': 'mshta_benign', 'weight': 2, 'params': {'url': 'http://127.0.0.1:8080/benign.hta'}},
                    {'name': 'regsvr32_benign', 'weight': 2, 'params': {'url': 'http://127.0.0.1:8080/safe.sct'}},
                    {'name': 'office_open_docm', 'weight': 2},
                    {'name': 'create_suspicious_lnk', 'weight': 2},
                    {'name': 'fake_installer_run', 'weight': 2},
                    {'name': 'eicar_zip_download_extract', 'weight': 2, 'params': {'url': 'https://www.ikarussecurity.com/wp-content/downloads/eicar_com.zip', 'open_after_extract': True}},
                ]
            }
        else:
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                raise ValueError('Scenario YAML root must be a mapping')
        burst = data.get('burst', {}) or {}
        return Scenario(
            name=data.get('name', 'default'),
            seed=int(data.get('seed', 0)),
            alert_rate_sla_per_hour=str(data.get('alert_rate_sla_per_hour', '30-60')),
            cooldown_seconds=str(data.get('cooldown_seconds', '5-20')),
            burst_probability=float(burst.get('probability', 0.2)),
            burst_size_range=str(burst.get('size_range', '2-3')),
            caps=data.get('caps', {}) or {},
            techniques=data.get('techniques', []) or [],
        )

class NoiseOrchestrator:
    def __init__(self, conn: WinRMConnection, scenario: Scenario, duration_sec: int):
        self.conn = conn
        self.scenario = scenario
        self.duration_sec = max(10, duration_sec)
        self.run_id = dt.datetime.utcnow().strftime("INDEGATE_NOISE_%Y%m%dT%H%M%SZ_") + str(uuid.uuid4())[:8]
        random.seed(self.scenario.seed or int(time.time()))
        self.tagger = TelemetryTagger(self.run_id, self.scenario.name)
        self.safety = SafetyGuard()
        self._build_techs()
        self._counters = {t: 0 for t in TECHNIQUE_REGISTRY}
        print(f"RUN_ID: {self.run_id}")

    def _build_techs(self):
        self.tech_entries: List[Tuple[Technique, int, Dict[str, Any]]] = []
        for entry in self.scenario.techniques:
            name = entry.get('name')
            if name not in TECHNIQUE_REGISTRY:
                print(f"[warn] unknown technique '{name}', skipping")
                continue
            cls = TECHNIQUE_REGISTRY[name]
            weight = int(entry.get('weight', 1))
            params = entry.get('params', {}) or {}
            self.tech_entries.append((cls(self.conn, self.tagger, self.safety), weight, params))
        self.pool: List[int] = []
        for idx, (_, w, _) in enumerate(self.tech_entries):
            self.pool += [idx] * max(1, w)

    def _pick(self) -> Tuple[Technique, Dict[str, Any]]:
        if not self.pool:
            raise RuntimeError('No techniques configured')
        idx = random.choice(self.pool)
        tech, _, params = self.tech_entries[idx]
        return tech, params

    def _respect_caps(self, tech: Technique) -> bool:
        key = getattr(tech, 'cap_key', None)
        if not key:
            return True
        cap = int(self.scenario.caps.get(key, 1_000_000))
        return self._counters.get(key, 0) < cap

    def _cooldown(self):
        lo, hi = _parse_range(self.scenario.cooldown_seconds)
        time.sleep(random.uniform(lo, hi))

    def run(self):
        t_end = time.time() + self.duration_sec
        sla_lo, sla_hi = _parse_range(self.scenario.alert_rate_sla_per_hour)
        target_per_min = random.uniform(sla_lo/60.0, sla_hi/60.0)
        next_window = time.time()
        window_count = 0
        burst_lo, burst_hi = _parse_range(self.scenario.burst_size_range)

        while time.time() < t_end:
            if time.time() >= next_window + 60:
                next_window = time.time()
                window_count = 0
                target_per_min = random.uniform(sla_lo/60.0, sla_hi/60.0)

            burst = (random.random() < self.scenario.burst_probability)
            burst_sz = random.randint(burst_lo, burst_hi) if burst else 1

            for _ in range(burst_sz):
                if time.time() >= t_end:
                    break
                tech, params = self._pick()
                if not self._respect_caps(tech):
                    continue
                res = tech.execute(params)
                key = getattr(tech, 'cap_key', tech.name)
                self._counters[key] = self._counters.get(key, 0) + 1

                status = "BLOCKED" if res.get('blocked') else ("OK" if res.get('success') else "ERR")
                print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {tech.name}: {status}")
                time.sleep(random.uniform(0.2, 0.9))
                window_count += 1
                if window_count >= target_per_min:
                    break

            if time.time() >= t_end:
                break
            self._cooldown()

        print("✅ Noise run finished. Counters:")
        for k, v in sorted(self._counters.items()):
            if v:
                print(f"  - {k}: {v}")

# ------------------------------ CLI --------------------------------

def main():
    ap = argparse.ArgumentParser(description='NoiseBot (FULL, NTLM) — Windows SOC noise generator (WinRM)')
    ap.add_argument('--host', required=True, help='Windows target host/IP')
    ap.add_argument('--user', required=True, help='Username (DOMAIN\\user or user)')
    ap.add_argument('--password', required=True, help='Password')
    ap.add_argument('--port', type=int, default=5985, help='WinRM port (5985)')
    ap.add_argument('--scenario', help='Path to scenario YAML')
    ap.add_argument('--duration', type=int, default=900, help='Run duration in seconds (default 900)')

    args = ap.parse_args()

    print("⚠️  LAB USE ONLY. Ensure test accounts/hosts and snapshots.")
    scen = Scenario.from_yaml(args.scenario)
    conn = WinRMConnection(args.host, args.user, args.password, port=args.port)
    orch = NoiseOrchestrator(conn, scen, args.duration)
    orch.run()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
