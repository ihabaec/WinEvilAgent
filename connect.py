import winrm

session = winrm.Session('http://192.168.56.110:5985/wsman', auth=('test', 'MySecurePassword123'))

result = session.run_cmd('whoami')
print("Status:", result.status_code)
print("Output:", result.std_out.decode())
print("Error:", result.std_err.decode())
# winrm enumerate winrm/config/listener
