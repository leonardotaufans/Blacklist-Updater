import paramiko
from paramiko import SSHClient

CONST_IP = '10.1.0.121'
CONST_CMD = 'tmsh list net address-list'
ssh = SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
ssh.connect(CONST_IP, username='root', password='Nxtzxvaa')
stdin, stdout, stderr = ssh.exec_command(CONST_CMD)
print(stdout.read().decode())
ssh.close()
