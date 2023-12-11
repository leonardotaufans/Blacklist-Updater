# Store username and password for NAS and BIG IP in Windows Secure Vault
import os.path
import subprocess

import keyring as kr
# To not show the inputted password when updating credentials
import getpass
# To add argument parsing
import argparse
# For arrays
import numpy as np
from itertools import chain

import paramiko
# F5 SDK
# from f5.bigip import ManagementRoot
# For SSH
from paramiko import SSHClient


# # Sample on how to update address list
# # afm = mgmt.tm.security.firewall
# # collection = afm.address_lists.get_collection()
# # collection[0].addresses = [{'name': '255.126.196.7'}, {'name': '255.135.158.135'}, {'name': '255.143.102.102'}]
# # collection[0].update()
# # print(collection[0].addresses)
# ##
# sample_blacklist = ['10.1.2.3', '10.2.3.4', '10.3.4.5']
# sample_whitelist = ['10.3.4.5']
#
# for sample in sample_blacklist:
#     if sample in sample_whitelist:
#         sample_blacklist.remove(sample)
#
# dict_blacklist = []
# for bl in sample_blacklist:
#     dict_blacklist.append(dict({'name': bl}))
#
# print(dict_blacklist)
# # new_dict = [dict({'a': 1}), dict({'a': 2})]
# # print(new_dict)


class Blacklist:
    CONST_MOUNT = 'Z:'
    CONST_NAS_ADDR = '\\\\vm-winsrv16-1\\shared'
    CONST_BIGIP = 'BIG-IP'
    CONST_NAS = 'NAS'
    CONST_SELF_IP1 = '10.1.0.121'
    CONST_SELF_IP2 = '10.1.0.122'

    # Initialize code, particularly for Argument Parser
    def __init__(self):
        # Argument Parser
        parent_args = argparse.ArgumentParser()
        parent_args.add_argument("--Update-Credentials", "-c", choices=[self.CONST_BIGIP, self.CONST_NAS],
                                 action="store")
        parent_args.add_argument("--Username", "-u", help="Username (for updating credentials)", nargs='?',
                                 action="store", default="")
        parent_args.add_argument("--Password", "-p", help="Password (for updating credentials)", nargs='?',
                                 action="store", default="")
        args = parent_args.parse_args()
        if args.Update_Credentials is not None:
            self.update_credentials(self, device=args.Update_Credentials, username=args.Username,
                                    password=args.Password)
        # Running the main code. It's close to the very bottom of this class
        self.main()

    @staticmethod
    def update_credentials(self, device, username='', password=''):
        print(f'Updating {device} Credentials in Vault\n-------------------')
        if device is self.CONST_BIGIP:
            print(f'(This account requires access to SSH)')
        username = username
        if username == "":
            username = input(f"Enter {device} Username: \n")
        password = password
        if password == "":
            password = getpass.getpass(f"Enter {device} Password: \n")
        old_username = kr.get_password(f"{device}.username", "username")

        if old_username is not None:
            kr.delete_password(f"{device}.username", username="username")
            kr.delete_password(f"{device}.password", username=old_username)
        kr.set_password(f"{device}.username", "username", username)

        # if kr.get_password(f"{device}.password", username) is not None:
        #     kr.delete_password(f"{device}.password", username)
        kr.set_password(f"{device}.password", username, password)

        # uname_test = kr.get_password(service_name=f"{device}.username", username="username")
        # pass_test = kr.get_password(service_name=f"{device}.password", username=uname_test)
        # print(f"{uname_test} {pass_test}")
        exit()

    def main(self):
        # bigip_credentials = self.get_credentials('BIG-IP')
        # nas_cred = self.get_credentials('NAS')
        # mgmt = ManagementRoot('10.1.0.121', 'admin', 'Kanya3101', token=True)
        # todo: make this file came from NAS
        # black_file = open(f'C:\\Users\\leona\\Blacklist-Updater\\10_blacklist.txt').read().splitlines()
        # white_file = open(f'C:\\Users\\leona\\Blacklist-Updater\\2_whitelist.txt').read().splitlines()
        # for line in black_file:
        #    if line in white_file:
        #        black_file.remove(line)
        # old_addr_lists = mgmt.tm.security.firewall.address_lists.get_collection()
        # new_addr = [j for sub in old_addr_lists for j in sub]
        # print(new_addr)
        # check if Z: is mounted and if not, mount it.

        if not (os.path.exists(self.CONST_MOUNT)):
            # todo: remove hardcoded username/password
            nas_username = kr.get_password(f"{self.CONST_NAS}.username", username="username")
            nas_password = kr.get_password(f"{self.CONST_NAS}.password", username=nas_username)
            if nas_username is None or nas_password is None:
                # todo: If needed, use custom exception here.
                print('Username or password for NAS is not found. Ensure you have updated the username or \n'
                      'password and not delete them from the vault.')
                exit(-1)
            subprocess.check_output(
                f"net use {self.CONST_MOUNT} {self.CONST_NAS_ADDR} /user:{nas_username} {nas_password}", shell=True)

        bigip_username = kr.get_password(f"{self.CONST_BIGIP}.username", f"username")
        bigip_password = kr.get_password(f"{self.CONST_BIGIP}.password", bigip_username)
        if bigip_username is None or bigip_password is None:
            # todo: If needed, use custom exception here.
            print('Username or password for BIG IP is not found. Ensure you have updated the username or \n'
                  'password and not delete them from the vault.')
            exit(-1)
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        ssh.connect(hostname=self.CONST_SELF_IP1, username=bigip_username, password=bigip_password)
        # todo: make the 16 address list and all
        _, stdout, ___ = ssh.exec_command('tmsh modify net address-list owo-2 addresses add {arr}'
                                          .format(arr="{ 0.0.0.1 }"))
        print(stdout.read().decode())
        stdin, stdout, stderr = ssh.exec_command('tmsh list net address-list owo-2')
        print(stdout.read().decode())
        ssh.close()


if __name__ == '__main__':
    Blacklist()
