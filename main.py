import argparse
import contextlib
# To not show the inputted password when updating credentials
import getpass
import math
import re
import urllib.request
import urllib.error
import keyring as kr
import numpy as np
# For SSH
import paramiko
from bigrest.bigip import BIGIP


class Conf:
    """
    Configuration class. Please adjust these variables.
    """

    SYNC_GROUP_NAME = ""  # The sync-group name. If left blank, configuration sync will not be performed.
    ARRAY_AMOUNT = 16  # The amount of address list. Adjust if necessary
    ARRAY_AMOUNT_V6 = 4  # The amount of address list for IPv6
    SELF_IP1 = '10.1.0.122'  # BIG IP Self IP address for Box 1.
    # SELF_IP2 = ''  # BIG IP Self IP address for Box 2.
    LIST_PREFIX = "address-list"  # Prefix for the address lists.
    LIST_PREFIX_V6 = "address-list_v6"  # Prefix for IPv6 address lists
    BLACKLIST_URL = "http://localhost:8000/blacklist.txt"  # Path for blacklist file
    WHITELIST_URL = "http://localhost:8000/whitelist.txt"  # Path for whitelist file


class Blacklist:
    """
        Automates updating address lists.
        ...
        Methods
        -------
        update_credentials(self, device: str, username: str = '', password: str = '') : None
            Method to update the credentials in Credential Manager.
        which_array(self, ip_address: str) : int
            To decide which list the IP address goes to.
        split_list_to_2d(self, ip_list: list) : list
            To split the IPv4 list (both blacklist and whitelist) to its own arrays.
        split_list_to_2d_v6(self, ip_list: list) : list
            To split the IPv6 list (both blacklist and whitelist) to its own arrays.

        main(self) : None
    """
    # DO NOT EDIT
    CONST_BIGIP = 'BIG-IP'

    def __init__(self) -> None:
        """
        This is mostly used to initialize Argument Parser, enables other scripts to automate
        whenever there is a need to update the username/password.
        """
        # Argument Parser
        parent_args = argparse.ArgumentParser()
        parent_args.add_argument("--Update-Credentials", "-c",
                                 action="store")
        parent_args.add_argument("--Username", "-u", help="Username (for updating credentials)", nargs='?',
                                 action="store", default="")
        parent_args.add_argument("--Password", "-p", help="Password (for updating credentials)", nargs='?',
                                 action="store", default="")
        args = parent_args.parse_args()
        if args.Update_Credentials is not None:
            self.update_credentials(username=args.Username,
                                    password=args.Password)
        # Running the main code. It's close to the very bottom of this class
        self.main()

    @staticmethod
    def update_credentials(username: str = '', password: str = '') -> None:
        """
        Method used to update the credentials. This will delete the old username and password and upload
        the replacement.
        :param username: str
            Username for said device. If the username is not entered, username will need to be manually
            typed in.
        :param password: str
            Password for said device. If the password is not entered, password will need to be manually
            typed in.
        """
        print(f'Updating BIG-IP Credentials in Vault\n-------------------')
        print(f'(This account requires access to SSH)')
        device = "BIG-IP"
        username = username
        if username == "":
            username = input(f"Enter {device} Username: \n")
        password = password
        if password == "":
            password = getpass.getpass(f"Enter {device} Password: \n")
        old_username = kr.get_password(f"{device}.username", "username")

        # This ensures that only one user/password is saved in the server and prevent erratic behavior.
        if old_username is not None:
            kr.delete_password(f"{device}.username", username="username")
            kr.delete_password(f"{device}.password", username=old_username)
        kr.set_password(f"{device}.username", "username", username)
        kr.set_password(f"{device}.password", username, password)
        exit()

    @staticmethod
    def blacklist(ssh: paramiko.SSHClient, device: BIGIP, addr_list: list, destination: int):
        # Add blacklisted IP
        for r in range(len(addr_list)):
            new_list = addr_list[r]
            match destination:
                case 4:
                    new_list_name = f"{Conf.LIST_PREFIX}-{r + 1}"
                    dummy_ip = "233.252.0.255"
                case _:
                    new_list_name = f"{Conf.LIST_PREFIX_V6}-{r + 1}"
                    dummy_ip = "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"
            # If address list is not found
            if not device.exist(f'/mgmt/tm/security/firewall/address-list/{new_list_name}'):
                is_new_list = True
                print(f'\u24d8 Creating new address lists as {new_list_name}...')
                _, stdout, stderr = (ssh.exec_command
                                     (f"tmsh create net address-list {new_list_name} addresses add "
                                      f"{{ {dummy_ip} }}"))
                print(stdout.read().decode())
                print(stderr.read().decode())
            else:
                curr = \
                    device.load(
                        f'/mgmt/tm/security/firewall/address-list/{new_list_name}?$select=addresses').properties[
                        "addresses"]
                old_list = []
                for i in curr:
                    old_list.append(list(i.values())[0])
                new_list = list(set(addr_list[r]) - set(old_list))
                if len(new_list) == 0:
                    print(f"\u24d8 There are no new IP addresses for {new_list_name}.")
                    continue
            with contextlib.suppress(ValueError):
                split_list = np.array_split(new_list, math.ceil(len(new_list) / 1000))
            print(f'\u24d8 Adding new IP address to {new_list_name}...')
            for i in range(len(split_list)):
                _, stdout, stderr = (ssh.exec_command
                                     (f"tmsh modify net address-list {new_list_name} addresses add "
                                      f"{{ {' '.join(map(str, split_list[i]))} }}"))
                exit_status = stdout.channel.recv_exit_status()
                if exit_status == 0:
                    print(f"\u2705 Success ({i + 1}/{len(split_list)}).")
                else:
                    print(f"\u274c Failed ({i + 1}/{len(split_list)}).")
                    print(stdout.read().decode().strip())
                    print(stderr.read().decode().strip())

    @staticmethod
    def whitelist(ssh: paramiko.SSHClient, addr_list: list, destination: int) -> None:
        for r in range(len(addr_list)):
            with contextlib.suppress(ValueError):
                whitelisting = addr_list[r]
                split_list = np.array_split(whitelisting, math.ceil(len(whitelisting) / 1000))
            match destination:
                case 4:
                    new_list_name = f"{Conf.LIST_PREFIX}-{r + 1}"
                case _:
                    new_list_name = f"{Conf.LIST_PREFIX_V6}-{r + 1}"
            print(f'\u24d8 Removing IP address from {new_list_name}...')
            for i in range(len(split_list)):
                _, stdout, stderr = (ssh.exec_command
                                     (f"tmsh modify net address-list {new_list_name} addresses delete "
                                      f"{{ {' '.join(map(str, split_list[i]))} }}"))
                exit_status = stdout.channel.recv_exit_status()
                if exit_status == 0:
                    print(f"\u2705 Success ({i + 1}/{len(split_list)}).")
                else:
                    print(f"\u274c Failed ({i + 1}/{len(split_list)}).")
                    print(stdout.read().decode().strip())
                    print(stderr.read().decode().strip())

    def main(self) -> None:
        print(f"\u24d8 Checking for credentials...")
        # Get BIG IP username & password
        big_ip_username = kr.get_password(f"{self.CONST_BIGIP}.username", f"username")
        big_ip_password = kr.get_password(f"{self.CONST_BIGIP}.password", big_ip_username)
        if big_ip_username is None or big_ip_password is None:
            print('Username or password for BIG IP is not found. Ensure you have updated the username or \n'
                  'password and not delete them from the vault.')
            exit(-1)

            # SSH to BIG IP
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        print(f"\u24d8 Starting SSH...")
        try:
            ssh.connect(hostname=Conf.SELF_IP1, username=big_ip_username, password=big_ip_password)
        except paramiko.ssh_exception.AuthenticationException as e:
            print(f"\u274c Failed.")
            print("Error: Authentication with BIG-IP failed. Please ensure your username/password are correct.")
            print(f"Error details: {e}")
            exit(-1)
        print(f"\u2705 SSH Success.")
        # Get blacklist and put them to AFM
        blacklist = [[] * 16 for _ in range(Conf.ARRAY_AMOUNT)]
        blacklist_v6 = [[] * 16 for _ in range(Conf.ARRAY_AMOUNT_V6)]
        print(f"\u24d8 Accessing {Conf.BLACKLIST_URL}...")

        for line in urllib.request.urlopen(Conf.BLACKLIST_URL):
            ip_address = line.decode('utf-8').strip()
            split = re.split('[.:]', string=ip_address)
            # Check if this is an IPv6 address
            if ip_address.find(':') != -1:  # IPv6
                array_location = (int(split[0], 16) % Conf.ARRAY_AMOUNT_V6)
                blacklist_v6[array_location].append(ip_address)
            else:  # IPv4
                array_location = (int(split[0]) % Conf.ARRAY_AMOUNT)
                blacklist[array_location].append(ip_address)
        print(f"\u24d8 Logging in to BIG-IP...")
        device = BIGIP(device=Conf.SELF_IP1, session_verify=False, username=big_ip_username, password=big_ip_password)
        self.blacklist(ssh=ssh, device=device, addr_list=blacklist, destination=4)
        self.blacklist(ssh=ssh, device=device, addr_list=blacklist_v6, destination=6)

        # Get whitelist and remove them from AFM
        whitelist = [[] * 16 for _ in range(Conf.ARRAY_AMOUNT)]
        whitelist_v6 = [[] * 16 for _ in range(Conf.ARRAY_AMOUNT_V6)]
        print(f"\u24d8 Accessing {Conf.WHITELIST_URL}")
        for line in urllib.request.urlopen(Conf.WHITELIST_URL):
            ip_address = line.decode('utf-8').strip()
            split = re.split('[.:]', string=ip_address)
            # Check if this is an IPv6 address
            if ip_address.find(':') != -1:  # IPv6
                array_location = (int(split[0], 16) % Conf.ARRAY_AMOUNT_V6)
                whitelist_v6[array_location].append(ip_address)
            else:  # IPv4
                array_location = (int(split[0]) % Conf.ARRAY_AMOUNT)
                whitelist[array_location].append(ip_address)
        self.whitelist(ssh=ssh, addr_list=whitelist, destination=4)
        self.whitelist(ssh=ssh, addr_list=whitelist_v6, destination=6)

        # The BIG IP only syncs if sync-group name is entered.
        if not Conf.SYNC_GROUP_NAME:
            print(f"\u24d8 Syncing HA device...")
            ssh.exec_command(f"run /cm config-sync to-group {Conf.SYNC_GROUP_NAME}")
        # close SSH session
        print(f"\u2705 AFM Address List update has been completed.")
        ssh.close()


if __name__ == '__main__':
    Blacklist()
