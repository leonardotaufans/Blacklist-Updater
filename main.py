# Store username and password for NAS and BIG IP in Windows Secure Vault
# To add argument parsing
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
        To split the list (both blacklist and whitelist) to its own arrays.
    main(self) : None
"""
import argparse
# To not show the inputted password when updating credentials
import getpass
import os.path
import re
import subprocess
import keyring as kr
# For SSH
import paramiko


class Conf:
    """
    Configuration class. Please adjust these variables.
    """

    SYNC_GROUP_NAME = ""  # The sync-group name. If left blank, configuration sync will not be performed.

    ARRAY_AMOUNT = 16  # The amount of address list. Adjust if necessary
    MOUNT = 'Z:'  # Where NAS would be letter-mounted.
    NAS_ADDR = '\\\\vm-winsrv16-1\\shared'  # Location on where the blacklist.txt and whitelist.txt file is stored.
    SELF_IP1 = '10.1.0.121'  # BIG IP Self IP address for Box 1.
    SELF_IP2 = '10.1.0.122'  # BIG IP Self IP address for Box 2.
    LIST_PREFIX = "addresslist"  # Prefix for the address lists' name.


class Blacklist:
    # DO NOT EDIT
    CONST_BIGIP = 'BIG-IP'
    CONST_NAS = 'NAS'

    # Initialize code, particularly for Argument Parser
    def __init__(self) -> None:
        """
        This is mostly used to initialize Argument Parser, enables other scripts to automate
        whenever there is a need to update the username/password.
        """
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
    def update_credentials(self, device: str, username: str = '', password: str = '') -> None:
        """
        Method used to update the credentials. This will delete the old username and password and upload
        the replacement.
        :param self:
        :param device: str
            To identify which device to be updated. This will also be used as part of the name
            in Windows Credentials Manager.
        :param username: str
            Username for said device. If the username is not entered, username will need to be manually
            typed in.
        :param password: str
            Password for said device. If the password is not entered, password will need to be manually
            typed in.
        """
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
        kr.set_password(f"{device}.password", username, password)
        exit()

    @staticmethod
    def which_array(ip_address: str) -> int:
        """
        Get to which list does the IP address should go to.
        :param ip_address:
            IP address that needs to be separated.
        :return:
            Which array the IP should go to (default: 0-15).
        """
        # Split by two parameter: dot (.) and colon (:)
        split = re.split('[.:]', ip_address)
        # Check if this is an IPv6 address
        if ip_address.find(':') != -1:
            # Change hex to decimal then modulus by number of lists (default: 16)
            return int(split[0], 16) % Conf.ARRAY_AMOUNT
        else:
            return int(split[0]) % Conf.ARRAY_AMOUNT

    def split_list_to_2d(self, ip_list: list) -> list:
        """
        Transform the list into a 2D array while splitting them by their first octet.
        :param ip_list:
            List of IP addresses that need to be separated.
        :return:
            2D arrays of IP addresses that has been separated.
        """
        # Initialize 2D arrays
        arr_2d = [[] * 16 for _ in range(Conf.ARRAY_AMOUNT)]
        for i in ip_list:
            # Add the IP address to the correct 2D array.
            arr_2d[self.which_array(ip_address=i)].append(i)
        return arr_2d

    def main(self) -> None:
        # check if Z: is mounted and if not, mount it.
        if not (os.path.exists(Conf.MOUNT)):
            nas_username = kr.get_password(f"{self.CONST_NAS}.username", username="username")
            nas_password = kr.get_password(f"{self.CONST_NAS}.password", username=nas_username)
            if nas_username is None or nas_password is None:
                # todo: If needed, use custom exception here.
                print('Username or password for NAS is not found. Ensure you have updated the username or \n'
                      'password and not delete them from the vault.')
                exit(-1)
            subprocess.check_output(
                f"net use {Conf.MOUNT} {Conf.NAS_ADDR} /user:{nas_username} {nas_password}", shell=True)

        # Get BIG IP username & password
        big_ip_username = kr.get_password(f"{self.CONST_BIGIP}.username", f"username")
        big_ip_password = kr.get_password(f"{self.CONST_BIGIP}.password", big_ip_username)
        if big_ip_username is None or big_ip_password is None:
            # todo: If needed, use custom exception here.
            print('Username or password for BIG IP is not found. Ensure you have updated the username or \n'
                  'password and not delete them from the vault.')
            exit(-1)

        # Get blacklist and whitelist file and split them to 2D array
        try:
            # Open the blacklist.txt and split them.
            with open(f"{Conf.MOUNT}\\blacklist.txt") as __:
                blacklist = self.split_list_to_2d(ip_list=[_.rstrip() for _ in __])
            # Open the whitelist.txt and split them.
            with open(f"{Conf.MOUNT}\\whitelist.txt") as __:
                whitelist = self.split_list_to_2d(ip_list=[_.rstrip() for _ in __])
        except IOError as e:
            print(e)
            exit(-1)

        # SSH to BIG IP
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        ssh.connect(hostname=Conf.SELF_IP1, username=big_ip_username, password=big_ip_password)
        # List the address list to be checked later
        _, stdout, stderr = (ssh.exec_command(f"tmsh list net address-list address-lists | grep {Conf.LIST_PREFIX}"))
        list_addr = stdout.read().decode()
        # Add blacklisted IP
        for r in range(len(blacklist)):
            # If address list is not found
            if list_addr.find(f"{Conf.LIST_PREFIX}-{r+1}") == -1:
                _, stdout, stderr = (ssh.exec_command
                                     (f"tmsh create net address-list {Conf.LIST_PREFIX}-{r + 1} addresses add "
                                      f"{{ {' '.join(map(str, blacklist[r]))} }}"))
            else:
                _, stdout, stderr = (ssh.exec_command
                                 (f"tmsh modify net address-list {Conf.LIST_PREFIX}-{r + 1} addresses add "
                                  f"{{ {' '.join(map(str, blacklist[r]))} }}"))
            if stdout.read().decode():
                print(stdout.read().decode())
            if stderr.read().decode():
                print(stderr.read().decode())
        # Delete whitelisted IP
        for r in range(len(whitelist)):
            _, stdout, stderr = (ssh.exec_command
                                 (f"tmsh modify net address-list {Conf.LIST_PREFIX}-{r + 1} addresses delete "
                                  f"{{ {' '.join(map(str, whitelist[r]))} }}"))
            if stdout.read().decode():
                print(stdout.read().decode())
            if stderr.read().decode():
                print(stderr.read().decode())
        # The BIG IP only syncs if sync-group name is entered.
        if not Conf.SYNC_GROUP_NAME:
            ssh.exec_command(f"tmsh run /cm config-sync to-group {Conf.SYNC_GROUP_NAME}")
        # close SSH session
        ssh.close()


if __name__ == '__main__':
    Blacklist()
