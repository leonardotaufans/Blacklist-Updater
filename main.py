import argparse
import contextlib
import getpass  # To not show the inputted password when updating credentials
import math
import re
# For mail
import smtplib
import socket
from datetime import date
from email.message import EmailMessage
from urllib import request as http_req
import keyring as kr
import keyring.errors as kr_e
import numpy as np
# For SSH
import paramiko
from bigrest.bigip import BIGIP

# Constant Values for this script
bigip_username = "BIG-IP.username"
bigip_password = "BIG-IP.password"
mail_username = "BIG-IP.address"
mail_password = "BIG-IP.password"


class Conf:
    """
    Configuration class. Please adjust these variables.
    """
    SYNC_GROUP_NAME = ""  # The sync-group name. If left blank, configuration sync will not be performed.
    ARRAY_AMOUNT = 16  # The amount of address list. Adjust if necessary
    ARRAY_AMOUNT_V6 = 4  # The amount of address list for IPv6
    SELF_IP1 = '10.10.10.199'  # BIG IP Self IP address for Box 1.
    LIST_PREFIX = "address-list"  # Prefix for the address lists.
    LIST_PREFIX_V6 = "address-list_v6"  # Prefix for IPv6 address lists
    BLACKLIST_URL = "http://10.10.10.113:8000/blacklist.txt"  # Path for blacklist file
    WHITELIST_URL = "http://10.10.10.113:8000/whitelist.txt"  # Path for whitelist file
    # For email
    EMAIL_RECEIVER = ["<user@localhost.lab>", "<group@localhost.lab>"]  # Email addresses who will receive the email
    EMAIL_SUBJECT = "Automated Blacklist Update Report"
    EMAIL_SMTP = {
        "host": "10.10.10.113",  # SMTP address
        "address": "localhost.lab",
        "port": 25  # SMTP port
    }


class Email:
    """Class used for handling the preparing and delivering emails.

    ...
    Methods
    -----
    msg_add(self, append_message: str = "") -> None
        Adds information to the message body into a new line.
    send_mail(self, error: str = "") : None
        Sends the mail. If error is found, it will also append the error message.
    """
    user, pw = "", ""
    data = ""
    mes = EmailMessage()

    def __init__(self, subject=""):
        today = date.today().strftime("%B %d, %Y")
        try:
            _ = kr.get_password(bigip_username, "username")
            user = f"{_}@{Conf.EMAIL_SMTP["address"]}"
            mail = smtplib.SMTP(host=Conf.EMAIL_SMTP["host"], port=Conf.EMAIL_SMTP["port"])
            mail.ehlo()
        except kr_e.KeyringError as e:
            print(e)
            exit(-1)
        except smtplib.SMTPException as e:
            print(e)
            exit(-1)

        del self.mes["Subject"]
        del self.mes["From"]
        del self.mes["To"]
        self.mes.add_header("Subject", f"{Conf.EMAIL_SUBJECT} - {today}")
        self.mes.add_header("From", f"<{user}>")
        self.mes.add_header("To", ', '.join(Conf.EMAIL_RECEIVER))
        self.data += f"""Automated Blacklist Update Report - {today}:\n{subject}"""

    def msg_add(self, append_message: str = "") -> None:
        """
        Appends new information to the message body.
        :param append_message: Message to be added.
        :type append_message: str
        """
        self.data += f"""{append_message}\n"""
        print(f"{append_message}")

    def send_mail(self, error: str = "") -> None:
        """
        Sends the email.
        :param error: Error message if any. Default is empty ("")
        :type error: str
        :except KeyringError: if username/password can't be fetched.
        :except SMTPError: if SMTP server can't be reached.
        """
        try:
            _ = kr.get_password(bigip_username, "username")
            user = f"{_}@{Conf.EMAIL_SMTP["address"]}"
            pw = kr.get_password(bigip_password, _)
        except kr_e.KeyringError as e:
            print(e)
            exit(-1)
        if error:
            self.data += f"""Error: {error}"""
        self.data += """Execution Completed. \n"""
        self.mes.set_content(self.data)
        try:
            mail = smtplib.SMTP(host=Conf.EMAIL_SMTP["host"], port=Conf.EMAIL_SMTP["port"])
            mail.login(user=user, password=pw)
            mail.send_message(
                from_addr=user,
                to_addrs=Conf.EMAIL_RECEIVER,
                msg=self.mes
            )
            mail.quit()
        except smtplib.SMTPException as e:
            print(e)
            exit(-1)


class RunError(Exception):
    """This exception will be raised if there is any issues during this run."""

    def __init__(self, message, errors):
        super().__init__(message)
        msg = Email()
        msg.msg_add(errors)
        msg.send_mail(error=errors)
        print(errors)
        exit(-1)


class Blacklist:
    """
        Automates updating address lists.
        ...
        Methods
        -------
        update_credentials(username: str = '', password: str = '') : None
            Method to update the credentials in Credential Manager.
        blacklist(ssh: paramiko.SSHClient, device: BIGIP, address_list: list, destination: int, mail: Email) : None
        whitelist(ssh: paramiko.SSHClient, device: BIGIP, address_list: list, destination: int, mail: Email) : None
        main(self) : None
    """

    def __init__(self) -> None:
        """
        This is mostly used to initialize Argument Parser, enables other scripts to automate
        whenever there is a need to update the username/password.
        """
        # Argument Parser
        parent_args = argparse.ArgumentParser(description="Automates updating AFM blacklist.")
        parent_args.add_argument("--Update-F5-Credentials", "-cf5",
                                 action="store_true",
                                 help="Updates the email credentials. "
                                      "Optional Arguments: --Username [Email] --Password [Password]",
                                 default=None)
        parent_args.add_argument("--Username", "-u",
                                 help="(Optional) Username (for updating credentials)", nargs='?',
                                 action="store", default="", required=False)
        parent_args.add_argument("--Password", "-p",
                                 help="(Optional) Password (for updating credentials)", nargs='?',
                                 action="store", default="", required=False)
        args = parent_args.parse_args()
        if args.Update_F5_Credentials is not None:
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
        :returns: None
        """
        print(f'\u24d8 Updating F5 Credentials in Vault\n-------------------')
        print(f'(This account requires access to SSH)')
        username = username
        if username == "":
            username = input(f"Enter F5 Username: \n")
        password = password
        if password == "":
            password = getpass.getpass(f"Enter F5 Password: \n")

        # This ensures that only one user/password is saved in the server and prevent erratic behavior.
        old_username = kr.get_password(f"BIG-IP.username", "username")
        if old_username is not None:
            kr.delete_password(f"BIG-IP.username", username="username")
            kr.delete_password(f"BIG-IP.password", username=old_username)
        kr.set_password(f"BIG-IP.username", "username", username)
        kr.set_password(f"BIG-IP.password", username, password)
        mail = Email("Update F5 Credentials")
        mail.msg_add(f"Update F5 Credentials complete.\nUsername: {username}.")
        exit()

    @staticmethod
    def blacklist(ssh: paramiko.SSHClient, device: BIGIP,
                  addr_list: list, destination: int, mail: Email) -> None:
        """
        Prepares the IP addresses to be blacklisted. This will split the IP address into chunks that
        can be easily processed, ensure that it doesn't have any duplicates, and further split them for
        bigger push.
        :param ssh:
            SSH Client used to access F5 device
        :type ssh: SSHClient
        :param device:
            F5 BIG-IP iControl to get the current address lists
        :type device: BIGIP
        :param addr_list:
            Lists of IP addresses that need to be split
        :type addr_list: list
        :param destination:
            Which IP version this list is for (IPv4 or IPv6)
        :type destination: int
        :param mail:
            Initialized email class
        :type mail: Email
        :returns: None
        """
        # Add blacklisted IP to separate lists
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
                mail.msg_add(f'\u24d8 Creating new address lists as {new_list_name}...')
                _, stdout, stderr = (ssh.exec_command
                                     (f"create net address-list {new_list_name} addresses add "
                                      f"{{ {dummy_ip} }}"))
                print(stdout.read().decode())
                print(stderr.read().decode())
            else:
                # If found, this address list will be checked for any duplicates
                curr = \
                    device.load(
                        f'/mgmt/tm/security/firewall/address-list/{new_list_name}?$select=addresses').properties[
                        "addresses"]
                old_list = []
                for i in curr:
                    old_list.append(list(i.values())[0])
                new_list = list(set(addr_list[r]) - set(old_list))
                if len(new_list) == 0:
                    mail.msg_add(f"\u24d8 There are no new IP addresses for {new_list_name}.")
                    continue
            # Split further to 1000 IPs to reduce performance impact
            with contextlib.suppress(ValueError):
                split_list = np.array_split(new_list, math.ceil(len(new_list) / 1000))
                print(f'\u24d8 Adding new IP address to {new_list_name}...')
                for i in range(len(split_list)):
                    _, stdout, stderr = (ssh.exec_command
                                         (f"modify net address-list {new_list_name} addresses add "
                                          f"{{ {' '.join(map(str, split_list[i]))} }}"))
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status == 0:
                        mail.msg_add(
                            f"\u2705 {new_list_name}: Blacklisting of IPs success ({i + 1}/{len(split_list)}).")

                    else:
                        mail.msg_add(f"\u274c {new_list_name}: Blacklisting of IPs failed ({i + 1}/{len(split_list)}).")
                        print(stdout.read().decode().strip())
                        print(stderr.read().decode().strip())

    @staticmethod
    def whitelist(ssh: paramiko.SSHClient, addr_list: list, destination: int, mail: Email) -> None:
        for r in range(len(addr_list)):
            with contextlib.suppress(ValueError):
                # todo: Test if whitelisting would mess up if one of them are not found
                # cause if so, there will be a need to verify the IP address existence
                whitelisting = addr_list[r]
                split_list = np.array_split(whitelisting, math.ceil(len(whitelisting) / 1000))
                match destination:
                    case 4:
                        new_list_name = f"{Conf.LIST_PREFIX}-{r + 1}"
                    case _:
                        new_list_name = f"{Conf.LIST_PREFIX_V6}-{r + 1}"
                mail.msg_add(f'\u24d8 Removing IP address from {new_list_name}...')
                for i in range(len(split_list)):
                    _, stdout, stderr = (ssh.exec_command
                                         (f"modify net address-list {new_list_name} addresses delete "
                                          f"{{ {' '.join(map(str, split_list[i]))} }}"))
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status == 0:
                        mail.msg_add(
                            f"  \u2705 {new_list_name} ({i + 1}/{len(split_list)}): Whitelisting of IPs success.")
                    else:
                        mail.msg_add(
                            f"  \u274c {new_list_name} ({i + 1}/{len(split_list)}): Whitelisting of IPs failed.")
                        mail.msg_add(stderr.read().decode().strip())
                        print(stdout.read().decode().strip())
                        print(stderr.read().decode().strip())

    def main(self) -> None:
        mail = Email()
        print(f"\u24d8 Checking for credentials...")
        # Get BIG IP username & password
        big_ip_username = kr.get_password(f"BIG-IP.username", "username")
        big_ip_password = kr.get_password(f"BIG-IP.password", big_ip_username)
        if big_ip_username is None or big_ip_password is None:
            raise RunError(
                "\u274c Username or password for BIG IP is not found. Ensure you have updated the username or \n"
                "password and not delete them from the vault.", "Authentication Failed")

        # SSH to BIG IP
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        print(f"\u24d8 Starting SSH...")
        try:
            ssh.connect(hostname=Conf.SELF_IP1, username=big_ip_username, password=big_ip_password)
        except KeyboardInterrupt:
            exit()
        except paramiko.ssh_exception.AuthenticationException as e:
            print(f"\u274c Failed.")
            raise RunError(
                message=f"\u274c Authentication with BIG-IP failed. Please ensure your username/password are correct."
                        f"Details: {e}", errors=e)
        except socket.error as e:
            print(f"\u274c Failed.")
            raise RunError(
                message="\u274c Error: SSH with BIG-IP failed. Please ensure you are able to connect with BIG-IP and "
                        "firewalls have been opened."
                        f"Details: {e}", errors=e)
        print(f"\u2705 SSH Success.")
        print(f"\u24d8 Logging in to BIG-IP through iControl...")
        device = BIGIP(device=Conf.SELF_IP1, session_verify=False, username=big_ip_username, password=big_ip_password)

        # Getting blacklisted address
        blacklist = [[] * 16 for _ in range(Conf.ARRAY_AMOUNT)]
        blacklist_v6 = [[] * 16 for _ in range(Conf.ARRAY_AMOUNT_V6)]
        # Accessing the URL to get blacklisted IP addresses
        print(f"\u24d8 Accessing {Conf.BLACKLIST_URL}...")
        try:
            for line in http_req.urlopen(Conf.BLACKLIST_URL):
                ip_address = line.decode('utf-8').strip()
                split = re.split('[.:]', string=ip_address)
                # Check if this is an IPv6 address
                if ip_address.find(':') != -1:  # IPv6
                    array_location = (int(split[0], 16) % Conf.ARRAY_AMOUNT_V6)
                    blacklist_v6[array_location].append(ip_address)
                else:  # IPv4
                    array_location = (int(split[0]) % Conf.ARRAY_AMOUNT)
                    blacklist[array_location].append(ip_address)
        except Exception as e:
            raise RunError(f"\u274c Accessing to {Conf.BLACKLIST_URL} failed. Please ensure that the firewall is open. "
                           f"Details: {e}",
                           errors=e)
        self.blacklist(ssh=ssh, device=device, addr_list=blacklist, destination=4, mail=mail)
        self.blacklist(ssh=ssh, device=device, addr_list=blacklist_v6, destination=6, mail=mail)

        # Get whitelist and remove them from AFM
        whitelist = [[] * 16 for _ in range(Conf.ARRAY_AMOUNT)]
        whitelist_v6 = [[] * 16 for _ in range(Conf.ARRAY_AMOUNT_V6)]
        print(f"\u24d8 Accessing {Conf.WHITELIST_URL}")
        for line in http_req.urlopen(Conf.WHITELIST_URL):
            ip_address = line.decode('utf-8').strip()
            split = re.split('[.:]', string=ip_address)
            # Check if this is an IPv6 address
            if ip_address.find(':') != -1:  # IPv6
                array_location = (int(split[0], 16) % Conf.ARRAY_AMOUNT_V6)
                whitelist_v6[array_location].append(ip_address)
            else:  # IPv4
                array_location = (int(split[0]) % Conf.ARRAY_AMOUNT)
                whitelist[array_location].append(ip_address)
        self.whitelist(ssh=ssh, addr_list=whitelist, destination=4, mail=mail)
        self.whitelist(ssh=ssh, addr_list=whitelist_v6, destination=6, mail=mail)

        # The BIG IP will only be synced if sync-group name is entered.
        if Conf.SYNC_GROUP_NAME:
            print(f"\u24d8 Syncing HA device...")
            ssh.exec_command(f"run /cm config-sync to-group {Conf.SYNC_GROUP_NAME}")
            mail.msg_add(f"\u2705 Syncing HA device {Conf.SYNC_GROUP_NAME} has been completed.")
        # close SSH session
        print(f"\u2705 AFM Address List update has been completed.")
        mail.send_mail()
        ssh.close()


if __name__ == '__main__':
    Blacklist()
