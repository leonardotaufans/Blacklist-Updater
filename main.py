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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib import request as http_req

import keyring as kr
import keyring.errors as kr_e
import numpy as np
# For SSH
import paramiko
import requests.exceptions
from bigrest.bigip import BIGIP

# Constant Values for this script
bigip_username = "BIG-IP.username"
bigip_password = "BIG-IP.password"
mail_username = "BIG-IP.address"
mail_password = "BIG-IP.password"


class Conf:
    """
    Configuration class. Please adjust these variables as needed.
    """
    SYNC_GROUP_NAME = ""  # The sync-group name. If left blank, configuration sync will not be performed.
    ARRAY_AMOUNT = 16  # The amount of address list. Adjust if necessary
    ARRAY_AMOUNT_V6 = 4  # The amount of address list for IPv6
    SELF_IP1 = '10.1.0.122'  # BIG IP Self IP address for Box 1.
    SELF_IP2 = '10.1.0.123'  # BIG IP Self IP address for Box 2.
    LIST_PREFIX = "security_blacklist"  # Prefix for the address lists.
    LIST_PREFIX_V6 = "v6_security_blacklist"  # Prefix for IPv6 address lists
    BLACKLIST_URL = "http://10.10.10.11:8000/blacklist.txt"  # Path for blacklist file
    # For email
    EMAIL_RECEIVER = ["<security@sp.edu.sg>",
                      "<INDT-InfraFM-Vendor-NW-Staff@sp.edu.sg>",
                      "<INDT-InfraFM-Vendor-Mgr@sp.edu.sg>",
                      "<noc@sp.edu.sg>"]  # Email addresses who will receive the email
    EMAIL_SUBJECT = "Automated Blacklist Update Report"  # Subject of the email (will be appended with date)
    SEND_EMAIL = True  # This will enable/disable email delivery
    VERBOSE = False  # This will enable/disable full logging
    EMAIL_SMTP = {"host": "localhost", "address": "sp.edu.sg", "port": 25}  # For debugging only todo:
    # EMAIL_SMTP = {"host": "smtp.sp.edu.sg", "address": "sp.edu.sg", "port": 25}  # SMTP address
    MESSAGE_BODY = \
        """Automated Blacklist Update Report\n
Date: {date}\n
{result}\n
        """  # If there is a template needed for the email


class Email:
    """Class used for handling the preparing and delivering emails.

    Methods

    -----

    -- __init__(self, subject: str="") -> None
        Initialize the email class
    -- update_number_of_ip(self, ip_added: int, ip_removed: int) -> None
        Adds information about the numbers of IP added and removed.
    -- msg_add(self, append_message: str = "", error: int = 0) -> None
        Adds information to the message body into a new line. If error is found in the script,
        it will be logged as an error.
    -- send_mail(self, error: str = "") : None
        Sends the mail. If error is found, it will also append the error message.
    """
    user, pw = "", ""
    data = ""
    mes = EmailMessage()
    error = 0
    today = date.today().strftime("%B %d, %Y")
    ip_added = -1
    ip_removed = -1
    subject = ""

    def __init__(self, subject=""):
        _ = kr.get_password(bigip_username, "username")
        user = f"{_}@{Conf.EMAIL_SMTP['address']}"
        if Conf.SEND_EMAIL:
            try:
                mail = smtplib.SMTP(host=Conf.EMAIL_SMTP["host"], port=Conf.EMAIL_SMTP["port"])
                # mail.starttls()
                mail.connect(Conf.EMAIL_SMTP["host"], Conf.EMAIL_SMTP["port"])
                mail.ehlo()
            except kr_e.KeyringError as e:
                print(e)
                exit(-1)
            except smtplib.SMTPException as e:
                print(e)
                exit(-1)
            except ConnectionRefusedError:
                pass

        del self.mes["Subject"]
        del self.mes["From"]
        del self.mes["To"]
        self.mes.add_header("From", f"<{user}>")
        self.mes.add_header("To", ', '.join(Conf.EMAIL_RECEIVER))
        if subject:
            self.subject = subject

    def update_number_of_ip(self, ip_added: int = -1, ip_removed: int = -1) -> None:
        """
        Adds information about the number of IP address being added or removed.
        :param int ip_added: Number of IP address that is added to the list.
        :param int ip_removed: Number of IP address that is removed from the list.
        :return: None
        """
        if ip_added > -1:
            self.ip_added = ip_added
        if ip_removed > -1:
            self.ip_removed = ip_removed

    def msg_add(self, append_message: str = "", error: int = 0) -> None:
        """
        Appends new information to the message body. If verbose is disabled, only errors are added to the message.
        :param int error: This parameter will be used if there is any error in the script.
        :param str append_message: Message to be added.
        """
        if Conf.VERBOSE:
            self.data += f"""{append_message}\n"""
        self.error = error

    def send_mail(self, error: str = "") -> None:
        """
        Sends the email. If Conf.VERBOSE is False, it will only send a simple message from Conf.MESSAGE_BODY.
        :param str error: Error message if any is found. Default is empty ("")
        :except KeyringError: if username/password can't be fetched.
        :except SMTPError: if SMTP server can't be reached.
        """
        if Conf.SEND_EMAIL:  # So this won't be executed when email is not being sent
            result = "The script has been executed successfully."
            if error:
                result = "The script found an error that needs to be fixed."
            self.data += f"""{Conf.MESSAGE_BODY.format(date=self.today, result=result)}\n"""
            if Conf.VERBOSE:
                self.data += """\nDetails: \n"""
            try:
                # Getting username from Keyring
                _ = kr.get_password(bigip_username, "username")
                user = f"{_}@{Conf.EMAIL_SMTP['address']}"
            except kr_e.KeyringError as e:
                print(e)
                exit(-1)

            if error:  # If the script failed entirely
                self.mes.add_header("Subject", f"{Conf.EMAIL_SUBJECT} Failed - {self.today}")
                self.data += f"""Failed: {error}\n"""
            elif self.error >= 1:  # If error is found during the script
                self.mes.add_header("Subject", f"{Conf.EMAIL_SUBJECT} Error - {self.today}")
                self.data += f"""Error has been captured during execution."""
            elif self.subject:  # If this is not the main script activity (credentials update etc.)
                self.mes.add_header("Subject", f"{Conf.EMAIL_SUBJECT} {self.subject}")
                self.data += f"""Credentials have been updated."""
            else:
                self.mes.add_header("Subject", f"{Conf.EMAIL_SUBJECT} Success - {self.today}")
                self.data += """Execution Completed. \n"""

            # Show how many addresses are being added and/or removed.
            if not error and not Conf.VERBOSE and (self.ip_added > -1 or self.ip_removed > -1):
                self.data += f"""Number of added IP address: {self.ip_added}\n"""
                self.data += f"""Number of removed IP address: {self.ip_removed}\n"""

            self.mes.set_payload(self.data)
            try:
                # Sending mail
                mail = smtplib.SMTP(host=Conf.EMAIL_SMTP["host"], port=Conf.EMAIL_SMTP["port"])
                mail.connect(Conf.EMAIL_SMTP["host"], Conf.EMAIL_SMTP["port"])
                mail.send_message(
                    from_addr=user,
                    to_addrs=Conf.EMAIL_RECEIVER,
                    msg=self.mes
                )
                mail.quit()
            except smtplib.SMTPException as e:
                print(e)
                exit(-1)
            except ConnectionRefusedError:
                pass


class RunError(Exception):
    """This exception will be raised if there is any issues during this run."""

    def __init__(self, message: str, errors: str):
        """
        This will send an email when a failure is caught that causes the script unable to continue.
        :param str message: Message about the failure.
        :param str errors: Exception details (if any).
        """
        msg = Email()
        msg.msg_add(message)
        msg.send_mail(error=errors)
        print(errors)
        exit(-1)


class Blacklist:
    """
        Automates updating address lists.

        Methods

        ------

        -- update_credentials(username: str = '', password: str = '') : None
            Method to update the credentials in Credential Manager.
        -- blacklist(ssh: paramiko.SSHClient, device: BIGIP, address_list: list, destination: int, mail: Email) : None
            Method to update the blacklisted IP address
        -- get_active_ip(big_ip_username: str, big_ip_password: str) : None
            Method to get which self IP is the currently running device
        -- main(self) : None
            Main script

    """

    def __init__(self) -> None:
        """
        This is mostly used to initialize Argument Parser, enables other scripts to automate whenever there is a
        need to update the username/password.

        """
        # Argument Parser
        parent_args = argparse.ArgumentParser(description="Automates updating AFM blacklist.")
        parent_args.add_argument("--Update-F5-Credentials", "-cf5",
                                 action="store_true",
                                 help="Updates the credentials. "
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
        the replacement. This requires an argument passed to be executed.

        Sample 1::

            python main.py --Update-F5-Credentials
        This will prompt you for username and password.

        Sample 2::

            python main.py --Update-F5-Credentials --Username <username>
        This will only prompt for password.

        Sample 3::

            python main.py --Update-F5-Credentials --Username <username> --Password <password>
        This won't prompt for any input. Useful if the password update needs to be automated.


        :param str username:
            Username for said device. If the username is not entered, username will need to be manually
            typed in.

        :param str password:
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
        mail.send_mail()
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
            new_list: list = addr_list[r]
            del_list = []
            match destination:
                case 4:
                    new_list_name = f"{Conf.LIST_PREFIX}-{r + 1}"
                    dummy_ip = "233.252.0.255"
                case _:
                    new_list_name = f"{Conf.LIST_PREFIX_V6}-{r + 1}"
                    dummy_ip = "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"
            if not device.exist(f'/mgmt/tm/security/firewall/address-list/{new_list_name}'):
                new_list.append(dummy_ip)
                device.create(f'/mgmt/tm/security/firewall/address-list',
                              {'name': new_list_name, 'addresses': new_list})
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
                    f"\u24d8 There are no removed IP addresses for {new_list_name}."
                    mail.msg_add(f"\u24d8 There are no new IP addresses for {new_list_name}.")
                else:
                    with contextlib.suppress(ValueError):
                        split_list = np.array_split(new_list, math.ceil(len(new_list) / 1000))
                        print(f'\u24d8 Adding new IP address to {new_list_name}...')
                        for i in range(len(split_list)):
                            _, stdout, stderr = (ssh.exec_command
                                                 (f"modify net address-list {new_list_name} addresses add "
                                                  f"{{ {' '.join(map(str, split_list[i]))} }}"))
                            exit_status = stdout.channel.recv_exit_status()
                            if exit_status == 0:
                                print(
                                    f"\u2705 {new_list_name}: Blacklisting of IPs success ({i + 1}/{len(split_list)}).")

                            else:
                                print(
                                    f"\u274c {new_list_name}: Blacklisting of IPs failed ({i + 1}/{len(split_list)}).")
                                mail.msg_add(
                                    f"\u274c {new_list_name}: Blacklisting of IPs failed ({i + 1}/{len(split_list)}).")
                                print(stdout.read().decode().strip())
                                print(stderr.read().decode().strip())

                # Whitelisting
                print("Removing IP address from the address list...")
                new_curr = \
                    device.load(
                        f'/mgmt/tm/security/firewall/address-list/{new_list_name}?$select=addresses').properties[
                        "addresses"]
                curr_list = []
                for i in new_curr:
                    curr_list.append(list(i.values())[0])
                del_list = list(set(curr_list) - set(addr_list[r]) - {dummy_ip})
                print(del_list)
                if len(del_list) <= 1:
                    print(f"\u24d8 There are no removed IP addresses for {new_list_name}.")
                    mail.msg_add(f"\u24d8 There are no removed IP addresses for {new_list_name}.")
                else:
                    with contextlib.suppress(ValueError):
                        split_list = np.array_split(del_list, math.ceil(len(del_list) / 1000))
                        print(f'\u24d8 Removing IP address from {new_list_name}...')
                        for i in range(len(split_list)):
                            _, stdout, stderr = (ssh.exec_command
                                                 (f"modify net address-list {new_list_name} addresses delete "
                                                  f"{{ {' '.join(map(str, split_list[i]))} }}"))
                            exit_status = stdout.channel.recv_exit_status()
                            if exit_status == 0:
                                print(
                                    f"\u2705 {new_list_name}: Whitelisting of IPs success ({i + 1}/{len(split_list)}).")

                            else:
                                print(
                                    f"\u274c {new_list_name}: Whitelisting of IPs failed ({i + 1}/{len(split_list)}).")
                                mail.msg_add(
                                    f"\u274c {new_list_name}: Whitelisting of IPs failed ({i + 1}/{len(split_list)}).")
                                print(stdout.read().decode().strip())
                                print(stderr.read().decode().strip())
            mail.update_number_of_ip(ip_added=len(new_list), ip_removed=len(del_list))
            mail.msg_add(
                f"\u2705 {new_list_name}: Blacklisting of IPs success. "
                f"Number of addresses added: {len(new_list)}")
            mail.msg_add(
                f"\u2705 {new_list_name}: Whitelisting of IPs success. "
                f"Number of addresses removed: {len(del_list)}")

    @staticmethod
    def get_active_ip(big_ip_username: str, big_ip_password: str) -> str:
        """
        Get which device is currently the active device.
        :param str big_ip_username: F5 Username
        :param str big_ip_password: F5 Password
        :return: The active box's IP address
        :except requests.exceptions.ConnectTimeout: If the first box is unreachable.
        """
        try:
            device = BIGIP(device=Conf.SELF_IP1, session_verify=False, username=big_ip_username,
                           password=big_ip_password,
                           timeout=10)
            ha_status = device.load("/mgmt/tm/cm/failover-status?$select=status").properties
            status = \
                ha_status['entries']['https://localhost/mgmt/tm/cm/failover-status/0']['nestedStats']['entries'][
                    'status'][
                    'description']
            if status == "ACTIVE":
                return Conf.SELF_IP1
            else:
                return Conf.SELF_IP2
        except requests.exceptions.ConnectTimeout:
            print(f"{Conf.SELF_IP1} can't be connected. Trying {Conf.SELF_IP2}...")
            return Conf.SELF_IP2

    def main(self) -> None:
        """
        The main script.
        :except RunError: If there are any issues with the script's prerequisites.
        :except paramiko.ssh_exception.AuthenticationException: If the username and/or password is incorrect.
        :except socket.error: If the script is unable to reach the device.
        :except Exception: If the script is unable to reach the txt file.
        """
        mail = Email()
        print(f"\u24d8 Checking for credentials...")
        # Get BIG IP username & password
        big_ip_username = kr.get_password(f"BIG-IP.username", "username")
        big_ip_password = kr.get_password(f"BIG-IP.password", big_ip_username)
        if big_ip_username is None or big_ip_password is None:
            raise RunError(
                "\u274c Username or password for BIG IP is not found. Ensure you have updated the username or \n"
                "password and not delete them from the vault.", "Authentication Failed")
        active_ip = self.get_active_ip(big_ip_username, big_ip_password)
        # SSH to BIG IP
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        print(f"\u24d8 Starting SSH...")
        try:
            ssh.connect(hostname=active_ip, username=big_ip_username, password=big_ip_password)
        except KeyboardInterrupt:
            exit()
        except paramiko.ssh_exception.AuthenticationException as e:
            print(f"\u274c Failed.")
            raise RunError(
                message=f"\u274c Authentication with BIG-IP failed. Please ensure your username/password are correct."
                        f"Details: {e}", errors=str(e))
        except socket.error as e:
            print(f"\u274c Failed.")
            raise RunError(
                message="\u274c Error: SSH with BIG-IP failed. Please ensure you are able to connect with BIG-IP and "
                        "firewalls have been opened."
                        f"Details: {e}", errors=str(e))
        print(f"\u2705 SSH Success.")
        print(f"\u24d8 Logging in to BIG-IP through iControl...")
        device = BIGIP(device=active_ip, session_verify=False, username=big_ip_username, password=big_ip_password,
                       timeout=120)
        # Getting blacklisted address
        blacklist = [[] * 16 for _ in range(Conf.ARRAY_AMOUNT)]
        blacklist_v6 = [[] * 16 for _ in range(Conf.ARRAY_AMOUNT_V6)]
        # check if Z: is mounted and if not, mount it.
        # if not (os.path.exists(Conf.MOUNT_LETTER)):
        #     # nas_username = kr.get_password(f"{Conf.NAS_ADDRESS}.username", username="username")
        #     # nas_password = kr.get_password(f"{Conf.NAS_ADDRESS}.password", username=nas_username)
        #     nas_username = kr.get_password(f"BIG-IP.username", "username")
        #     nas_password = kr.get_password(f"BIG-IP.password", big_ip_username)
        #     if nas_username is None or nas_password is None:
        #         raise RunError(
        #             errors="Username and/or password not found.",
        #             message=f"No username and/or password is found in Credential Manager. Please run the script with"
        #                     f"the argument --Update-F5-Credentials to enter the credentials to Credentials Manager."
        #                     f"\nExample: python main.py --Update-F5-Credentials"
        #         )
        #     try:
        #         # subprocess.check_output(f"net use {Conf.MOUNT_LETTER} /delete", shell=True)
        #         subprocess.check_output(
        #             f"net use {Conf.MOUNT_LETTER} {Conf.NAS_ADDRESS} /user:{nas_username} {nas_password}", shell=True)
        #     except subprocess.CalledProcessError as e:
        #         print(f"Error while authenticating with NAS:\n{e.output}")
        #         raise RunError(
        #             errors=e.output,
        #             message=f"An error has occurred while trying to remount the{Conf.MOUNT_LETTER} with "
        #                     f"{Conf.NAS_ADDRESS}. Please remount the network drive and re-run this script manually.")
        #         # Get blacklist and whitelist file and split them to 2D array
        # Accessing the URL to get blacklisted IP addresses
        print(f"\u24d8 Accessing {Conf.BLACKLIST_URL}...")
        try:
            for line in http_req.urlopen(Conf.BLACKLIST_URL):
                ip_address: str = line.decode('utf-8').strip()
                split = re.split('[.:]', string=ip_address)
                # Check if this is an IPv6 address
                if ip_address.find(':') != -1:  # IPv6
                    array_location = (int(split[0], 16) % Conf.ARRAY_AMOUNT_V6)
                    blacklist_v6[array_location].append(ip_address)
                else:  # IPv4
                    array_location = (int(split[0]) % Conf.ARRAY_AMOUNT)
                    blacklist[array_location].append(ip_address)
        except Exception as e:
            raise RunError(f"\u274c Accessing to {Conf.BLACKLIST_URL} failed. "
                           f"Please ensure that the firewall is open and re-run this script.",
                           errors=str(e))

        self.blacklist(ssh=ssh, device=device, addr_list=blacklist, destination=4, mail=mail)
        self.blacklist(ssh=ssh, device=device, addr_list=blacklist_v6, destination=6, mail=mail)
        mail.msg_add(f"\u2705 Blacklisting has been completed.")

        # The BIG IP will only be synced if sync-group name is entered.
        if Conf.SYNC_GROUP_NAME:
            print(f"\u24d8 Syncing HA device...")
            ssh.exec_command(f"run /cm config-sync to-group {Conf.SYNC_GROUP_NAME}")
            mail.msg_add(f"\u2705 Syncing to standby device {Conf.SYNC_GROUP_NAME} has been completed.")
        # close SSH session
        print(f"\u2705 AFM Address List update has been completed.")
        mail.msg_add(f"\u2705 AFM Address List update has been completed.")
        mail.send_mail()
        ssh.close()


if __name__ == '__main__':
    Blacklist()
