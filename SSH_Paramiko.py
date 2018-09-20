"""
# Title: SSH Paramiko Class
# Author: Dean Clark
# Date Created: 23/07/2016
# Date Modified: 06/09/2018
# Version: 0.61
# Purpose: This is intended as a SSH library to be used with Cisco switches and routers
# Notes:
0.1 - Requires update to output from executeCommands Method (To output string of Terminal Output)
0.2 - Update executeCommands for IOSXE specific and IOS specific
    - Code Commented
0.3 - Method to process information from executeCommands for desired validation
    - Added support for silent ssh command execution
    - Uses the creds file
0.4 - Add new method to cleanup ssh output
0.5 - Created Paramiko SSH class
0.6 - Updated cleanSSH method to remove \r
    - Added hold_timer to executeChannelCommands method
    - Fixed holding bug in execute methods
0.61- Added checkHostUp method - Use to perform a ping check before connecting to host
"""

# ++++++++++++++++++++++ Initialising Libraries ++++++++++++++++++++++
import csv
import paramiko
import time
import os
import subprocess
import sys

class SSH_Paramiko(object):
    def __init__(self):
        return None

    """
    Use this method to verify that the host is online before initiating an SSH session
    Reason - Waiting for SSH timeout adds by default 60 seconds of processing time for each offline host
    """
    def checkHostUp(self, host):
        try:
            if sys.platform == "win32":
                response = subprocess.check_output(["ping", "-n", "1", host], stderr=subprocess.STDOUT,
                                                   universal_newlines=True)
            else:
                response = subprocess.check_output(["ping", "-c", "1", host], stderr=subprocess.STDOUT,
                                                   universal_newlines=True)
            host_up = True
        except subprocess.CalledProcessError:
            host_up = False

        return host_up

    """
    Clean SSH Out and return the ssh output
    Function will remove the formatting that's returned from an SSH session
    """
    def cleanSSHOutput(self, ssh_out):
        ssh_out = ssh_out.replace('\\r\\n', '\n')
        ssh_out = ssh_out.replace("\'b\'", "")
        ssh_out = ssh_out.replace("\\x08", "")
        ssh_out = ssh_out.replace("b\'", "")
        ssh_out = ssh_out.replace("\\r", "")
        ssh_out = ssh_out.replace("         ", "")

        return ssh_out

    """
    Execute commands on remote device via SSH
    Returns - string(ssh_term) >> "session_terminated", "ping_failed" if error in session
    """
    def executeChannelCommands(self, user, passwd, device_ip, device_name, cmds, hold_time=0.1, silent_cmds=True, timeout=60):
        ssh_out = ""

        # Check if host is reachable before attempting to connect
        if self.checkHostUp(device_ip):
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(device_ip, username=user, password=passwd, look_for_keys=False, allow_agent=False, timeout=timeout)

                ssh_wait = True

                ssh_channel = ssh.invoke_shell()
                stuck_ssh_counter = 0

                # wait for terminal to be in ready state
                while ssh_wait:
                    time.sleep(0.1)
                    if ssh_channel.recv_ready():
                        ssh_wait = False

                    # Prevent the ssh_wait from getting stuck - Holds for 60 seconds
                    if stuck_ssh_counter > 600:
                        ssh_wait = False

                    stuck_ssh_counter += 1
                    time.sleep(0.1)

                for cmd_line in range(0, len(cmds)):
                    ssh_wait = True
                    cmd = str(cmds[cmd_line]) + "\n"
                    stuck_ssh_counter = 0

                    # Silent Command Run
                    if silent_cmds != True:
                        print("### Executing Command ###")
                        print(cmd)

                    ssh_channel.send(cmd)

                    # Hold untill the ssh session is ready
                    while ssh_wait:
                        if ssh_channel.recv_ready():
                            ssh_wait = False
                            time.sleep(hold_time)

                            ssh_temp = str(ssh_channel.recv(20480))
                            ssh_out = ssh_out + ssh_temp
                        # Loading bar for user
                        if silent_cmds != True:
                            print(".", end="")

                        # Prevent the ssh_wait from getting stuck - Holds for 60 seconds
                        if stuck_ssh_counter > 600:
                            ssh_wait = False

                        stuck_ssh_counter += 1
                        time.sleep(0.1)

                    if silent_cmds != True:
                        print("\n")

                ssh.close()
            except:
                ssh_out = "session_terminated," + device_name
                ssh.close()
        else:
            ssh_out = "ping_failed," + device_name

        return ssh_out

    """
    Method is used to hold for a given amount of time to allow the SSH buffer to collect outputs
    Returns - string(ssh_term) >> "session_terminated", "ping_failed" if error in session
    """
    def executeCollectDebugSSH(self, user, passwd, device_ip, device_name, cmds, timer=60, silent_cmds=True, timeout=1800):
        # Declare returned variable
        ssh_out = ""

        # Check if host is reachable before attempting to connect
        if self.checkHostUp(device_ip):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(device_ip, username=user, password=passwd, look_for_keys=False, timeout=timeout)

                # client.invoke_shell()
                ssh_channel = client.invoke_shell()
                stuck_ssh_counter = 0
                ssh_wait = True

                # wait for terminal to be in ready state
                while ssh_wait:
                    time.sleep(0.1)
                    if ssh_channel.recv_ready():
                        ssh_wait = False

                    # Prevent the ssh_wait from getting stuck - Holds for 60 seconds
                    if stuck_ssh_counter > 600:
                        ssh_wait = False

                    stuck_ssh_counter += 1
                    time.sleep(0.1)

                # Execute the required debug commands
                for cmd_line in range(0, len(cmds)):
                    ssh_wait = True
                    stuck_ssh_counter = 0

                    cmd = str(cmds[cmd_line]) + "\n"

                    # Silent Command Run
                    if silent_cmds != True:
                        print("### Executing Command ###")
                        print(cmd)

                    ssh_channel.send(cmd)

                    # Hold until the ssh session is ready
                    while ssh_wait:
                        if ssh_channel.recv_ready():
                            ssh_wait = False
                            time.sleep(0.1)
                        # Loading bar for user
                        if silent_cmds != True:
                            print(".", end="")

                        stuck_ssh_counter += 1
                        # Prevent the ssh_wait from getting stuck - Holds for 60 seconds
                        if stuck_ssh_counter > 600:
                            ssh_wait = False

                # Hold for given amount of time
                i = 0
                while(i < timer):
                    i += 1
                    time.sleep(1)

                """
                Commands are sent after the runtime has expired to remove any debugs post collecting the required debugs
                """
                ssh_channel.send("no debug all\n")
                ssh_channel.send("\n")
                ssh_channel.send("no debug all\n")
                ssh_channel.send("\n")

                time.sleep(1)

                ssh_out = ssh_channel.recv(40960)
            except:
                ssh_out = "session_terminated," + device_name
        else:
            ssh_out = "ping_failed," + device_name

        return ssh_out

    # Import CSV and output as an 3D Array
    # Returns - in_csv[]
    def getCSV(self, csv_nme):
        in_csv = []
        reader = csv.reader(open(csv_nme, 'r'), delimiter=',')

        # Read CSV content into 3D Array
        for row in reader:
            in_csv.append(row)

        return in_csv

    # Send string to text file and create an output dir
    def printTextFile(self, f_nme, input, name, exec_time="", write_method="write"):
        cwd = os.getcwd()

        folder = str(exec_time + name + "log")

        # Determine if dir /output exists and change to this directory
        if not os.path.isdir(folder):
            os.system("mkdir " + folder)

        os.chdir(os.path.join(str(cwd), folder))

        f_nme = f_nme + ".txt"

        if "write" == write_method:
            f_write = "w"
        else:
            f_write = "a"

        results = open(f_nme, f_write)
        results.write(input)

        # Set CWD to Program Home Directory
        os.chdir(str(cwd))
