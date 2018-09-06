"""
# Author: Dean Clark
# Date Created: 25/08/2018
# Date Modified: 06/09/2018
# Version: 0.4
# Purpose: To search through a list of devices and look for the Cisco AP corrupt flash bug, this script will also run known fixes
Known fixes can reload APs. These will be reloaded one at a time
# - Compatible with Python 3.6
Notes:
0.1 - Requires update to output from executeCommands Method (To output string of Terminal Output)
0.2 - Update executeCommands for IOSXE specific and IOS specific
    - Code Commented
0.3 - Method to process information from executeCommands for desired validation
0.4 - Added test capwap image - to fix corrupt AireOS images
"""

# ++++++++++++++++++++++ Initialising Libraries ++++++++++++++++++++++
from SSH_Paramiko import SSH_Paramiko
from creds import LocalUser
import multiprocessing
import os
import time
import smtplib

"""
Method is used in conjunction with multiprocessing to filter output from the pool into variable types
Uses md5 hash to verify Cisco AP image
"""
def run_SSHsession(user, passwd, device_ip, device_name, output_dir, exec_time, hold_time):
    image_file_name = "ap3g2-k9w8-mx.ap_smr3_esc.201712191345"
    image_hash = "d55c0adb2d331c2fcaa5ec466c2c5cbb"

    print("Child Process id: ", os.getpid())

    ssh_session = SSH_Paramiko()

    ap_chk_log_cmds = ["enable",
                       passwd,
                       "verify /md5 flash:" + image_file_name + "/" + image_file_name + " " + image_hash,
                       "\n",
                       "\n",
                       "\n",
                       "\n",
                       "\n"]

    ssh_out = ssh_session.executeChannelCommands(user, passwd, device_ip, device_name, ap_chk_log_cmds, timeout=120,
                                                 hold_time=hold_time)
    ssh_out = ssh_session.cleanSSHOutput(ssh_out)

    # Looking for Corrupt flash based on AireOS 8.3.133.10
    # 684351209 : AP will not allocate clients into correct VLAN; "no bridge-group 1 unicast-flooding"
    if "Verified" in ssh_out:
        ap_detail = "valid_image" + "," + device_name + "," + device_ip
    elif "Computed signature" in ssh_out:
        ap_detail = "corrupt_image" + "," + device_name + "," + device_ip
    else:
        ap_detail = "corrupt_flash" + "," + device_name + "," + device_ip

    if ("session_terminated" not in ssh_out) and ("ping_failed" not in ssh_out):
        ssh_session.printTextFile(device_name, ssh_out, output_dir, exec_time)
    else:
        if ("session_terminated" in ssh_out):
            fname_failed = device_name + "_session_terminated"
            ssh_session.printTextFile(fname_failed, ssh_out, output_dir, exec_time)
            ap_detail = "session_terminated" + "," + device_name + "," + device_ip
        else:
            fname_failed = device_name + "_ping_failed"
            ssh_session.printTextFile(fname_failed, ssh_out, output_dir, exec_time)
            ap_detail = "ping_failed" + "," + device_name + "," + device_ip

    result = ap_detail

    print("Completed on Device " + device_name)

    return result

# ++++++++++++++++++++++ Main Method ++++++++++++++++++++++
if __name__ == "__main__":
    devices = []
    ap_corrupt_flash = []
    ap_corrupt_image = []
    ap_reloaded = []
    ap_fsck_fixed = []
    ap_offline = []
    ap_ssh_terminated = []
    ap_fix_image_pass = []
    ap_fix_image_fail = []
    parameters = []

    device_keyword = ""
    fix_faults = "null"
    hold_time = 5
    device_count = 0
    sender_email = ""
    receiver_email = ""
    smtp_host = ''

    local_user = LocalUser()
    ssh_session = SSH_Paramiko()
    smtp_server = smtplib.SMTP(smtp_host, 25)

    devices = ssh_session.getCSV('<Device_List>.csv')

    user = local_user.user
    passwd = local_user.passwd

    exec_time = time.strftime("%y%m%d%H%M%S")
    output_dir = "_ap_corrupt_flash_"

    # Fix commands
    ap_diagnose_cmds = ["enable",
                        passwd,
                        "debug capwap console cli",
                        "\n",
                        "fsck flash:",
                        "\n",
                        "\n",
                        "\n",
                        "\n",
                        "\n",
                        "\n",
                        "no debug all",
                        "\n",
                        "no debug all",
                        "\n",
                        "\n",
                        "\n"]

    ap_reload_cmds = ["enable",
                      passwd,
                      "debug capwap console cli",
                      "\n",
                      "\n",
                      "reload",
                      "yes",
                      "\n",
                      "\n",
                      "no debug all",
                      "\n",
                      "no debug all",
                      "\n",
                      "\n",
                      "\n"]

    ap_cp_image_cmds = ["enable",
                        passwd,
                        "debug capwap console cli",
                        "\n",
                        "test capwap image capwap",
                        "\n",
                        "\n",
                        "\n",
                        "\n",
                        "no debug all",
                        "\n",
                        "no debug all",
                        "\n",
                        "\n",
                        "\n",
                        "\n"]

    ap_sh_log_img_verify_cmds = ["enable",
                                 passwd,
                                 "show log | include \"AP image\"\n",
                                 "\n",
                                 "\n",
                                 "\n"]

    # build the parameters list with values to run on the workers in the pool
    for k in range(0, len(devices)):
        if device_keyword in str(devices[k][0]):
            device_name = str(devices[k][0])
            device_ip = str(devices[k][1])

            parameters.append((user, passwd, device_ip, device_name, output_dir, exec_time, hold_time))
            device_count = device_count + 1

    # validate with user the number of devices this will execute on
    print("Running on " + str(device_count) + " devices")

    time.sleep(20)

    # Start the processing
    # Set how many simultaneous processes
    pool = multiprocessing.Pool(processes=50)

    # Run the processes - in the pool using the multiprocessing handler
    results = pool.starmap(run_SSHsession, parameters)

    print("Pools Completed")

    # Close the Worker Pool
    pool.close()
    pool.join()

    for ap_result in results:
        ap_list = ap_result.split(",")
        if "ping_failed" == ap_list[0]:
            ap_offline.append(ap_list)
        if "corrupt_image" in ap_list[0]:
            ap_corrupt_image.append(ap_list)
        if "corrupt_flash" in ap_list[0]:
            ap_corrupt_flash.append(ap_list)
        if "session_terminated" in ap_list[0]:
            ap_ssh_terminated.append(ap_list)

    # List to user findings and results
    print("\n-----")
    print("APs with corrupt AireOS image:")
    log_image_corrupt = ("Executed: " + exec_time + "\nAPs with corrupt images")
    for ap in ap_corrupt_image:
        print(ap)
        log_image_corrupt = log_image_corrupt + "\n" + str(ap)
    print("Total APs ", len(ap_corrupt_image))
    log_image_corrupt = log_image_corrupt + "\n" + "Total APs " + str(len(ap_corrupt_image))

    print("APs with Flash Issues")
    log_flash_corrupt = "APs with Flash Issues"
    for ap in ap_corrupt_flash:
        print(ap)
        log_flash_corrupt = log_flash_corrupt + "\n" + str(ap)
    print("Total APs ", len(ap_corrupt_flash))
    log_flash_corrupt = log_flash_corrupt + "\n" + "Total APs " + str(len(ap_corrupt_flash))

    print("APs that are unreachable")
    log_ap_offline = ("APs that are unreachable")
    for ap in ap_offline:
        print(ap)
        log_ap_offline = log_ap_offline + "\n" + str(ap)
    print("Total APs ", len(ap_offline))
    log_ap_offline = log_ap_offline + "\n" + "Total APs " + str(len(ap_offline))

    print("APs SSH Terminated")
    log_ap_ssh_terminated = ("APs SSH Terminated")
    for ap in ap_ssh_terminated:
        print(ap)
        log_ap_ssh_terminated = log_ap_ssh_terminated + "\n" + str(ap)
    print("Total APs ", len(ap_ssh_terminated))
    log_ap_ssh_terminated = log_ap_ssh_terminated + "\n" + "Total APs " + str(len(ap_ssh_terminated))

    log_all = log_image_corrupt + "\n" + log_flash_corrupt + "\n" + log_ap_offline + "\n" + log_ap_ssh_terminated
    ssh_session.printTextFile("ap_chk_cisco_bugs_log", log_all, output_dir, exec_time, write_method="append")

    # send a completion email to prompt next actions
    try:
        msg = "\nFinished polling devices"
        smtp_server.sendmail(sender_email, receiver_email, msg)
        smtp_server.quit()
    except:
        print("Email Failed")

    # prompt user to run known fixes
    while "yes" != fix_faults:
        print("Do you want to run known fixes on APs: \"yes\" to proceed or \"no\" to quit")
        fix_faults = input("#")

        if "no" == fix_faults:
            break

    if "yes" == fix_faults:
        for ap in ap_corrupt_flash:
            print("Checking AP; ", str(ap))
            device_ip = str(ap[2])
            device_name = str(ap[1])

            # Check the flash filesystem
            ssh_out = ssh_session.executeChannelCommands(user, passwd, device_ip, device_name, ap_diagnose_cmds,
                                                         timeout=120, hold_time=10)
            ssh_out = ssh_session.cleanSSHOutput(ssh_out)

            if "Error fscking" in ssh_out:
                print("Reloading; ", str(ap))
                ssh_out = ssh_session.executeChannelCommands(user, passwd, device_ip, device_name, ap_reload_cmds,
                                                             timeout=30)
                ap_reloaded.append(ap)
                time.sleep(200)
            else:
                ap_fsck_fixed.append(ap)

        print("APs that have been reloaded")
        log_fix_ap = "APs that have been reloaded\n"
        for ap in ap_reloaded:
            print(ap)
            log_fix_ap = log_fix_ap + "\n" + str(ap)
        print("Total reloaded: ", len(ap_reloaded))
        log_fix_ap = log_fix_ap + "\n" + "Total reloaded: " + str(len(ap_reloaded))

        print("APs that have been fixed by fsck")
        log_fsck_ap = "\nAPs that have been fixed by fsck\n"
        for ap in ap_fsck_fixed:
            print(ap)
            log_fsck_ap = log_fsck_ap + "\n" + str(ap)
        print("Total fixed using fsck: ", len(ap_fsck_fixed))
        log_fsck_ap = log_fsck_ap + "\n" + "Total fixed using fsck: " + str(len(ap_fsck_fixed))

        log_all = "\n" + log_fix_ap + "\n" + log_fsck_ap
        ssh_session.printTextFile("ap_chk_cisco_bugs_log", log_all, output_dir, exec_time, write_method="append")

        log_ap_online = "\nReloaded APs Online"
        log_ap_offline = "Reloaded APs Offline"
        for ap in ap_reloaded:
            device_ip = str(ap[2])
            device_name = str(ap[1])

            if ssh_session.checkHostUp(device_ip):
                print("Reloaded AP Online: ", str(ap))
                log_ap_online = log_ap_online + "\n" + str(ap)
            else:
                print("Reloaded AP is buggered: ", str(ap))
                log_ap_offline = log_ap_offline + "\n" + str(ap)

        log_all = "\n" + log_ap_offline + "\n" + log_ap_online
        ssh_session.printTextFile("ap_chk_cisco_bugs_log", log_all, output_dir, exec_time, write_method="append")

        print("Fix APs that have corrupt images")
        for ap in ap_corrupt_image:
            print("Running on AP; ", ap)
            device_ip = str(ap[2])
            device_name = str(ap[1])

            ssh_out = ssh_session.executeChannelCommands(user, passwd, device_ip, device_name, ap_cp_image_cmds,
                                                         timeout=120)
        print("Waiting a while for downloads to complete ", time.strftime("%y/%m/%d/%H:%M:%S"))
        time.sleep(2400)

        print("Verifying image downloads")
        for ap in ap_corrupt_image:
            ssh_out = ssh_session.executeChannelCommands(user, passwd, device_ip, device_name,
                                                         ap_sh_log_img_verify_cmds,
                                                         timeout=120)

            if "PASSED" in ssh_out:
                ap_fix_image_pass.append(ap)
            else:
                ap_fix_image_fail.append(ap)

        print("APs that succeeded to download a replacement images")
        log_fix_corrupt_img_pass = "\nAPs that succeeded to download a replacement images"
        for ap in ap_fix_image_pass:
            print(ap)
            log_fix_corrupt_img_pass = log_fix_corrupt_img_pass + "\n" + ap

        print("Total APs with fixed images: ", len(ap_fix_image_pass))
        log_fix_corrupt_img_pass = log_fix_corrupt_img_pass + "\n" + "Total APs with fixed images: " + str(
            len(ap_fix_image_pass))

        print("APs that failed to download a replacement image")
        log_fix_corrupt_img_fail = "\nAPs that failed to download a replacement image"
        for ap in ap_fix_image_fail:
            print(ap)
            log_fix_corrupt_img_fail = log_fix_corrupt_img_fail + "\n" + ap
        print("Total APs with corrupt images: ", len(ap_fix_image_fail))
        log_fix_corrupt_img_fail = log_fix_corrupt_img_fail + "\n" + "Total APs with corrupt images: " + str(
            len(ap_fix_image_fail))

        log_all = "\n" + log_fix_corrupt_img_pass + "\n" + log_fix_corrupt_img_fail
        ssh_session.printTextFile("ap_chk_cisco_bugs_log", log_all, output_dir, exec_time, write_method="append")
    else:
        print("You have elected not to fix these, its ok the results are logged")

    print("Completed Execution")
