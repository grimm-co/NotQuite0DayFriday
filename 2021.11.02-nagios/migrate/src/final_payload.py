import os
import pwd

print('[*] Payload demonstrating root access')

uid = os.getuid()
user_info = pwd.getpwuid(uid)
username = user_info.pw_name
gid = user_info.pw_gid

dst = '/tmp/proof_of_root'
with open(dst, 'w') as f:
    f.write('%s %s %s\n' % (username, uid, gid))

os.chmod(dst, int('4777', 8))
with open(dst, 'r') as f:
    data = f.read()

if data.startswith('root'):
    print('[+] Success: "%s"' % data.strip())
else:
    print('[-] Failure: "%s"' % data.strip())

