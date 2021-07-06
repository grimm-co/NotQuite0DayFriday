# Overview

During an analysis of enterprise time synchronization software, GRIMM
found a vulnerability that allows remote attackers to execute arbitrary
commands with elevated privileges on all clients that are not filtering
traffic on the target port. The software in concern is Beagle Software’s
ClockWatch Enterprise, part of a product line built around synchronizing
machines’ clocks with high-accuracy time sources, with the Enterprise
solution focused on synchronizing time across a domain or other group of
Windows machines. Exploitation of this vulnerability is straightforward
because the client is designed to execute plaintext commands without
authentication from the server and without alerting the user.

In the ClockWatch Enterprise version, a single ClockWatch Enterprise
host can centrally control the time synchronization of all the clients
instead of depending on clients to connect to the server regularly and
synch their clocks. The ClockWatch Enterprise host is intended to run
both a ClockWatch time server as well as the ClockWatch Enterprise
program that allows the host to detect and interact with clients on the
network, as shown in Figure
<a href="#fig:enterprise" data-reference-type="ref" data-reference="fig:enterprise">1</a>.
The Enterprise Service Module (ESM) is the client software installed on
each machine and is the component vulnerable to remote command
injection.

<figure>
<img src="images/clockwatch_enterprise.png" id="fig:enterprise" style="width:90.0%" alt="ClockWatch Enterprise Architecture" /><figcaption aria-hidden="true">ClockWatch Enterprise Architecture</figcaption>
</figure>

The software in question is intended to run in the background with
elevated privileges (SYSTEM by default), and the risk is not just that
an attacker could disrupt the functioning of a critical software
service, but that a remote attacker could take over any machine with the
vulnerable software installed.

This report provides details and a Proof of Concept (PoC) attack for
this vulnerability, as well as a discussion of detection and mitigation
steps.

# Bug identification

## Beagle Software Enterprise Service Module Remote Command Injection

-   Vulnerability Type: Unauthenticated Remote Code Execution (RCE)

-   Location: `fmMainEntSrvc::do_command` function in EntSrvc.exe

-   Affected Versions: Enterprise Service Module v1.2.2 (latest, build:
    Dec 2005)

-   Impact: Arbitrary RCE as SYSTEM (in default configuration) or local
    user (in standalone mode)

-   CVE Number: TBD

The Beagle Software ESM is intended to run in the background on client
machines, listening on TCP port 1001 by default for connections from the
ClockWatch Enterprise host. The simple network protocol used by
ClockWatch Enterprise invokes a command on the remote host by sending
the string `C+` followed by the command to execute. No authentication or
encryption is used, so commands can be sent by arbitrary remote
attackers.

In the `do_command` function, the ESM passes the command string from the
network as an argument to the Visual Basic `Shell` function (the ESM is
compiled from Visual Basic), which interprets the string as a path to an
executable and any command line arguments. This is equivalent to the
Windows API function `WinExec` and similar to the C runtime library’s
`system` function, since it starts a new child process with the given
arguments.

# Technical analysis

The RCE vulnerability exists in the function `fmMainEntSrvc::do_command`
and can be triggered by a remote, unauthenticated attacker sending
properly formatted command instructions. By using a network traffic
capture tool such as WireShark, we can see the plaintext traffic between
the ClockWatch Enterprise host and ESM when a remote command is
executed. The text-based protocol allows for several different kinds of
interaction (such as time check or forced time set), but attackers will
most likely be interested in the remote command functionality. The only
barrier to exploitation is learning the port and format of the remote
command functionality.

<figure>
<img src="images/traffic_hexdump.png" id="fig:traffic" style="width:90.0%" alt="Sample remote command invocation traffic" /><figcaption aria-hidden="true">Sample remote command invocation traffic</figcaption>
</figure>

Remote commands will be executed in the context of the ESM process, so
if the ESM is running as a service, remote commands will execute as
SYSTEM and no resulting GUI or windows will be visible to a logged-on
user. Alternatively the ESM can be run (automatically or manually) by a
local user, in which case the command will execute as the local user and
any GUI windows resulting from the command run may be visible to the
user. On modern versions of Windows, changing time and date settings
require Administrative privileges by default, so given the context of
enterprise time synchronization, it is expected that deployments will be
running as a service.

## Exploit

The provided Python PoC demonstrates the remote command functionality,
but specialized scripts are not required. Since there is no encryption
or authentication used and the protocol is plaintext, the standard
netcat utility could be used to demonstrate this vulnerability. The
provided script has been tested and provides a standardized experience.

The PoC itself was tested and verified to work against version `1.2.2`
of the ClockWatch ESM. Due to the closed-source nature of ClockWatch, we
were unable to locate additional versions on which to test, but it is
suspected that all versions that support remote command functionality
are vulnerable.

## Testing

To test the provided PoC, the easiest setup is to create a 64-bit
Windows 10 Virtual Machine (VM) and download the evaluation version of
the ClockWatch Enterprise Service Module ([available
here](http://www.beaglesoft.com/clwaentprise.htm)).

To make commands run visibly in the foreground, we recommend running the
`EntSrvc.exe` executable manually, not installing as a service. During
the installation, when the installer asks whether to install as an
enterprise service, select “No". If the installer says it cannot find
“WinSock.dll" and asks to connect to the Internet to locate it, click
“Ok" to proceed. The operation does not need to succeed for the
installation to succeed. At the end of installation, leave the “Start
Beagle Software Enterprise Service Module when done" box checked. If the
Windows firewall requests access, allow for both Public and Private
networks.

Once installed, return to your host and run the `esm_poc.py` script. You
will need to enter the IP address of the target along with a command to
run. If the ESM program is running in the foreground and not as a
service, a command that opens a window such as “calc.exe” or
“notepad.exe” should suffice.

      python3 esm_poc.py XXX.XXX.XXX.XXX calc.exe

When you run this command, the script will output `[+] Success` if it
succeeds. Since the ESM’s network response only confirms that a command
was run and does not include any output, demonstrations of the exploit
working may require a visible effect such as opening a window or writing
to a file. The text in the ESM window will also change to indicate the
command that was just run, as well as the source and timestamp of the
command.

<figure>
<img src="images/esm_command_run.png" id="fig:command" style="width:60.0%" alt="ESM Command Display" /><figcaption aria-hidden="true">ESM Command Display</figcaption>
</figure>

# Timeline

-   05/19/2021 - Notified vendor

-   05/24/2021 - Notified CISA

-   06/02/2021 - Beagle Software agrees to update product page to
    indicate that ClockWatch Enterprise has been discontinued and remove
    it from their online store

-   06/02/2021 - Beagle Software confirms that they will not fix the
    vulnerability

-   07/06/2021 - NotQuite0DayFriday release

-   07/06/2021 - Blog post release
