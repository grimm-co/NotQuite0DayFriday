# Netgear upnpd UpdateNewFirmware Exploit

This folder contains an exploit for a stack overflow within the `upnpd` daemon
on the Netgear R7000 and other models with the same codebase. This stack
overflow can be combined with an authentication bypass vulnerability to allow an
unauthenticated attacker on the LAN side of the router to gain remote code
execution.

## Vulnerable Models

The following devices and versions have both the stack overflow and the
authentication bypass used within the exploit:

* R4500     - 1.0.0.4
* R6200     - 1.0.1.58
* R6200v2   - 1.0.3.12
* R6250     - 1.0.4.48
* R6300     - 1.0.2.80
* R6300v2   - 1.0.4.52
* R6400     - 1.0.1.72
* R6400v2   - 1.0.4.106
* R6700     - 1.0.2.16
* R6700v3   - 1.0.4.106
* R6900     - 1.0.2.16
* R6900P    - 1.3.2.134
* R7000     - 1.0.11.123
* R7000P    - 1.3.2.134
* R7100LG   - 1.0.0.64
* R7300DST  - 1.0.0.74
* R7850     - 1.0.5.68
* R7900     - 1.0.4.38
* R8000     - 1.0.4.68
* R8300     - 1.0.2.144
* R8500     - 1.0.2.136
* RS400     - 1.5.0.68
* D6220     - 1.0.0.72
* D6400     - 1.0.0.104
* D7000v2   - 1.0.0.66
* D8500     - 1.0.3.60
* DC112A    - 1.0.0.56
* DGN2200v4 - 1.0.0.116
* MBR1200   - 1.2.2.53
* MBR1515   - 1.2.2.68
* MBR1516   - 1.2.2.84BM
* MBRN3000  - 1.0.0.74

The following devices have the stack overflow but not the authentication bypass.
However, due to a separate bug, these devices allow unauthenticated access to
the vulnerable components for the first 5 minutes after they've booted.

* EX3700 - 1.0.0.88
* EX3800 - 1.0.0.88
* EX3920 - 1.0.0.88
* EX6000 - 1.0.0.44
* EX6100 - 1.0.2.28
* EX6120 - 1.0.0.54
* EX6130 - 1.0.0.40
* EX6150 - 1.0.0.46
* EX6920 - 1.0.0.54
* EX7000 - 1.0.1.94

Additionally, the following devices are vulnerable to the stack overflow, but
not the authentication bypass and do not allow unauthenticated requests at boot.

* EX6200  - 1.0.3.94
* DGN2200 - 1.0.0.60
* LG2200D - 1.0.0.57

## Stack Overflow

The `upnpd` server allows the client to upgrade the router's firmware. However,
the firmware update code is vulnerable to the same stack overflow that the
`httpd` server was previously vulnerable to. More information on the previous
`httpd` vulnerability can be found on
[GRIMM's blog](https://blog.grimm-co.com/2020/06/soho-device-exploitation.html).

The same vulnerable function, `abCheckBoardID`, is also present in the `upnpd`
server. After GRIMM reported the previous vulnerability, Netgear patched the
`httpd` server to include a length check in `abCheckBoardID` which prevents the
overflow. However, the `upnpd` was not patched. Thus, this server is vulnerable
to the stack overflow.

The `abCheckBoardID` function, shown below, expects the user input to be the chk
firmware file for the R7000. It parses the user input to validate the magic
value (bytes 0-3), obtains the header size (bytes 4-7) and checksum
(bytes 36-49), and then copies the header to a stack buffer. This copy,
performed via the memcpy function, uses the size specified in the user input.
As such, it’s trivial to overflow the stack buffer.

![](images/abCheckBoardID.png)

These days, we'd expect this vulnerability to be unexploitable because stack
cookies would cause the program to bail before returning to the overwritten
return address... but the vulnerable device firmwares do not use stack cookies.

## Authentication Bypass

Unlike the previous `httpd` vulnerability, the `upnpd` firmware upgrade commands
are only to an authenticated user. However, the authentication can be bypassed
via a variation of [Pedro Ribeiro and Radek Domanski's authentication bypass
from PWN2OWN 2019](https://github.com/pedrib/PoC/blob/master/advisories/Pwn2Own/Tokyo_2019/tokyo_drift/tokyo_drift.md).

The initial authentications checks within the `upnpd` daemon are performed via
the below pseudocode:

```
//Find the SOAPAction header
soap_action_begin = stristr(request_input, "SOAPAction:");
soap_action_end = strchr(soap_action_begin+strlen("SOAPAction"), '\r');
strncpy(soap_action_line, soap_action_begin, MIN(soap_action_begin-soap_action_end, 127));

//Look for each of the available SOAP actions within the SOAP header, break when one is found 
actions = ["DeviceInfo", "DeviceConfig", "WANIPConnection", "WANEthernetLinkConfig",
  "LANConfigSecurity", "WLANConfiguration", "Time", "ParentalControl", "AppSystem",
  "AdvancedQoS", "UserOptionsTC"]
for action in actions:
  if(stristr(soap_action_line, action) != 0)
    action_to_handle = action
    break
...
 //if we're not doing the ParentalControl Authenticate action, require the caller to authenticate
 if(strncmp(input, " urn:NETGEAR-ROUTER:service:ParentalControl:1#Authenticate", 58) {
  require_auth()
 }
...
process_action(action_to_handle)
```

In order to reach the desired functionality, we must specify the SOAP action
`DeviceConfig` and the command `UpdateNewFirmware`. Ordinarily this request
would fail to match the `ParentalControl:1#Authenticate` string and be required
to authenticate before the `UpdateNewFirmware` command is processed. However,
due to a discrepancy in the way the SOAP actions are parsed when determining if
authentication is required and when determining which command to handle, we can
bypass the authentication checks.

The `upnpd` daemon determines if authentication is necessary by looking for the
string `urn:NETGEAR-ROUTER:service:ParentalControl:1#Authenticate` immediately
after the `SOAPAction` header name. This check is performed via `strncmp`, and
if this string is found, authentication is skipped. This is in contrast to how
the `upnpd` daemon determines which SOAP action to process. This search is
performed by iterating over all possible SOAP actions and determining if the
`SOAPAction` header contains the action name, via the `stristr` function. As
such, if we include an additional SOAP action name after the `ParentalControl`
action, we can parse a different action name than the one used for the
authentication check. As long as the second action name is before the
`ParentalControl` action in the actions list, it will be found before the loop
searches for `ParentalControl`, and we'll be able to access it without
authentication. An example request which uses this technique to bypass
authentication is shown below:
```
POST /soap/server_sa HTTP/1.1\r\n
Host: http://192.168.2.1:5000\r\n
SOAPAction: urn:NETGEAR-ROUTER:service:ParentalControl:1#Authenticate
SOAPAction: urn:NETGEAR-ROUTER:service:DeviceConfig\r\n
Content-Length: 295\r\n
\r\n
<?xml version="1.0"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <SOAP-ENV:Body>
  <UpdateNewFirmware/>
  <NewFirmware>Base64 Encoded Buffer</NewFirmware>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

## Authentication Bypass (Wifi Extender Series)

The EX wifi extender models do not contain the bypass used by other devices.
However, these devices have a separate bug that enables unauthenticated access
to the `upnpd` server for the first 5 minutes that they're online.

These devices record the uptime, i.e. seconds since boot, that the upnpd was
last authenticated to via the `DeviceConfig:Authenticate` command in the global
`g_lastAccess`. This global is also updated any time a request is processed.
When `upnpd` receives a request for a command other than
`DeviceConfig:Authenticate`, it will check the `g_lastAccess` time to see if it
is within 5 minutes of the current uptime. However, the `g_lastAccess` global is
not initialized at startup. As the uptime of a system at boot is 0, and globals
in the `bss` section are initially set to 0, any requests within the first 5
minutes of boot will be allowed. Additionally, if an attacker were to
continually ping the `upnpd` server with commands, they could maintain access
indefinitely.

The following pseudocode is used to validate requests within the Wifi Extender
Devices' upnpd servers:
```
int g_lastAccess = 0
...
int handle_request() {
  if(command == "DeviceConfig:Authenticate") {
    if(do_login()) {
      g_lastAccess = uptime();
      return http_ok();
    } else {
      return http_error401();
    }
  }
...
  if(uptime() - g_lastAccess < 600) {
    g_lastAccess = uptime();
    return process_request()
  } else {
    return http_error401();
  }
...
}
```

