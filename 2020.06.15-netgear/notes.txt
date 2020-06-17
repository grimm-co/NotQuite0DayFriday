Pre-Authentication Remote Code Execution in Netgear SOHO devices

Overview:
A pre-authentication stack overflow vulnerability is present in many Netgear
SOHO devices that can allow a network-based attacker to execute code on the
device.

Exercising:
$ python exploit.py 192.168.1.1
The exploit will automatically determine the SOHO device model/version and then
exploit it to start telnet on TCP Port 8888. Additional arguments can be used to
specify a separate payload command to run or serve the exploit via CSRF.

Details:
This vulnerability is a pre-authentication memcpy-based stack overflow in httpd,
originally found in the Netgear R7000. The router runs httpd as the main
web server that is accessible via the LAN, or if configured, via the WAN. The
vulnerability been present in the R7000 since it was released in 2013 (and
earlier for other devices).

Before parsing generic HTTP requests, httpd checks to see if the provided HTTP
request is part of the update process. If so, a separate request parser is
used, as compared to the generic request parser. If this parser decides that
the request is sending a firmware blob to update, the function abCheckBoardID
(at offset 0x1BA78 in the httpd from the R7000 V1.0.9.12_1.2.23 firmware image)
will be called to validate the POST'd image before upgrading. If the image
begins with the string "*#$^", the image will be parsed and a header will be
copied to a stack variable. The length of the header will be taken from bytes
5-8 of the image and is not checked before the vulnerable memcpy (at offset
0x1BB18). Thus, by setting a size larger than the stack buffer, an attacker can
overflow it and corrupt the saved registers. Further, because the overflow is
memcpy based, the exploit is not limited by any encoding restrictions.

The exploit makes use of the non-PIE httpd binary to jump to ROP gadget(s) which
call system with a stack buffer argument. Thus, by including our command after
the overflown buffer in the POST'd image, the exploit achieves command
execution.

Also, of note is that the entire update process can be triggered without
authentication. Thus, our overflow in the update process is also able to be
triggered without authentication. If the stack-overflow is patched, a separate
exploit could take advantage of the unauthenticated update process to send a
properly encoded update image, that includes a backdoor. The receiving device
will unpack it and update accordingly. However, this exploit would require more
work and leave evidence of the exploit after reboot.

The exploit has been tested to work against the following devices and versions:
* D6300 version 1.0.0.90 and 1.0.0.102
* DGN2200 version 1.0.0.58
* DGN2200M version 1.0.0.35 and 1.0.0.37
* DGN2200v4 version 1.0.0.102
* R6250 versions 1.0.4.36 and 1.0.1.84
* R6300v2 version 1.0.3.6CH, 1.0.3.8, and 1.0.4.32
* R6400 version 1.0.1.20, 1.0.1.36, and 1.0.1.44
* R7000 versions 9.88, 9.64, 9.60, 9.42, 9.34, 9.18, 9.14, 9.12, 9.10, 9.6, and 8.34
* R8000 version 1.0.4.18, 1.0.4.46
* R8300 version 1.0.2.128 and 1.0.2.130
* R8500 version 1.0.0.28
* WGR614v9 version 1.2.32NA
* WGR614v10 version 1.0.2.66NA
* WGT624v4 version 2.0.12NA and 2.0.13.2
* WN3000RP versions 1.0.2.64 and 1.0.1.18
* WNDR3300 versions 1.0.45, 1.0.45NA, and 1.0.14NA
* WNDR3400 versions 1.0.0.52 and 1.0.0.38
* WNDR3400v2 versions 1.0.0.54 and 1.0.0.16
* WNDR3400v3 versions 1.0.1.24 and 1.0.0.38
* WNDR3700v3 versions 1.0.0.42, 1.0.0.38, and 1.0.0.18
* WNDR4000 versions 1.0.2.10, 1.0.2.4, and 1.0.0.82
* WNDR4500v2 versions 1.0.0.60 and 1.0.0.72
* WNR1000v3 version 1.0.2.72
* WNR2000v2 versions 1.2.0.8, 1.2.0.4NA, and 1.0.0.40
* WNR3500 version 1.0.36NA
* WNR3500L versions 1.2.2.48NA, 1.2.2.44NA, and 1.0.2.50
* WNR3500Lv2 version 1.2.0.56
* WNR834Bv2 version 2.1.13NA

Additional firmware versions of these devices and other devices have been
included in the exploit, but have not been explicitly tested, see the exploit.py
header for more specific versioning information. Each version requires a
separate ROP gadget address, and thus the -version and -model flags have been
added to the exploit to specify which version of the router that the exploit is
attacking. If not specified, the exploit will attempt to automatically
determine the router's version.

Timeline:
2020.05.07 - Reported to vendor
2020.06.15 - Public disclosure
