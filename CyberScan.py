#!/usr/bin/python
# -*- coding: utf-8 -*-
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor Boston,
#  MA 02110-1301, USA.
#
#  Author: Mohamed BEN ALI

import os
import sys
import platform
import argparse
import time
import socket

# Scapy imports
from scapy.all import rdpcap, srp, sr, Ether, ARP, IP, ICMP, TCP, UDP

# colorama and local libs
try:
    from libs.colorama import *
except Exception:
    # colorama might not be installed or the local libs package layout may differ
    # define minimal fallbacks to avoid crashes when colorama is not available
    class Style:
        BRIGHT = ""
        RESET_ALL = ""

    class Fore:
        RED = ""

    def write(x):
        sys.stdout.write(x + "\n")

# local FileUtils import
try:
    from libs import FileUtils
except Exception:
    FileUtils = None

# pygeoip is legacy; keep import but provide helpful message if unavailable
try:
    import pygeoip
except Exception:
    pygeoip = None

__version__ = "1.1.1"
__description__ = ("""
  ___________________________________________

  CyberScan | v.""" + __version__ + """
  Author: BEN ALI Mohamed
  ___________________________________________
""")


def header():
    MAYOR_VERSION = 1
    MINOR_VERSION = 1
    REVISION = 1
    VERSION = {
        "MAYOR_VERSION": MAYOR_VERSION,
        "MINOR_VERSION": MINOR_VERSION,
        "REVISION": REVISION,
    }

    if FileUtils is not None:
        banner_path = FileUtils.buildPath('banner.txt')
        try:
            with open(banner_path, 'r', encoding='utf-8', errors='ignore') as f:
                PROGRAM_BANNER = f.read().format(**VERSION)
        except Exception:
            PROGRAM_BANNER = __description__
    else:
        PROGRAM_BANNER = __description__

    message = Style.BRIGHT + Fore.RED + PROGRAM_BANNER + Style.RESET_ALL
    write(message)


def usage():
    print("""\033[92m CyberScan v.1.1.1 http://github/medbenali/CyberScan
\tIt is the end user's responsibility to obey all applicable laws.
\tIt is just for server testing script. Your ip is visible. \n
\t  ___________________________________________

\t  CyberScan | v.1.1.1   
\t  Author: BEN ALI Mohamed
\t  ___________________________________________

\n \033[0m""")


def write(string):
    if platform.system() == 'Windows':
        sys.stdout.write(string)
        sys.stdout.flush()
        sys.stdout.write('\n')
        sys.stdout.flush()
    else:
        sys.stdout.write(string + '\n')
        sys.stdout.flush()


def geo_ip(host):
    if pygeoip is None:
        print("[*] pygeoip module not installed. Install it or use an alternative geoip library (e.g., geoip2).")
        return

    try:
        rawdata = pygeoip.GeoIP('GeoLiteCity.dat')
        data = rawdata.record_by_name(host)
        if not data:
            print("[*] No geoip data found for: {}".format(host))
            return

        country = data.get('country_name')
        city = data.get('city')
        longi = data.get('longitude')
        lat = data.get('latitude')
        time_zone = data.get('time_zone')
        area_code = data.get('area_code')
        country_code = data.get('country_code')
        region_code = data.get('region_code')
        dma_code = data.get('dma_code')
        metro_code = data.get('metro_code')
        country_code3 = data.get('country_code3')
        zip_code = data.get('postal_code')
        continent = data.get('continent')

        print('[*] IP Address: {}'.format(host))
        print('[*] City: {}'.format(city))
        print('[*] Region Code: {}'.format(region_code))
        print('[*] Area Code: {}'.format(area_code))
        print('[*] Time Zone: {}'.format(time_zone))
        print('[*] Dma Code: {}'.format(dma_code))
        print('[*] Metro Code: {}'.format(metro_code))
        print('[*] Latitude: {}'.format(lat))
        print('[*] Longitude: {}'.format(longi))
        print('[*] Zip Code: {}'.format(zip_code))
        print('[*] Country Name: {}'.format(country))
        print('[*] Country Code: {}'.format(country_code))
        print('[*] Country Code3: {}'.format(country_code3))
        print('[*] Continent: {}'.format(continent))

    except Exception as e:
        print("[*] Please verify your ip ! Error: {}".format(e))


def arp_ping(host):
    print('[*] Starting CyberScan Ping ARP for {}'.format(host))
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host), timeout=2)

    # scapy returns list of (sent, received) tuples; use lambda that takes the tuple
    try:
        ans.summary(lambda sr: sr[1].sprintf("%Ether.src% %ARP.psrc%"))
    except Exception:
        # fallback to printing each response
        for s, r in ans:
            try:
                print(r.sprintf("%Ether.src% %ARP.psrc%"))
            except Exception:
                print(r.summary())


def icmp_ping(host):
    print('[*] Starting CyberScan Ping ICMP for {}'.format(host))
    ans, unans = sr(IP(dst=host) / ICMP())
    try:
        ans.summary(lambda sr: sr[1].sprintf("%IP.src% is alive"))
    except Exception:
        for s, r in ans:
            try:
                print(r.sprintf("%IP.src% is alive"))
            except Exception:
                print(r.summary())


def tcp_ping(host, dport):
    ans, unans = sr(IP(dst=host) / TCP(dport, flags="S"))
    try:
        ans.summary(lambda sr: sr[1].sprintf("%IP.src% is alive"))
    except Exception:
        for s, r in ans:
            try:
                print(r.sprintf("%IP.src% is alive"))
            except Exception:
                print(r.summary())


def udp_ping(host, port=0):
    print('[*] Starting CyberScan Ping UDP for {}'.format(host))
    ans, unans = sr(IP(dst=host) / UDP(dport=port))
    try:
        ans.summary(lambda sr: sr[1].sprintf("%IP.src% is alive"))
    except Exception:
        for s, r in ans:
            try:
                print(r.sprintf("%IP.src% is alive"))
            except Exception:
                print(r.summary())


def superscan(host, start_port, end_port):
    print('[*] CyberScan Port Scanner')
    open_ports = []
    common_ports = {
        '21': 'FTP',
        '22': 'SSH',
        '23': 'TELNET',
        '25': 'SMTP',
        '53': 'DNS',
        '69': 'TFTP',
        '80': 'HTTP',
        '109': 'POP2',
        '110': 'POP3',
        '123': 'NTP',
        '137': 'NETBIOS-NS',
        '138': 'NETBIOS-DGM',
        '139': 'NETBIOS-SSN',
        '143': 'IMAP',
        '156': 'SQL-SERVER',
        '389': 'LDAP',
        '443': 'HTTPS',
        '546': 'DHCP-CLIENT',
        '547': 'DHCP-SERVER',
        '993': 'IMAP-SSL',
        '995': 'POP3-SSL',
        '2082': 'CPANEL',
        '2083': 'CPANEL',
        '2086': 'WHM/CPANEL',
        '2087': 'WHM/CPANEL',
        '3306': 'MYSQL',
        '8443': 'PLESK',
        '10000': 'VIRTUALMIN/WEBIN',
    }

    starting_time = time.time()
    if flag:
        print("[*] Scanning For Most Common Ports On {}".format(host))
    else:
        print("[*] Scanning {} From Port {} To {}: ".format(host, start_port, end_port))
    print("[*] Starting CyberScan 1.01 at {}".format(time.strftime("%Y-%m-%d %H:%M %Z")))

    def check_port(host, port, result=1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            r = sock.connect_ex((host, port))
            if r == 0:
                result = r
            sock.close()
        except Exception as e:
            # ignore errors but keep them from crashing
            pass
        return result

    def get_service(port):
        port = str(port)
        return common_ports.get(port, 0)

    try:
        print("[*] Scan In Progress ...")
        print("[*] Connecting To Port : ", end='')

        if flag:
            for p in sorted(common_ports, key=lambda x: int(x)):
                sys.stdout.flush()
                p_int = int(p)
                print(p_int, end=' ')
                response = check_port(host, p_int)
                if response == 0:
                    open_ports.append(p_int)
                sys.stdout.write('\b' * len(str(p_int)))

        else:
            for p in range(start_port, end_port + 1):
                sys.stdout.flush()
                print(p, end=' ')
                response = check_port(host, p)
                if response == 0:
                    open_ports.append(p)
                if not p == end_port:
                    sys.stdout.write('\b' * len(str(p)))

        print("\n[*] Scanning Completed at {}".format(time.strftime("%Y-%m-%d %H:%M %Z")))
        ending_time = time.time()
        total_time = ending_time - starting_time
        if total_time <= 60:
            print("[*] CyberScan done: 1IP address (1host up) scanned in {:.2f} seconds".format(total_time))
        else:
            total_time = total_time / 60
            print("[*] CyberScan done: 1IP address (1host up) scanned in {:.2f} Minutes".format(total_time))

        if open_ports:
            print("[*] Open Ports: ")
            for i in sorted(open_ports):
                service = get_service(i)
                if not service:
                    service = "Unknown service"
                print("\t{} {}: Open".format(i, service))
        else:
            print("[*] Sorry, No
