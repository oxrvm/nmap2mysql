# -*- coding: utf-8 -*-
"""
==============================================================================
Title        : nmap.py
Description  : This script contains Nmap functions for nmap2mysql
Author       : Grégory Marendaz
Date         : 25.09.2024
Version      : 1.0
Usage        : N/A

==============================================================================
Changelog:
    - 25.05.2024 : Creation

==============================================================================
"""

import subprocess

def nmap_network_scan(cwd):
    nmap_command = f"nmap -iL {cwd}/nmap/subnet.txt -p- -sV --script=http-title,ssl-cert -oX {cwd}/nmap/results.xml"
    subprocess.run(nmap_command, shell=True, executable="/bin/bash")

def delete_results(cwd):
    del_command = f"rm -f {cwd}/nmap/*results*"
    subprocess.run(del_command, shell=True, executable="/bin/bash")