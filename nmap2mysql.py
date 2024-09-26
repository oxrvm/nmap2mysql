# -*- coding: utf-8 -*-
"""
==============================================================================
Title        : nmap2mysql
Description  : This script is designed to parse Nmap XML output files and
               insert the parsed data into a MySQL database
Author       : Grégory Marendaz
Date         : 13.08.2024
Version      : 2.0
Usage        : python3 nmap2mysql.py

==============================================================================
Changelog:
    - 13.08.2024 : Creation
    - 25.05.2024 : Code Refactoring

==============================================================================
"""

import os

from dotenv import load_dotenv

from _lib import mysql, nmap, xml

load_dotenv()

def main():
    cwd = os.getcwd()
    mysql.truncate_nmap_tables()
    nmap.nmap_network_scan(cwd)
    nmap_hosts, nmap_scan = xml.parse_nmap_xml(f"{cwd}/nmap/results.xml")
    mysql.insert_nmap_data(nmap_hosts, nmap_scan)
    nmap.delete_results(cwd)

if __name__ == '__main__':
    main()