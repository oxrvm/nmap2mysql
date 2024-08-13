# -*- coding: utf-8 -*-
"""
@author :
    Grégory Marendaz

@description :
    Port Scan Analyzer v1.0
    Main Application
"""

from datetime import datetime
import mysql.connector
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

def get_current_working_dir():
    current_working_dir = os.getcwd()

    return current_working_dir

def nmap_network_scan():
    current_working_dir = get_current_working_dir()
    nmap_command = f"nmap -sV -F --script=http-title,ssl-cert -oA {current_working_dir}/nmap/nmap_results -iL {current_working_dir}/nmap/subnet.txt"
    subprocess.run(nmap_command, shell = True, executable="/bin/bash")

def parse_nmap_xml(nmap_xml_file):
    tree = ET.parse(nmap_xml_file)
    root = tree.getroot()
    
    nmap_version = root.get('version', '')
    nmap_arguments = root.get('args', '')
    
    nmap_scan_start_time = root.get('start')
    if nmap_scan_start_time is not None:
        nmap_scan_start_timestamp = int(nmap_scan_start_time)
    
    nmap_scan_elapsed_time = None
    nmap_tag_runstats = root.find('runstats/finished')
    if nmap_tag_runstats is not None:
        nmap_scan_elapsed_time = nmap_tag_runstats.get('elapsed')
    
    nmap_total_hosts = 0
    nmap_total_open_ports = 0
    
    nmap_hosts = []
    for nmap_host in root.findall('host'):
        nmap_total_hosts += 1
        nmap_host_ip = nmap_host.find('address').get('addr')
        
        nmap_tag_hostnames = nmap_host.findall('hostnames/hostname')
        if nmap_tag_hostnames:
            nmap_host_hostname = nmap_tag_hostnames[0].get('name', '')
        else:
            nmap_host_hostname = None
        
        nmap_host_os = 'Unknown'
        nmap_tag_host_os = nmap_host.find('os')
        if nmap_tag_host_os:
            nmap_host_os_match = nmap_tag_host_os.find('osmatch')
            if nmap_host_os_match:
                nmap_host_os = nmap_host_os_match.get('name', 'Unknown')
            else:
                nmap_host_os = 'Unknown'
        
        nmap_total_ports_closed = 0
        nmap_total_ports_filtered = 0
        nmap_total_ports_opened = 0
        nmap_total_ports_tested = 0
        
        nmap_ports = []
        nmap_tag_ports = nmap_host.find('ports')
        if nmap_tag_ports is not None:
            for nmap_port in nmap_tag_ports.findall('port'):
                nmap_port_id = nmap_port.get('portid')
                nmap_port_protocol = nmap_port.get('protocol')
                nmap_port_status = nmap_port.find('state').get('state')
                if nmap_port_status == 'open':
                    nmap_total_ports_opened += 1
                    nmap_total_open_ports += 1
                elif nmap_port_status == 'closed':
                    nmap_total_ports_closed += 1
                elif nmap_port_status == 'filtered':
                    nmap_total_ports_filtered += 1
                
                nmap_service = nmap_port.find('service')
                if nmap_service is not None:
                    nmap_service_name = nmap_service.get('name', None)
                    nmap_service_ostype = nmap_service.get('ostype', None)
                    nmap_service_product = nmap_service.get('product', None)
                    nmap_service_version = nmap_service.get('version', None)
                    if nmap_service_product and nmap_service_version:
                        nmap_service_info = nmap_service_product + ' ' + nmap_service_version
                    else:
                        nmap_service_info = None
                else:
                    nmap_service_name = None
                    nmap_service_ostype = None
                    nmap_service_product = None
                    nmap_service_version = None
                    nmap_service_info = None
                
                nmap_http_title = None
                nmap_ssl_common_name = None
                nmap_ssl_issuer = None
                
                for nmap_script in nmap_port.findall('script'):
                    if nmap_script.get('id') == 'http-title':
                        nmap_http_title = nmap_script.get('output')
                    if nmap_script.get('id') == 'ssl-cert':
                        for nmap_ssl_table in nmap_script.findall('table'):
                            if nmap_ssl_table.get('key') == 'subject':
                                if nmap_ssl_table.find("elem[@key='commonName']") is not None:
                                    nmap_tag_ssl_cn = (nmap_ssl_table.find("elem[@key='commonName']"))
                                    nmap_ssl_common_name = nmap_tag_ssl_cn.text
                            elif nmap_ssl_table.get('key') == 'issuer':
                                nmap_tag_ssl_issuer = {elem.get('key'): elem.text for elem in nmap_ssl_table.findall('elem')}
                                if 'commonName' in nmap_tag_ssl_issuer:
                                    nmap_ssl_issuer = f"{nmap_tag_ssl_issuer.get('commonName')} {nmap_tag_ssl_issuer.get('organizationName', '')}".strip()
                
                if nmap_service_ostype and nmap_host_os == 'Unknown':
                    nmap_host_os = nmap_service_ostype
                
                nmap_ports.append({
                    'port': nmap_port_id,
                    'protocol': nmap_port_protocol,
                    'status': nmap_port_status,
                    'service_name': nmap_service_name,
                    'service_info': nmap_service_info,
                    'http_title': nmap_http_title,
                    'ssl_common_name': nmap_ssl_common_name,
                    'ssl_issuer': nmap_ssl_issuer
                })
            
            nmap_tag_extraports = nmap_tag_ports.find('extraports')
            if len(nmap_tag_extraports):
                nmap_extraports_count = int(nmap_tag_extraports.get('count', '0'))
                nmap_extraports_status = nmap_tag_extraports.get('state', '')
                if nmap_extraports_status == 'closed':
                    nmap_total_ports_closed += nmap_extraports_count
                elif nmap_extraports_status == 'filtered':
                    nmap_total_ports_filtered += nmap_extraports_count
        
        nmap_host_start_time = nmap_host.get('starttime')
        nmap_host_end_time = nmap_host.get('endtime')
        if nmap_host_start_time and nmap_host_end_time:
            nmap_host_start_timestamp = int(nmap_host_start_time)
            nmap_host_end_timestamp = int(nmap_host_end_time)
        else:
            nmap_host_start_timestamp = None
            nmap_host_end_timestamp = None
            
        nmap_hosts.append({
            'ip': nmap_host_ip,
            'hostname': nmap_host_hostname,
            'os': nmap_host_os,
            'ports_tested': nmap_total_ports_tested,
            'ports_open': nmap_total_ports_opened,
            'ports_closed': nmap_total_ports_closed,
            'ports_filtered': nmap_total_ports_filtered,
            'start_time': nmap_host_start_timestamp,
            'end_time': nmap_host_end_timestamp,
            'ports': nmap_ports
        })
    
    nmap_scan = {
        'nmap_version': nmap_version,
        'command_line': nmap_arguments,
        'start_time': nmap_scan_start_time,
        'elapsed_time': nmap_scan_elapsed_time,
        'total_hosts': nmap_total_hosts,
        'total_open_ports': nmap_total_open_ports
    }
    
    return nmap_hosts, nmap_scan

def connect_nmap_database():
    conn = mysql.connector.connect(
        host="localhost",
        user="nmap",
        password="nmap",
        database="nmap"
    )
    
    return conn

def truncate_nmap_tables():
    conn = connect_nmap_database()
    cursor = conn.cursor()
    
    cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")
    
    cursor.execute("SHOW TABLES;")
    tables = cursor.fetchall()
    
    for table in tables:
        table_name = table[0]
        cursor.execute(f"TRUNCATE TABLE {table_name};")
    
    cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")
    
    conn.commit()
    cursor.close()
    conn.close()

def insert_nmap_data(nmap_hosts, nmap_scan):
    conn = connect_nmap_database()
    cursor = conn.cursor()

    scan_query = """
        INSERT INTO nmap_scan (nmap_version, command_line, start_time, elapsed_time, total_hosts, total_open_ports)
        VALUES (%s, %s, FROM_UNIXTIME(%s), %s, %s, %s)
    """
    cursor.execute(scan_query, (
        nmap_scan['nmap_version'],
        nmap_scan['command_line'],
        nmap_scan['start_time'],
        nmap_scan['elapsed_time'],
        nmap_scan['total_hosts'],
        nmap_scan['total_open_ports']
    ))

    scan_id = cursor.lastrowid

    host_query = """
        INSERT INTO nmap_hosts (ip, hostname, os, ports_tested, ports_open, ports_closed, ports_filtered, start_time, end_time)
        VALUES (%s, %s, %s, %s, %s, %s, %s, FROM_UNIXTIME(%s), FROM_UNIXTIME(%s))
    """

    port_query = """
        INSERT INTO nmap_ports (host_id, port, protocol, status, service_name, service_info, http_title, ssl_common_name, ssl_issuer)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    for host in nmap_hosts:
        cursor.execute(host_query, (
            host['ip'],
            host['hostname'],
            host['os'],
            host['ports_tested'],
            host['ports_open'],
            host['ports_closed'],
            host['ports_filtered'],
            host['start_time'],
            host['end_time']
        ))
        host_id = cursor.lastrowid

    for port in host['ports']:
        cursor.execute(port_query, (
            host_id,
            port['port'],
            port['protocol'],
            port['status'],
            port['service_name'],
            port['service_info'],
            port['http_title'],
            port['ssl_common_name'],
            port['ssl_issuer']
        ))

    conn.commit()
    cursor.close()
    conn.close()

def delete_results():
    current_working_dir = get_current_working_dir()
    del_command = f"rm -f {current_working_dir}/nmap/nmap_results*"
    subprocess.run(del_command, shell = True, executable="/bin/bash")

def main():
    current_working_dir = get_current_working_dir()
    truncate_nmap_tables()
    nmap_network_scan()
    nmap_hosts, nmap_scan = parse_nmap_xml(f"{current_working_dir}/nmap/nmap_results.xml")
    insert_nmap_data(nmap_hosts, nmap_scan)
    delete_results()

if __name__ == '__main__':
    main()