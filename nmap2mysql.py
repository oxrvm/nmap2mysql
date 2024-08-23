# -*- coding: utf-8 -*-
"""
@author:
    Grégory Marendaz
    jubnl

@description:
    nmap2mysql: Main Application

@modifications:
    - Added by jubnl: Refactored the code for better readability and efficiency.
    - Added by jubnl: Created helper functions outside the main function to improve modularity.
"""

import os
import subprocess
import xml.etree.ElementTree as ET

import mysql.connector
from dotenv import load_dotenv

load_dotenv()


def nmap_network_scan():
    current_working_dir = os.getcwd()
    nmap_command = f"nmap -sV -F --script=http-title,ssl-cert -oA {current_working_dir}/nmap/nmap_results -iL {current_working_dir}/nmap/subnet.txt"
    subprocess.run(nmap_command, shell=True, executable="/bin/bash")


def parse_nmap_xml(nmap_xml_file):
    tree = ET.parse(nmap_xml_file)
    root = tree.getroot()

    nmap_scan = extract_nmap_scan_info(root)
    nmap_hosts = [parse_host(host) for host in root.findall('host')]

    return nmap_hosts, nmap_scan


def extract_nmap_scan_info(root):
    return {
        'nmap_version': get_text(root, 'version'),
        'command_line': get_text(root, 'args'),
        'start_time': get_text(root, 'start'),
        'elapsed_time': get_text(root.find('runstats/finished'), 'elapsed'),
        'total_hosts': len(root.findall('host')),
        'total_open_ports': sum(parse_host(host)['ports_open'] for host in root.findall('host'))
    }


def parse_host(host):
    ip = get_text(host.find('address'), 'addr')
    hostname = get_text(host.find('hostnames/hostname'), 'name')
    os = get_host_os(host)
    ports, open_ports, closed_ports, filtered_ports = parse_ports(host.find('ports'))

    return {
        'ip': ip,
        'hostname': hostname,
        'os': os,
        'ports_tested': len(ports),
        'ports_open': open_ports,
        'ports_closed': closed_ports,
        'ports_filtered': filtered_ports,
        'start_time': get_text(host, 'starttime'),
        'end_time': get_text(host, 'endtime'),
        'ports': ports
    }


def get_host_os(host):
    os_match = host.find('os/osmatch')
    return get_text(os_match, 'name', 'Unknown') if os_match is not None else 'Unknown'


def parse_ports(ports_element):
    ports = []
    open_ports = closed_ports = filtered_ports = 0

    if ports_element is not None:
        for port in ports_element.findall('port'):
            port_info, open_count, closed_count, filtered_count = parse_port(port)
            ports.append(port_info)
            open_ports += open_count
            closed_ports += closed_count
            filtered_ports += filtered_count

        extra_ports = ports_element.find('extraports')
        if extra_ports is not None:
            count = int(get_text(extra_ports, 'count', 0))
            status = get_text(extra_ports, 'state', '')
            if status == 'closed':
                closed_ports += count
            elif status == 'filtered':
                filtered_ports += count

    return ports, open_ports, closed_ports, filtered_ports


def parse_port(port):
    port_id = get_text(port, 'portid')
    protocol = get_text(port, 'protocol')
    status = get_text(port.find('state'), 'state')
    service = port.find('service')

    open_count, closed_count, filtered_count = calculate_port_counts(status)

    service_info = get_service_info(service) if service is not None else {}

    return {
        'port': port_id,
        'protocol': protocol,
        'status': status,
        **service_info
    }, open_count, closed_count, filtered_count


def calculate_port_counts(status):
    if status == 'open':
        return 1, 0, 0
    elif status == 'closed':
        return 0, 1, 0
    elif status == 'filtered':
        return 0, 0, 1
    return 0, 0, 0


def get_service_info(service):
    service_name = get_text(service, 'name')
    product = get_text(service, 'product')
    version = get_text(service, 'version')
    service_info = f"{product} {version}".strip() if product and version else None

    http_title, ssl_common_name, ssl_issuer = parse_scripts(service)

    return {
        'service_name': service_name,
        'service_info': service_info,
        'http_title': http_title,
        'ssl_common_name': ssl_common_name,
        'ssl_issuer': ssl_issuer
    }


def parse_scripts(service):
    http_title = ssl_common_name = ssl_issuer = None

    for script in service.findall('script'):
        if script.get('id') == 'http-title':
            http_title = script.get('output')
        elif script.get('id') == 'ssl-cert':
            ssl_common_name, ssl_issuer = parse_ssl_cert(script)

    return http_title, ssl_common_name, ssl_issuer


def parse_ssl_cert(script):
    common_name = issuer = None

    for table in script.findall('table'):
        if table.get('key') == 'subject':
            cn_element = table.find("elem[@key='commonName']")
            if cn_element is not None:
                common_name = cn_element.text
        elif table.get('key') == 'issuer':
            issuer = parse_issuer(table)

    return common_name, issuer


def parse_issuer(table):
    issuer_data = {elem.get('key'): elem.text for elem in table.findall('elem')}
    return f"{issuer_data.get('commonName')} {issuer_data.get('organizationName', '')}".strip()


def get_text(element, key, default=None):
    return element.get(key, default)


def connect_nmap_database():
    conn = mysql.connector.connect(
        host=os.getenv('MYSQL_HOST'),
        user=os.getenv('MYSQL_USER'),
        password=os.getenv('MYSQL_PASSWORD'),
        database=os.getenv('MYSQL_DATABASE')
    )

    return conn


def truncate_nmap_tables():
    with connect_nmap_database() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")

            cursor.execute("SHOW TABLES;")
            tables = cursor.fetchall()

            for table in tables:
                table_name = table[0]
                cursor.execute(f"TRUNCATE TABLE {table_name};")

            cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")

            conn.commit()


def insert_nmap_data(nmap_hosts, nmap_scan):
    with connect_nmap_database() as conn:
        with conn.cursor() as cursor:
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


def delete_results():
    current_working_dir = os.getcwd()
    del_command = f"rm -f {current_working_dir}/nmap/nmap_results*"
    subprocess.run(del_command, shell=True, executable="/bin/bash")


def nmap2mysql():
    current_working_dir = os.getcwd()
    truncate_nmap_tables()
    nmap_network_scan()
    nmap_hosts, nmap_scan = parse_nmap_xml(f"{current_working_dir}/nmap/nmap_results.xml")
    insert_nmap_data(nmap_hosts, nmap_scan)
    delete_results()


if __name__ == '__main__':
    nmap2mysql()
