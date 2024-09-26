# -*- coding: utf-8 -*-
"""
==============================================================================
Title        : xml.py
Description  : This script contains XML functions for nmap2mysql
Author       : Grégory Marendaz
Date         : 25.09.2024
Version      : 1.0
Usage        : N/A

==============================================================================
Changelog:
    - 25.05.2024 : Creation

==============================================================================
"""

import xml.etree.ElementTree as ET

def get_text(element, key, default=None):
    return element.get(key, default)

def parse_nmap_xml(nmap_xml_file):
    tree = ET.parse(nmap_xml_file)
    root = tree.getroot()

    nmap_scan = parse_nmap_scan_info(root)
    nmap_hosts = [parse_nmap_host(host) for host in root.findall('host')]

    return nmap_hosts, nmap_scan


def parse_nmap_scan_info(root):
    return {
        'nmap_version': get_text(root, 'version'),
        'command_line': get_text(root, 'args'),
        'start_time': get_text(root, 'start'),
        'elapsed_time': get_text(root.find('runstats/finished'), 'elapsed'),
        'total_hosts': len(root.findall('host')),
        'total_open_ports': sum(parse_nmap_host(host)['ports_open'] for host in root.findall('host'))
    }


def parse_nmap_host(host):
    ip = get_text(host.find('address'), 'addr')
    hostname = get_text(host.find('hostnames/hostname'), 'name')
    os = parse_nmap_host_os(host)
    ports, open_ports, closed_ports, filtered_ports = parse_nmap_ports(host.find('ports'))

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


def parse_nmap_host_os(host):
    os_match = host.find('os/osmatch')
    return get_text(os_match, 'name', 'Unknown') if os_match is not None else 'Unknown'


def parse_nmap_ports(ports_element):
    ports = []
    open_ports = closed_ports = filtered_ports = 0

    if ports_element is not None:
        for port in ports_element.findall('port'):
            port_info, open_count, closed_count, filtered_count = parse_nmap_port(port)
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


def parse_nmap_port(port):
    port_id = get_text(port, 'portid')
    protocol = get_text(port, 'protocol')
    status = get_text(port.find('state'), 'state')
    service = port.find('service')

    open_count, closed_count, filtered_count = calculate_nmap_port_count(status)

    service_info = parse_nmap_service_info(service) if service is not None else {}

    return {
        'port': port_id,
        'protocol': protocol,
        'status': status,
        **service_info
    }, open_count, closed_count, filtered_count


def calculate_nmap_port_count(status):
    if status == 'open':
        return 1, 0, 0
    elif status == 'closed':
        return 0, 1, 0
    elif status == 'filtered':
        return 0, 0, 1
    return 0, 0, 0


def parse_nmap_service_info(service):
    service_name = get_text(service, 'name')
    product = get_text(service, 'product')
    version = get_text(service, 'version')
    service_info = f"{product} {version}".strip() if product and version else None

    http_title, ssl_common_name, ssl_issuer = parse_nmap_scripts(service)

    return {
        'service_name': service_name,
        'service_info': service_info,
        'http_title': http_title,
        'ssl_common_name': ssl_common_name,
        'ssl_issuer': ssl_issuer
    }


def parse_nmap_scripts(service):
    http_title = ssl_common_name = ssl_issuer = None

    for script in service.findall('script'):
        if script.get('id') == 'http-title':
            http_title = script.get('output')
        elif script.get('id') == 'ssl-cert':
            ssl_common_name, ssl_issuer = parse_nmap_ssl_cert(script)

    return http_title, ssl_common_name, ssl_issuer


def parse_nmap_ssl_cert(script):
    common_name = issuer = None

    for table in script.findall('table'):
        if table.get('key') == 'subject':
            cn_element = table.find("elem[@key='commonName']")
            if cn_element is not None:
                common_name = cn_element.text
        elif table.get('key') == 'issuer':
            issuer = parse_nmap_ssl_issuer(table)

    return common_name, issuer


def parse_nmap_ssl_issuer(table):
    issuer_data = {elem.get('key'): elem.text for elem in table.findall('elem')}
    return f"{issuer_data.get('commonName')} {issuer_data.get('organizationName', '')}".strip()