# -*- coding: utf-8 -*-
"""
==============================================================================
Title        : mysql.py
Description  : This script contains MySQL functions for nmap2mysql
Author       : Grégory Marendaz
Date         : 25.09.2024
Version      : 1.0
Usage        : N/A

==============================================================================
Changelog:
    - 25.05.2024 : Creation

==============================================================================
"""

import os

import mysql.connector

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