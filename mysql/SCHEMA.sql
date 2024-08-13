CREATE DATABASE IF NOT EXISTS nmap;

CREATE USER IF NOT EXISTS 'nmap'@'localhost' IDENTIFIED WITH mysql_native_password BY 'nmap';

GRANT ALL PRIVILEGES ON nmap.* TO 'nmap'@'localhost';

FLUSH PRIVILEGES;

USE nmap;

CREATE TABLE nmap_hosts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45),
    hostname VARCHAR(255),
    os VARCHAR(255),
    ports_tested INT,
    ports_open INT,
    ports_closed INT,
    ports_filtered INT,
    start_time DATETIME,
    end_time DATETIME
);

CREATE TABLE nmap_ports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    host_id INT,
    port INT,
    protocol VARCHAR(10),
    status VARCHAR(20),
    service_name VARCHAR(255),
    service_info VARCHAR(255),
    http_title TEXT,
    ssl_common_name VARCHAR(255),
    ssl_issuer VARCHAR(255),
    FOREIGN KEY (host_id) REFERENCES nmap_hosts(id)
);

CREATE TABLE nmap_scan (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nmap_version VARCHAR(50),
    command_line TEXT,
    start_time DATETIME,
    elapsed_time FLOAT,
    total_hosts INT,
    total_open_ports INT
);