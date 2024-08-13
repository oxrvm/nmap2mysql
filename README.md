# nmap2mysql

This repository contains a Python script designed to parse Nmap XML output files and insert the parsed data into a MySQL database.\
This tool is useful for network administrators and security professionals who need to store and analyze Nmap scan results in a structured and queryable format.

## Features

- Nmap XML parsing : parses Nmap XML output file to extract informations
- MySQL integration : inserts parsed data directly into a MySQL database

## Folder structure

```
└── nmap2mysql/
    ├── bash/
    │   └── crontab.sh
    ├── mysql/
    │   └── SCHEMA.sql
    ├── nmap/
    │   └── subnet.txt
    └── python/
        └── nmap2mysql.py
```

## Requirements

- Nmap
- Miniconda3
- Python 3.x
- **mysql-connector-python** library

## Installation

### Prerequisites

1. Clone the repository
```
git clone https://github.com/oxrvm/nmap2mysql.git
cd nmap2mysql
```
2. Install Nmap
```
sudo apt-get install nmap -y
```
3. Install MySQL server
```
sudo apt-get mysql-server -y
sudo mysql -u root -p < mysql/SCHEMA.sql
```
4. Install Miniconda3
```
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh
```
5. Create virtual environment
```
conda create --name nmap2mysql -y
conda install --name nmap2mysql mysql-connector-python -y
conda activate nmap2mysql
```

### Configuration

- Nmap command can be customized in **nmap2mysql.py** file in *nmap_network_scan()* function.
- **subnet.txt** file can be modified to reflect the actual network architecture.
- Nmap Python script can be automatized with crontab (**crontab.sh**).

## Usage

The script is now functional from the command line : `python3 python/nmap2mysql.py`

## Contribution

Contributions are welcome!\
Please fork the repository and create a pull request with your improvements.

## License
This project is licensed under the GNU GPLv3 License.\
See the LICENSE file for details.