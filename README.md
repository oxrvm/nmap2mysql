# nmap2mysql

This repository contains a Python script designed to parse Nmap XML output files and insert the parsed data into a MySQL database.\
This tool is useful for network administrators and security professionals who need to store and analyze Nmap scan results in a structured and queryable format.

## Features

- Nmap XML parsing : parses Nmap XML output file to extract informations
- MySQL integration : inserts parsed data directly into a MySQL database

## Folder structure

```
└── nmap2mysql/
    ├── _lib/
    │   ├── __init__.py
    │   ├── mysql.py
    │   ├── nmap.py
    │   └── xml.py
    ├── bash/
    │   └── crontab.sh
    ├── mysql/
    │   └── SCHEMA.sql
    ├── nmap/
    │   └── subnet.txt
    ├── .env
    ├── .gitignore
    ├── LICENSE.md
    ├── nmap2mysql.py
    ├── README.md
    ├── requirements.txt
    └── setup.sh
```

## Requirements

- Python 3.x
- Nmap
- MySQL Server

## Installation

### Prerequisites

1. Install OS requirements
```
sudo apt-get install python3 python3-pip python3-venv -y
sudo apt-get install nmap -y
sudo apt-get install mysql-server -y
```
2. Clone the repository
```
git clone https://github.com/oxrvm/nmap2mysql.git
cd nmap2mysql
```
3. Install all dependencies
```
bash setup.sh
sudo mysql -u root -p < mysql/SCHEMA.sql
```

### Configuration

- Configure a Crontab schedule
    - `crontab -e`
    - e.g. : `0 0 * * * /bin/bash /installation/path/nmap2mysql/bash/crontab.sh`
- Customize Nmap command in **nmap2mysql.py**.
- Customize **subnet.txt** to reflect the actual network infrastructure.

## Usage

The script is now functional from the command line : `python3 nmap2mysql.py`

## Contribution

Contributions are welcome !\
Please fork the repository and create a pull request with your improvements.

## License
This project is licensed under the GNU GPLv3 License.\
See the LICENSE file for details.