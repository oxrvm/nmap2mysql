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
    │   └── common.py
    ├── bash/
    │   └── crontab.sh
    ├── mysql/
    │   └── SCHEMA.sql
    ├── nmap/
    │   └── subnet.txt
    ├── .env
    ├── nmap2mysql.py
    ├── LICENSE.md
    └── README.md
```

## Requirements

- Nmap
- Miniconda3
- Python 3.x
- **mysql-connector-python** and **python-dotenv** libraries

## Installation

### Prerequisites

1. Install Miniconda3
```
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh
```
2. Clone the repository
```
git clone https://github.com/oxrvm/nmap2mysql.git
cd nmap2mysql
```
3. Install Nmap
```
sudo apt-get install nmap -y
```
4. Install MySQL server
```
sudo apt-get install mysql-server -y
sudo mysql -u root -p < mysql/SCHEMA.sql
```
5. Create virtual environment
```
conda create --name nmap2mysql -y
conda install --name nmap2mysql mysql-connector-python python-dotenv -y
conda activate nmap2mysql
```

### Configuration

- Configure a Crontab schedule
    - Replace _$HOME_ variable in **crontab.sh**
    - `crontab -e`
    - e.g. : `0 0 * * * /bin/bash /home/user/nmap2mysql/bash/crontab.sh`
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