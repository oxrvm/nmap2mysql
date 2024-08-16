#!/bin/bash

# Define HOME variable
HOME=/home/user

# Activate nmap2mysql environment
source "$HOME/miniconda3/bin/activate" nmap2mysql

# Execute nmap2mysql.py
python3 "$HOME/nmap2mysql/nmap2mysql.py"