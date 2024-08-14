#!/bin/bash

source "$HOME/miniconda3/etc/profile.d/conda.sh"
conda activate nmap2mysql
python3 "$HOME/nmap2mysql/nmap2mysql.py"
conda deactivate