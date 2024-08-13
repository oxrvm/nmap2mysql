#!/bin/bash

HOME_PATH="$(dirname "$PWD")"
source "$HOME_PATH/miniconda3/etc/profile.d/conda.sh"
conda activate nmap2mysql
python3 "$HOME_PATH/nmap2mysql/python/nmap2mysql.py"
conda deactivate