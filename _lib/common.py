# -*- coding: utf-8 -*-
"""
@author :
    Grégory Marendaz

@description :
    nmap2mysql : Common functions library
"""

import inspect
import os

def get_current_working_dir():
    current_working_dir = os.path.dirname(os.path.abspath(inspect.stack()[1].filename))

    return current_working_dir

def get_current_script_dir():
    current_script_dir = os.path.dirname(os.path.abspath(__file__))

    return current_script_dir