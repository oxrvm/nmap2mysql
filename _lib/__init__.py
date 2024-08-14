# -*- coding: utf-8 -*-
"""
@author :
    Grégory Marendaz

@description :
    nmap2mysql : __init__.py
"""

import importlib.util
import os
import pkgutil

# Dynamically Import Modules
def import_module(module_name, path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# Load Modules
__all__ = []
for _, module_name, is_pkg in pkgutil.iter_modules([os.path.dirname(__file__)]):
    if not is_pkg:
        file_path = os.path.join(os.path.dirname(__file__), module_name + '.py')
        module = import_module(module_name, file_path)
        globals()[module_name] = module
        __all__.append(module_name)
