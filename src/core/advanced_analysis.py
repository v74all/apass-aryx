#!/usr/bin/env python3
from __future__ import annotations 

import importlib .util 
from pathlib import Path 


_impl_path =Path (__file__ ).with_name ("advanced_analysis_impl.py")
spec =importlib .util .spec_from_file_location ("advanced_analysis_impl",_impl_path )
if spec is None or spec .loader is None :
    raise ImportError (f"Cannot load module from {_impl_path }")
_mod =importlib .util .module_from_spec (spec )
spec .loader .exec_module (_mod )


AdvancedAPKAnalyzer =getattr (_mod ,"AdvancedAPKAnalyzer")
main =getattr (_mod ,"main",None )
