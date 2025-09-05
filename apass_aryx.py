#!/usr/bin/env python3
from __future__ import annotations 

import importlib .util 
from pathlib import Path 

_module_path =Path (__file__ ).resolve ().parent /"apass-aryx.py"
_spec =importlib .util .spec_from_file_location ("apass_aryx_impl",str (_module_path ))
if not _spec or not _spec .loader :
    raise ImportError ("Failed to load apass-aryx.py module")

_impl =importlib .util .module_from_spec (_spec )
_spec .loader .exec_module (_impl )

APP_NAME =getattr (_impl ,"APP_NAME")
APP_VERSION =getattr (_impl ,"APP_VERSION")
APP_AUTHOR =getattr (_impl ,"APP_AUTHOR")
APP_SLOGAN =getattr (_impl ,"APP_SLOGAN")
APP_TAGLINE =getattr (_impl ,"APP_TAGLINE")
REPO_ROOT =getattr (_impl ,"REPO_ROOT")
config =getattr (_impl ,"config")
log =getattr (_impl ,"log")

cmd_status =getattr (_impl ,"cmd_status")
cmd_analyze =getattr (_impl ,"cmd_analyze",None )
cmd_batch =getattr (_impl ,"cmd_batch",None )
cmd_web =getattr (_impl ,"cmd_web",None )

do_analyze =getattr (_impl ,"do_analyze")
do_analyze_details =getattr (_impl ,"do_analyze_details",None )
