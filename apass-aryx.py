#!/usr/bin/env python3
from __future__ import annotations 

import argparse 
import copy 
import json 
import logging 
import sys 
from concurrent .futures import ThreadPoolExecutor ,as_completed 
from pathlib import Path 
from typing import Optional ,Type ,Dict ,Any ,Tuple 

try :
    import yaml 
except Exception :
    yaml =None 

APP_NAME ="APASS ARYX"
APP_VERSION ="Beta v1"
APP_AUTHOR ="Aiden Azad (V7lthronyx)"
APP_SLOGAN ="No mask can hide. APASS ARYX sees through."
APP_TAGLINE ="APASS ARYX, part of the V7lthronyx_IX arsenal - Under Development"


DEFAULT_CONFIG ={
"analysis":{
"engine":"auto",
"timeout":300 ,
"report_formats":["json","txt","html"],
"retries":0 ,
},
"batch":{
"max_workers":2 ,
"recursive":True ,
"fail_fast":False ,
},
"web":{
"host":"0.0.0.0",
"port":5000 ,
"debug":False ,
},
"logging":{
"level":"INFO",
"file":"apass-aryx.log",
"console":True ,
},
}


def setup_logging (level :int =logging .INFO ,log_file :str ="apass-aryx.log",console :bool =True )->logging .Logger :
    handlers :list [logging .Handler ]=[]
    if log_file :
        try :
            fh =logging .FileHandler (log_file )
            fh .setLevel (level )
            handlers .append (fh )
        except Exception :
            pass 
    if console :
        ch =logging .StreamHandler ()
        ch .setLevel (level )
        handlers .append (ch )

    logging .basicConfig (
    level =level ,
    format ="%(asctime)s - %(levelname)s - %(message)s",
    handlers =handlers or None ,
    force =True ,
    )
    return logging .getLogger ("apass-aryx")


log =setup_logging ()

REPO_ROOT =Path (__file__ ).resolve ().parent 
SRC_DIR =REPO_ROOT /"src"
if str (SRC_DIR )not in sys .path :
    sys .path .insert (0 ,str (SRC_DIR ))

CONFIG_FILE =REPO_ROOT /"config.yaml"
config =copy .deepcopy (DEFAULT_CONFIG )

def parse_log_level (level_val :Any )->int :
    try :
        if isinstance (level_val ,int ):
            return level_val 
        return getattr (logging ,str (level_val ).upper (),logging .INFO )
    except Exception :
        return logging .INFO 

def update_logging_from_config ()->None :
    global log 
    log_cfg =config .get ("logging",{})
    log =setup_logging (
    level =parse_log_level (log_cfg .get ("level","INFO")),
    log_file =log_cfg .get ("file","apass-aryx.log"),
    console =bool (log_cfg .get ("console",True )),
    )

def load_config ()->None :
    global config 
    if CONFIG_FILE .exists ()and yaml is not None :
        try :
            with open (CONFIG_FILE ,"r",encoding ="utf-8")as f :
                user_cfg =yaml .safe_load (f )or {}
            if isinstance (user_cfg ,dict ):
                config =deep_update (copy .deepcopy (DEFAULT_CONFIG ),user_cfg )
        except Exception as e :
            log .warning (f"Failed to load config.yaml: {e }")

    update_logging_from_config ()

def deep_update (d :Dict [str ,Any ],u :Dict [str ,Any ])->Dict [str ,Any ]:
    for k ,v in u .items ():
        if isinstance (v ,dict )and isinstance (d .get (k ),dict ):
            d [k ]=deep_update (d .get (k ,{}),v )
        else :
            d [k ]=v 
    return d 


def save_config ()->None :
    try :
        if yaml is None :
            raise RuntimeError ("PyYAML not installed")
        with open (CONFIG_FILE ,"w",encoding ="utf-8")as f :
            yaml .safe_dump (config ,f ,sort_keys =False )
        log .info ("Configuration saved to config.yaml")
    except Exception as e :
        log .error (f"Failed to save config: {e }")


def _load_unified ()->Type :
    from core .unified_analysis import UnifiedAPKAnalyzer 

    return UnifiedAPKAnalyzer 


def _load_advanced ()->Optional [Type ]:
    try :
        from core .advanced_analysis import AdvancedAPKAnalyzer 

        return AdvancedAPKAnalyzer 
    except Exception :
        return None 


def _ensure_outputs (out :Path )->bool :
    rep =out /"reports"
    rep .mkdir (parents =True ,exist_ok =True )
    return True 


def do_analyze_details (apk :Path ,engine :str ,timeout :int =300 )->Tuple [int ,Optional [Path ],Optional [Path ]]:
    if not apk .exists ():
        log .error (f"APK not found: {apk }")
        return 1 ,None ,None 

    chosen =engine or config ["analysis"].get ("engine","auto")

    try :
        from analyzers import run_analyzer 
    except Exception as e :
        log .error (f"Analyzer registry unavailable: {e }")
        return 3 ,None ,None 

    log .info (f"Analyzing {apk .name } with {chosen } engine")
    try :
        code ,outdir ,reports =run_analyzer (chosen ,str (apk ))
        if code !=0 :
            return code ,None ,None 
        out_path =Path (outdir )if outdir else None 
        rep_path =Path (reports )if reports else None 
        return 0 ,out_path ,rep_path 
    except Exception as e :
        log .exception (f"Analysis failed: {e }")
        return 1 ,None ,None 


def do_analyze (apk :Path ,engine :str ,timeout :int =300 )->int :
    rc ,_ ,_ =do_analyze_details (apk ,engine ,timeout )
    return rc 


def cmd_analyze (args :argparse .Namespace )->int :
    engine =args .engine or config ['analysis']['engine']
    timeout =args .timeout or config ['analysis']['timeout']
    return do_analyze (Path (args .apk ),engine ,timeout )


def cmd_batch (args :argparse .Namespace )->int :
    base =Path (args .path )
    if not base .exists ():
        log .error (f"Path not found: {base }")
        return 1 

    recursive =args .recursive if getattr (args ,'recursive',None )is not None else config ['batch']['recursive']

    apks :list [Path ]=[]
    if base .is_file ()and base .suffix .lower ()==".apk":
        apks =[base ]
    else :
        apks =[p for p in (base .rglob ("*.apk")if recursive else base .glob ("*.apk"))]

    if not apks :
        log .error ("No APKs found to analyze")
        return 1 

    max_workers =args .workers if getattr (args ,'workers',None )is not None else config ['batch']['max_workers']
    engine =args .engine or config ['analysis']['engine']
    timeout =args .timeout or config ['analysis']['timeout']

    failures =0 

    def analyze_single_apk (apk_path :Path )->Tuple [Path ,int ]:
        rc =do_analyze (apk_path ,engine ,timeout )
        return apk_path ,rc 

    if not max_workers or max_workers <=1 :
        for apk_path in apks :
            _ ,rc =analyze_single_apk (apk_path )
            failures +=int (rc !=0 )
    else :
        with ThreadPoolExecutor (max_workers =max_workers )as ex :
            futs =[ex .submit (analyze_single_apk ,p )for p in apks ]
            for fut in as_completed (futs ):
                _ ,rc =fut .result ()
                failures +=int (rc !=0 )

    total =len (apks )
    success =total -failures 
    print (f"\n📊 Batch Summary: {success }/{total } successful ({(success /total )*100 :.1f}%)")
    if failures :
        log .warning (f"{failures } analyses failed")
    log .info ("Batch finished")
    return 0 if failures ==0 else 2 


def cmd_status (_ :argparse .Namespace )->int :
    base =REPO_ROOT /"analysis_results"/"unified_output"
    latest :Optional [Path ]=None 
    if base .exists ():
        try :
            latest =max ((p for p in base .iterdir ()if p .is_dir ()),key =lambda p :p .stat ().st_mtime ,default =None )
        except Exception :
            latest =None 

    print (json .dumps ({
    "app":{"name":APP_NAME ,"version":APP_VERSION ,"author":APP_AUTHOR },
    "workspace":{"src":(REPO_ROOT /"src").exists (),"resources":(REPO_ROOT /"resources").exists ()},
    "latest_output":str (latest )if latest else None ,
    },indent =2 ))
    return 0 


def cmd_web (_ :argparse .Namespace )->int :
    try :
        from web_app import app 
        web_cfg =config .get ("web",{})
        app .run (host =web_cfg .get ("host","0.0.0.0"),port =web_cfg .get ("port",5000 ),debug =web_cfg .get ("debug",False ))
        return 0 
    except Exception as e :
        log .error (f"Failed to start web UI: {e }")
        return 1 


def cmd_config (args :argparse .Namespace )->int :
    if args .action =='show':
        print (json .dumps (config ,indent =2 ))
        return 0 
    elif args .action =='save':
        save_config ()
        return 0 
    elif args .action =='set':
        if not args .kv or "="not in args .kv :
            print ("Provide key=value for set action")
            return 2 
        key ,value =args .kv .split ("=",1 )
        try :
            value_parsed =json .loads (value )
        except Exception :
            value_parsed =value 
        ref =config 
        parts =key .split (".")
        for p in parts [:-1 ]:
            ref =ref .setdefault (p ,{})
        ref [parts [-1 ]]=value_parsed 
        print (json .dumps (config ,indent =2 ))
        return 0 
    else :
        return 2 


def migrate_config (cfg :Dict [str ,Any ])->Tuple [Dict [str ,Any ],list [str ]]:
    updated =deep_update (copy .deepcopy (DEFAULT_CONFIG ),cfg or {})
    notes :list [str ]=[]


    if "retries"not in updated .get ("analysis",{}):
        updated ["analysis"]["retries"]=DEFAULT_CONFIG ["analysis"]["retries"]
        notes .append ("Added analysis.retries")

    if "fail_fast"not in updated .get ("batch",{}):
        updated ["batch"]["fail_fast"]=DEFAULT_CONFIG ["batch"]["fail_fast"]
        notes .append ("Added batch.fail_fast")


    lvl_in =updated .get ("logging",{}).get ("level","INFO")
    lvl_out =parse_log_level (lvl_in )
    if isinstance (lvl_in ,str )and getattr (logging ,lvl_in .upper (),None )!=lvl_out :
        notes .append ("Normalized logging.level")
    updated ["logging"]["level"]=["CRITICAL","ERROR","WARNING","INFO","DEBUG","NOTSET"][[logging .CRITICAL ,logging .ERROR ,logging .WARNING ,logging .INFO ,logging .DEBUG ,logging .NOTSET ].index (lvl_out )]if lvl_out in [logging .CRITICAL ,logging .ERROR ,logging .WARNING ,logging .INFO ,logging .DEBUG ,logging .NOTSET ]else "INFO"

    return updated ,notes 

def cmd_upgrade (_ :argparse .Namespace )->int :
    global config 
    before =copy .deepcopy (config )
    config ,notes =migrate_config (before )
    save_config ()
    update_logging_from_config ()
    print (json .dumps ({
    "version":APP_VERSION ,
    "changes":notes or ["No changes; already up to date"],
    },indent =2 ))
    return 0 

def build_parser ()->argparse .ArgumentParser :
    description =f"{APP_NAME } CLI ({APP_VERSION }) - {APP_SLOGAN }\n{APP_TAGLINE }"
    p =argparse .ArgumentParser (
    prog ="apass-aryx",
    description =description ,
    formatter_class =argparse .RawDescriptionHelpFormatter 
    )
    p .add_argument ("--version",action ="version",version =f"{APP_NAME } {APP_VERSION }")
    sub =p .add_subparsers (dest ="cmd",required =True )


    try :
        from analyzers import get_analyzers 
        dynamic_choices =["auto"]+[a .id for a in get_analyzers ()]
    except Exception :
        dynamic_choices =["auto","advanced","unified"]

    a =sub .add_parser ("analyze",help ="Analyze a single APK")
    a .add_argument ("apk",help ="Path to APK file")
    a .add_argument ("--engine",choices =dynamic_choices ,help ="Analysis engine to use")
    a .add_argument ("--timeout",type =int ,help ="Analysis timeout in seconds")
    a .set_defaults (func =cmd_analyze )

    b =sub .add_parser ("batch",help ="Analyze all APKs in a folder (or a single file)")
    b .add_argument ("path",help ="APK file or directory containing APKs")
    b .add_argument ("--engine",choices =dynamic_choices ,help ="Analysis engine to use")
    b .add_argument ("--timeout",type =int ,help ="Analysis timeout in seconds")
    b .add_argument ("--workers",type =int ,help ="Number of concurrent workers (0=sequential)")
    b .add_argument ("--recursive",action ="store_true",help ="Search recursively for APKs")
    b .add_argument ("--no-recursive",dest ="recursive",action ="store_false",help ="Don't search recursively")
    b .set_defaults (func =cmd_batch )

    s =sub .add_parser ("status",help ="Show workspace and latest output status")
    s .set_defaults (func =cmd_status )

    w =sub .add_parser ("web",help ="Start the web UI")
    w .set_defaults (func =cmd_web )

    c =sub .add_parser ("config",help ="Manage configuration")
    c .add_argument ("action",choices =["show","save","set"],help ="Action to perform")
    c .add_argument ("kv",nargs ="?",help ="key=value for set action (supports dotted keys)")
    c .set_defaults (func =cmd_config )

    st =sub .add_parser ("selftest",help ="Print basic info to validate setup")
    st .set_defaults (func =lambda _ :cmd_status (argparse .Namespace ()))
    u =sub .add_parser ("upgrade",help ="Upgrade configuration to latest defaults")
    u .set_defaults (func =cmd_upgrade )
    return p 


def main (argv :Optional [list [str ]]=None )->int :
    load_config ()
    parser =build_parser ()
    args =parser .parse_args (argv )
    if not hasattr (args ,"func"):
        parser .print_help ()
        return 2 
    return int (args .func (args ))


if __name__ =="__main__":
    raise SystemExit (main ())
