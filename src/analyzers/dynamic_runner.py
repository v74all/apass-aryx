#!/usr/bin/env python3
from __future__ import annotations 
import argparse 
import json 
import logging 
import subprocess 
import sys 
import time 
from datetime import datetime 
from pathlib import Path 
from typing import Optional ,List ,Dict ,Any ,Union 

import frida 
from frida .core import Script ,Session ,Device 


logging .basicConfig (
level =logging .INFO ,
format ="%(asctime)s - %(levelname)s - %(message)s",
datefmt ="%Y-%m-%d %H:%M:%S"
)
logger =logging .getLogger ("dynamic_runner")

ROOT =Path (__file__ ).resolve ().parents [2 ]
FRIDA_DIR =ROOT /"scripts"/"frida"
NETWORK_JS =FRIDA_DIR /"network_analyzer.js"
MEMORY_JS =FRIDA_DIR /"memory_analyzer.js"


def run (cmd :list [str ],timeout :Optional [int ]=None )->subprocess .CompletedProcess :
    logger .debug (f"Running command: {' '.join (cmd )}")
    return subprocess .run (cmd ,text =True ,capture_output =True ,timeout =timeout )


def ensure_dirs ()->Path :
    ts =datetime .now ().strftime ("%Y%m%d_%H%M%S")
    outdir =ROOT /"analysis_results"/"unified_output"/f"dynamic_run_{ts }"
    (outdir /"dynamic").mkdir (parents =True ,exist_ok =True )
    (outdir /"logs").mkdir (parents =True ,exist_ok =True )
    (outdir /"screenshots").mkdir (parents =True ,exist_ok =True )
    logger .info (f"Created output directories at {outdir }")
    return outdir 


def pull_reports (device_id :str ,outdir :Path )->list [Path ]:
    dest =outdir /"dynamic"
    patterns =[
    "/sdcard/Download/network_analysis_*.json",
    "/sdcard/Download/memory_analysis_*.json",
    "/sdcard/Download/memory_summary_*.txt",
    ]
    pulled :list [Path ]=[]

    for pat in patterns :
        logger .debug (f"Looking for files matching {pat }")
        cp =run (["adb","-s",device_id ,"shell","sh","-c",f"ls {pat } 2>/dev/null"])
        if cp .returncode !=0 :
            logger .debug (f"No files found for pattern {pat }")
            continue 

        files =[p for p in cp .stdout .split ()if p .strip ().startswith ("/sdcard/")]
        for f in files :
            local =dest /Path (f ).name 
            logger .info (f"Pulling {f } to {local }")
            pull_result =run (["adb","-s",device_id ,"pull",f ,str (local )],timeout =120 )

            if pull_result .returncode ==0 :
                pulled .append (local )
            else :
                logger .error (f"Failed to pull {f }: {pull_result .stderr }")

    return pulled 


def capture_screenshot (device_id :str ,outdir :Path )->Optional [Path ]:
    screenshot_path =outdir /"screenshots"/f"screen_{datetime .now ().strftime ('%Y%m%d_%H%M%S')}.png"
    logger .info (f"Capturing screenshot to {screenshot_path }")


    cp =run (["adb","-s",device_id ,"shell","screencap","-p","/sdcard/screenshot_temp.png"])
    if cp .returncode !=0 :
        logger .error (f"Screenshot capture failed: {cp .stderr }")
        return None 


    cp =run (["adb","-s",device_id ,"pull","/sdcard/screenshot_temp.png",str (screenshot_path )])
    if cp .returncode !=0 :
        logger .error (f"Screenshot pull failed: {cp .stderr }")
        return None 


    run (["adb","-s",device_id ,"shell","rm","/sdcard/screenshot_temp.png"])

    return screenshot_path 


def load_script (session :Session ,path :Path )->Script :
    logger .info (f"Loading script: {path }")
    try :
        code =path .read_text (encoding ="utf-8")
        script =session .create_script (code )


        def on_message (msg :Dict [str ,Any ],data :Any )->None :
            t =msg .get ("type")
            if t =="error":
                logger .error (f"Frida Script Error: {msg .get ('description')}")
                if "stack"in msg :
                    logger .error (f"Stack: {msg .get ('stack')}")
            elif t =="send":
                payload =msg .get ("payload")
                logger .info (f"Frida: {payload }")

        script .on ("message",on_message )
        script .load ()
        logger .info (f"Script {path .name } loaded successfully")
        return script 
    except Exception as e :
        logger .error (f"Failed to load script {path }: {e }")
        raise 


def check_device_compatibility (device :Device )->bool :
    try :

        root_test =run (["adb","-s",device .id ,"shell","id"])
        if "uid=0(root)"not in root_test .stdout :
            logger .warning ("Device does not appear to be rooted. Some features may not work.")


        ps_output =run (["adb","-s",device .id ,"shell","sh","-c","ps | grep frida-server"])
        if ps_output .returncode !=0 :
            logger .warning ("frida-server not detected on device.")
            return False 


        version_output =run (["adb","-s",device .id ,"shell","getprop ro.build.version.release"])
        if version_output .returncode ==0 :
            android_version =version_output .stdout .strip ()
            logger .info (f"Android version: {android_version }")

        return True 
    except Exception as e :
        logger .error (f"Device compatibility check failed: {e }")
        return False 


def main ()->int :
    ap =argparse .ArgumentParser (description ="Dynamic analysis runner using Frida")
    ap .add_argument ("--package",required =True ,help ="Package name or app ID to analyze")
    ap .add_argument ("--device",default ="emulator-5554",help ="Device ID (from adb devices)")
    ap .add_argument ("--duration",type =int ,default =90 ,help ="Duration in seconds to run the analysis")
    ap .add_argument ("--attach",action ="store_true",help ="Attach to running app instead of spawning new")
    ap .add_argument ("--scripts",nargs ="+",help ="Additional script paths to load")
    ap .add_argument ("--screenshot",action ="store_true",help ="Capture screenshots during analysis")
    ap .add_argument ("--screenshot-interval",type =int ,default =15 ,help ="Screenshot interval in seconds")
    ap .add_argument ("--verbose","-v",action ="store_true",help ="Enable verbose logging")
    args =ap .parse_args ()


    if args .verbose :
        logger .setLevel (logging .DEBUG )

    logger .info (f"Starting dynamic analysis for {args .package } on {args .device }")
    logger .info (f"Duration: {args .duration }s, Mode: {'attach'if args .attach else 'spawn'}")

    outdir =ensure_dirs ()


    log_file =outdir /"logs"/"dynamic_runner.log"
    file_handler =logging .FileHandler (log_file )
    file_handler .setFormatter (logging .Formatter ("%(asctime)s - %(levelname)s - %(message)s"))
    logger .addHandler (file_handler )

    logger .info (f"Output directory: {outdir }")


    try :
        device =frida .get_device (args .device )
        logger .info (f"Connected to device: {device .name } ({device .id })")


        if not check_device_compatibility (device ):
            logger .error ("Device is not compatible with this analysis")
            return 2 
    except frida .InvalidArgumentError :
        logger .error (f"Device {args .device } not found. Available devices:")
        for dev in frida .enumerate_devices ():
            logger .error (f"  - {dev .id } ({dev .name })")
        return 2 
    except Exception as e :
        logger .error (f"Failed to connect to device: {e }")
        return 2 


    pid =None 
    session =None 
    try :
        if args .attach :

            logger .info (f"Looking for running process: {args .package }")
            procs =device .enumerate_processes ()
            for p in procs :
                if p .name ==args .package or str (p .pid )==args .package :
                    pid =p .pid 
                    break 
            if pid is None :
                logger .error ("Process not running; start the app and retry with --attach, or use spawn")
                return 3 
            session =device .attach (pid )
            logger .info (f"Attached to PID {pid }")
        else :

            logger .info (f"Spawning {args .package }")
            pid =device .spawn ([args .package ])
            logger .info (f"Spawned with PID {pid }")
            session =device .attach (pid )
            logger .info (f"Attached to spawned process")
    except Exception as e :
        logger .error (f"Spawn/attach failed: {e }")
        return 4 


    scripts =[]
    try :

        scripts .append (load_script (session ,NETWORK_JS ))
        scripts .append (load_script (session ,MEMORY_JS ))


        if args .scripts :
            for script_path in args .scripts :
                script_path =Path (script_path )
                if script_path .exists ():
                    scripts .append (load_script (session ,script_path ))
                else :
                    logger .warning (f"Script not found: {script_path }")
    except Exception as e :
        logger .error (f"Script load failed: {e }")
        try :
            if session :
                session .detach ()
                logger .info ("Session detached due to script load failure")
        except Exception as detach_error :
            logger .error (f"Failed to detach session: {detach_error }")
        return 5 


    try :
        if not args .attach and pid is not None :
            device .resume (pid )
            logger .info ("Resumed app")
    except Exception as e :
        logger .error (f"Resume failed: {e }")


    logger .info (f"Running analysis for {args .duration } seconds...")
    start_time =time .time ()
    screenshots =[]

    try :

        while time .time ()-start_time <args .duration :

            elapsed =time .time ()-start_time 
            remaining =args .duration -elapsed 
            if int (elapsed )%10 ==0 :
                logger .info (f"Analysis in progress: {int (elapsed )}s elapsed, {int (remaining )}s remaining")


            if args .screenshot and int (elapsed )%args .screenshot_interval ==0 :
                screenshot =capture_screenshot (args .device ,outdir )
                if screenshot :
                    screenshots .append (screenshot )

            time .sleep (1 )
    except KeyboardInterrupt :
        logger .info ("Analysis interrupted by user")
    finally :

        try :
            if session :

                for script in reversed (scripts ):
                    try :
                        script .unload ()
                    except Exception as e :
                        logger .error (f"Failed to unload script: {e }")

                session .detach ()
                logger .info ("Session detached")
        except Exception as e :
            logger .error (f"Cleanup failed: {e }")


    if args .screenshot :
        final_screenshot =capture_screenshot (args .device ,outdir )
        if final_screenshot :
            screenshots .append (final_screenshot )


    logger .info ("Pulling reports from device...")
    pulled =pull_reports (args .device ,outdir )
    if pulled :
        logger .info (f"Pulled {len (pulled )} report files:")
        for p in pulled :
            logger .info (f"  - {p }")
    else :
        logger .warning ("No reports pulled; app may have crashed or hooks blocked.")


    index_data ={
    "package":args .package ,
    "device":args .device ,
    "duration":args .duration ,
    "mode":"attach"if args .attach else "spawn",
    "outputs":[str (p )for p in pulled ],
    "screenshots":[str (p )for p in screenshots ],
    "scripts":[str (NETWORK_JS ),str (MEMORY_JS )]+([str (p )for p in args .scripts ]if args .scripts else []),
    "timestamp":datetime .now ().isoformat (),
    "success":bool (pulled ),
    }

    index_file =outdir /"dynamic_index.json"
    index_file .write_text (json .dumps (index_data ,indent =2 ))
    logger .info (f"Created index file: {index_file }")

    logger .info (f"Dynamic analysis completed: {outdir }")
    return 0 


if __name__ =="__main__":
    try :
        sys .exit (main ())
    except Exception as e :
        logger .exception (f"Unhandled exception: {e }")
        sys .exit (1 )
