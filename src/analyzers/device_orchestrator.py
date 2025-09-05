#!/usr/bin/env python3
from __future__ import annotations 

import os 
import re 
import subprocess 
import time 
import logging 
import json 
import asyncio 
import tempfile 
from dataclasses import dataclass ,field ,asdict 
from functools import lru_cache 
from pathlib import Path 
from typing import Any ,Dict ,List ,Optional ,Tuple ,Union ,Callable ,TypeVar ,cast 


logger =logging .getLogger (__name__ )


T =TypeVar ('T')


class DeviceOrchestratorError (Exception ):
    pass 


class DeviceNotFoundError (DeviceOrchestratorError ):
    pass 


class AdbCommandError (DeviceOrchestratorError ):
    def __init__ (self ,cmd :List [str ],returncode :int ,stdout :str ,stderr :str ):
        self .cmd =cmd 
        self .returncode =returncode 
        self .stdout =stdout 
        self .stderr =stderr 
        message =f"ADB command failed (returncode={returncode }): {' '.join (cmd )}\nStderr: {stderr }"
        super ().__init__ (message )


@dataclass 
class Device :
    serial :str 
    model :Optional [str ]=None 
    product :Optional [str ]=None 
    device :Optional [str ]=None 
    transport_id :Optional [str ]=None 
    android_version :Optional [str ]=None 
    api_level :Optional [int ]=None 
    battery_level :Optional [int ]=None 
    properties :Dict [str ,str ]=field (default_factory =dict )

    def to_dict (self )->Dict [str ,Any ]:
        return asdict (self )


class DeviceOrchestrator :

    def __init__ (self ,adb_path :Optional [str ]=None ,cache_timeout :int =60 )->None :
        self ._adb =adb_path or os .environ .get ("ADB_BIN","adb")

        if not os .path .isfile (self ._adb )or not os .access (self ._adb ,os .X_OK ):
            raise DeviceOrchestratorError (f"ADB binary not found or not executable at: {self ._adb }")
        self ._cache_timeout =cache_timeout 
        self ._device_cache :Dict [str ,Tuple [float ,Device ]]={}
        self ._init_logging ()

    def _init_logging (self )->None :
        if not logger .handlers :
            handler =logging .StreamHandler ()
            formatter =logging .Formatter ('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler .setFormatter (formatter )
            logger .addHandler (handler )
            logger .setLevel (logging .INFO )

    def _run (self ,args :List [str ],timeout :int =30 ,serial :Optional [str ]=None )->subprocess .CompletedProcess :
        cmd =[self ._adb ]
        if serial :
            cmd +=["-s",serial ]
        cmd +=args 

        logger .debug (f"Running ADB command: {' '.join (cmd )}")
        try :
            result =subprocess .run (cmd ,capture_output =True ,text =True ,timeout =timeout )
            if result .returncode !=0 and not any (x in result .stdout for x in ["Success","success"]):
                logger .error (f"ADB command failed: {' '.join (cmd )}, returncode={result .returncode }")
                logger .error (f"Stderr: {result .stderr }")
                raise AdbCommandError (cmd ,result .returncode ,result .stdout ,result .stderr )
            return result 
        except subprocess .TimeoutExpired as e :
            logger .error (f"ADB command timed out after {timeout }s: {' '.join (cmd )}")
            raise AdbCommandError (cmd ,-1 ,"",f"Command timed out after {timeout } seconds")from e 

    async def _run_async (self ,args :List [str ],timeout :int =30 ,serial :Optional [str ]=None )->subprocess .CompletedProcess :
        loop =asyncio .get_event_loop ()
        return await loop .run_in_executor (None ,lambda :self ._run (args ,timeout ,serial ))

    def list_devices (self ,refresh_cache :bool =False )->List [Device ]:
        if not refresh_cache :

            current_time =time .time ()
            valid_devices =[device for timestamp ,device in self ._device_cache .values ()
            if current_time -timestamp <self ._cache_timeout ]
            if valid_devices :
                return valid_devices 

        cp =self ._run (["devices","-l"],timeout =10 )
        devices :List [Device ]=[]

        for line in cp .stdout .splitlines ()[1 :]:
            line =line .strip ()
            if not line :
                continue 


            parts =line .split ()
            if len (parts )<2 :
                continue 

            serial =parts [0 ]
            if parts [1 ]!="device":

                continue 

            meta :Dict [str ,str ]={}
            for p in parts [2 :]:
                if ":"in p :
                    k ,v =p .split (":",1 )
                    meta [k ]=v 

            device =Device (
            serial =serial ,
            model =meta .get ("model"),
            product =meta .get ("product"),
            device =meta .get ("device"),
            transport_id =meta .get ("transport_id")
            )


            try :
                device .android_version =self ._getprop ("ro.build.version.release",serial )
                api_level =self ._getprop ("ro.build.version.sdk",serial )
                device .api_level =int (api_level )if api_level and api_level .isdigit ()else None 
                battery =self ._try_shell (["dumpsys","battery","|","grep","level"],serial )
                if battery and "level"in battery :
                    level_match =re .search (r'level:\s*(\d+)',battery )
                    if level_match :
                        device .battery_level =int (level_match .group (1 ))


                device .properties =self ._get_device_properties (serial )


                self ._device_cache [serial ]=(time .time (),device )
                devices .append (device )
            except Exception as e :
                logger .warning (f"Error enhancing device info for {serial }: {e }")
                devices .append (device )

        return devices 

    async def list_devices_async (self ,refresh_cache :bool =False )->List [Device ]:
        loop =asyncio .get_event_loop ()
        return await loop .run_in_executor (None ,lambda :self .list_devices (refresh_cache ))

    def pick_device (self ,preferred :Optional [str ]=None ,require :bool =True )->Optional [str ]:
        env_serial =os .environ .get ("ADB_DEVICE_SERIAL")
        if preferred :
            return preferred 
        if env_serial :
            return env_serial 

        devs =self .list_devices ()
        if not devs :
            if require :
                raise DeviceNotFoundError ("No ADB devices connected (or unauthorized)")
            return None 
        return devs [0 ].serial 

    def get_device_info (self ,serial :Optional [str ]=None )->Device :
        serial =self .pick_device (serial )
        devices =self .list_devices ()

        for device in devices :
            if device .serial ==serial :
                return device 

        raise DeviceNotFoundError (f"Device {serial } not found or not authorized")

    def _get_device_properties (self ,serial :Optional [str ]=None )->Dict [str ,str ]:
        result =self ._run (["shell","getprop"],timeout =15 ,serial =serial )
        properties ={}

        for line in result .stdout .splitlines ():
            match =re .match (r'\[([^\]]+)\]:\s*\[([^\]]*)\]',line )
            if match :
                key ,value =match .groups ()
                properties [key ]=value 

        return properties 



    def install_apk (self ,apk_path :str ,serial :Optional [str ]=None ,
    grant_runtime_perms :bool =False ,reinstall :bool =True )->Dict [str ,Any ]:
        serial =self .pick_device (serial )
        args =["install"]
        if reinstall :
            args .append ("-r")
        if grant_runtime_perms :
            args .append ("-g")
        args .append (apk_path )

        logger .info (f"Installing APK {apk_path } on device {serial }")
        try :
            cp =self ._run (args ,timeout =300 ,serial =serial )
            ok =("Success"in (cp .stdout +cp .stderr ))
            result ={"success":ok ,"stdout":cp .stdout ,"stderr":cp .stderr }

            if ok :

                package =self ._get_package_from_apk (apk_path )
                if package :
                    result ["package"]=package 
                logger .info (f"Successfully installed {apk_path }")
            else :
                logger .error (f"Failed to install {apk_path }: {cp .stderr }")

            return result 
        except AdbCommandError as e :
            logger .error (f"Install error: {e }")
            return {"success":False ,"stdout":e .stdout ,"stderr":e .stderr ,"error":str (e )}

    async def install_apk_async (self ,apk_path :str ,serial :Optional [str ]=None ,
    grant_runtime_perms :bool =False ,reinstall :bool =True )->Dict [str ,Any ]:
        loop =asyncio .get_event_loop ()
        return await loop .run_in_executor (
        None ,lambda :self .install_apk (apk_path ,serial ,grant_runtime_perms ,reinstall )
        )

    def _get_package_from_apk (self ,apk_path :str )->Optional [str ]:
        try :
            result =subprocess .run (
            ["aapt","dump","badging",apk_path ],
            capture_output =True ,
            text =True 
            )
            if result .returncode ==0 :
                match =re .search (r"package: name='([^']+)'",result .stdout )
                if match :
                    return match .group (1 )
        except Exception as e :
            logger .warning (f"Failed to extract package name from APK: {e }")
        return None 

    def uninstall (self ,package :str ,serial :Optional [str ]=None ,keep_data :bool =False )->Dict [str ,Any ]:
        serial =self .pick_device (serial )
        args =["uninstall"]
        if keep_data :
            args .append ("-k")
        args .append (package )

        logger .info (f"Uninstalling package {package } from device {serial }")
        try :
            cp =self ._run (args ,timeout =60 ,serial =serial )
            ok =("Success"in (cp .stdout +cp .stderr ))
            if ok :
                logger .info (f"Successfully uninstalled {package }")
            else :
                logger .error (f"Failed to uninstall {package }: {cp .stderr }")
            return {"success":ok ,"stdout":cp .stdout ,"stderr":cp .stderr }
        except AdbCommandError as e :
            logger .error (f"Uninstall error: {e }")
            return {"success":False ,"stdout":e .stdout ,"stderr":e .stderr ,"error":str (e )}

    def is_app_installed (self ,package :str ,serial :Optional [str ]=None )->bool :
        serial =self .pick_device (serial )
        try :
            cp =self ._run (["shell","pm","list","packages",package ],timeout =15 ,serial =serial )
            return f"package:{package }"in cp .stdout 
        except AdbCommandError :
            return False 

    def launch_app (self ,package :str ,activity :Optional [str ]=None ,
    serial :Optional [str ]=None ,wait_for_launch :bool =True )->Dict [str ,Any ]:
        serial =self .pick_device (serial )
        if not activity :

            cmd =["shell","cmd","package","resolve-activity","--brief",package ]
            try :
                result =self ._run (cmd ,timeout =15 ,serial =serial )
                for line in result .stdout .splitlines ():
                    if "/"in line :
                        activity =line .strip ()
                        break 
            except AdbCommandError :
                pass 

        if not activity :

            activity =f"{package }/.MainActivity"


        launch_cmd =["shell","am","start","-n",f"{package }/{activity }"]

        logger .info (f"Launching {package }/{activity } on device {serial }")
        try :
            cp =self ._run (launch_cmd ,timeout =20 ,serial =serial )
            success ="Starting"in cp .stdout and "Error"not in cp .stdout 

            if success and wait_for_launch :
                time .sleep (2 )

            return {
            "success":success ,
            "stdout":cp .stdout ,
            "stderr":cp .stderr ,
            "package":package ,
            "activity":activity 
            }
        except AdbCommandError as e :
            logger .error (f"Launch error: {e }")
            return {"success":False ,"stdout":e .stdout ,"stderr":e .stderr ,"error":str (e )}

    def stop_app (self ,package :str ,serial :Optional [str ]=None )->Dict [str ,Any ]:
        serial =self .pick_device (serial )
        cmd =["shell","am","force-stop",package ]

        logger .info (f"Stopping app {package } on device {serial }")
        try :
            cp =self ._run (cmd ,timeout =15 ,serial =serial )
            return {"success":cp .returncode ==0 ,"stdout":cp .stdout ,"stderr":cp .stderr }
        except AdbCommandError as e :
            logger .error (f"Stop app error: {e }")
            return {"success":False ,"stdout":e .stdout ,"stderr":e .stderr ,"error":str (e )}

    def clear_app_data (self ,package :str ,serial :Optional [str ]=None )->Dict [str ,Any ]:
        serial =self .pick_device (serial )
        cmd =["shell","pm","clear",package ]

        logger .info (f"Clearing data for app {package } on device {serial }")
        try :
            cp =self ._run (cmd ,timeout =15 ,serial =serial )
            success ="Success"in cp .stdout 
            return {"success":success ,"stdout":cp .stdout ,"stderr":cp .stderr }
        except AdbCommandError as e :
            logger .error (f"Clear app data error: {e }")
            return {"success":False ,"stdout":e .stdout ,"stderr":e .stderr ,"error":str (e )}



    def reboot (self ,serial :Optional [str ]=None ,mode :Optional [str ]=None )->Dict [str ,Any ]:
        serial =self .pick_device (serial )
        cmd =["reboot"]
        if mode :
            cmd .append (mode )

        logger .info (f"Rebooting device {serial }{' to '+mode if mode else ''}")
        try :
            cp =self ._run (cmd ,timeout =15 ,serial =serial )
            return {"success":cp .returncode ==0 ,"stdout":cp .stdout ,"stderr":cp .stderr }
        except AdbCommandError as e :
            logger .error (f"Reboot error: {e }")
            return {"success":False ,"stdout":e .stdout ,"stderr":e .stderr ,"error":str (e )}

    def take_screenshot (self ,output_path :Optional [str ]=None ,serial :Optional [str ]=None )->Dict [str ,Any ]:
        serial =self .pick_device (serial )


        if not output_path :
            tmp_dir =tempfile .gettempdir ()
            timestamp =time .strftime ("%Y%m%d-%H%M%S")
            output_path =os .path .join (tmp_dir ,f"screenshot_{timestamp }.png")

        logger .info (f"Taking screenshot from device {serial }")


        remote_path ="/sdcard/screenshot.png"
        try :
            self ._run (["shell","screencap","-p",remote_path ],timeout =15 ,serial =serial )

            self ._run (["pull",remote_path ,output_path ],timeout =30 ,serial =serial )

            self ._run (["shell","rm",remote_path ],timeout =5 ,serial =serial )

            return {
            "success":True ,
            "path":output_path ,
            "message":f"Screenshot saved to {output_path }"
            }
        except AdbCommandError as e :
            logger .error (f"Screenshot error: {e }")
            return {"success":False ,"error":str (e )}

    def screen_record (self ,output_path :Optional [str ]=None ,duration :int =10 ,
    serial :Optional [str ]=None ,bitrate :int =4000000 )->Dict [str ,Any ]:
        serial =self .pick_device (serial )


        if duration >180 :
            duration =180 
            logger .warning ("Maximum screen recording duration is 180 seconds, capping to this value")


        if not output_path :
            tmp_dir =tempfile .gettempdir ()
            timestamp =time .strftime ("%Y%m%d-%H%M%S")
            output_path =os .path .join (tmp_dir ,f"recording_{timestamp }.mp4")

        logger .info (f"Recording screen from device {serial } for {duration } seconds")


        remote_path ="/sdcard/recording.mp4"
        try :
            self ._run (
            ["shell","screenrecord","--time-limit",str (duration ),
            "--bit-rate",str (bitrate ),remote_path ],
            timeout =duration +30 ,serial =serial 
            )

            self ._run (["pull",remote_path ,output_path ],timeout =60 ,serial =serial )

            self ._run (["shell","rm",remote_path ],timeout =5 ,serial =serial )

            return {
            "success":True ,
            "path":output_path ,
            "duration":duration ,
            "message":f"Screen recording saved to {output_path }"
            }
        except AdbCommandError as e :
            logger .error (f"Screen recording error: {e }")
            return {"success":False ,"error":str (e )}



    def check_modules (self ,serial :Optional [str ]=None )->Dict [str ,Dict [str ,Any ]]:
        serial =self .pick_device (serial )
        return {
        "xposed_lsposed":self .check_xposed_lsposed (serial ),
        "magisk_zygisk":self .check_magisk_zygisk (serial ),
        "inspeckage":self .check_inspeckage (serial ),
        "frida":self .check_frida (serial )
        }

    def check_xposed_lsposed (self ,serial :Optional [str ]=None )->Dict [str ,Any ]:
        serial =self .pick_device (serial )
        pkgs =self ._pm_list (serial )
        indicators ={
        "org.lsposed.manager":("org.lsposed.manager"in pkgs ),
        "de.robv.android.xposed.installer":("de.robv.android.xposed.installer"in pkgs ),
        "mobi.acpm.inspeckage":("mobi.acpm.inspeckage"in pkgs ),
        }
        prop =self ._getprop ("persist.lsposed.api",serial )


        xposed_bridge =self ._try_shell (
        ["ls","/system/framework/XposedBridge.jar"],serial 
        )

        version =None 
        active_modules =[]


        if indicators .get ("org.lsposed.manager"):
            version_info =self ._try_shell (
            ["dumpsys","package","org.lsposed.manager","|","grep","versionName"],
            serial 
            )
            if version_info :
                version_match =re .search (r'versionName=([^\s]+)',version_info )
                if version_match :
                    version =version_match .group (1 )

        return {
        "available":any (indicators .values ())or bool (prop )or bool (xposed_bridge ),
        "packages":indicators ,
        "persist.lsposed.api":prop ,
        "xposed_bridge":bool (xposed_bridge ),
        "version":version ,
        "active_modules":active_modules 
        }

    def check_magisk_zygisk (self ,serial :Optional [str ]=None )->Dict [str ,Any ]:
        serial =self .pick_device (serial )
        pkgs =self ._pm_list (serial )
        has_magisk_app =("com.topjohnwu.magisk"in pkgs )


        magisk_version =(
        self ._try_shell (["magisk","-V"],serial )or 
        self ._try_shell (["su","-c","magisk -V"],serial )or 
        self ._try_shell (["su","-c","magisk --version"],serial )
        )


        zygisk_state =(
        self ._try_shell (["magisk","--zygisk"],serial )or 
        self ._try_shell (["su","-c","magisk --zygisk"],serial )or 
        self ._getprop ("zygisk",serial )
        )


        su_available =bool (self ._try_shell (["which","su"],serial ))


        modules =[]
        module_list =self ._try_shell (["su","-c","ls /data/adb/modules"],serial )
        if module_list :
            modules =[m .strip ()for m in module_list .split ()if m .strip ()]

        available =has_magisk_app or bool (magisk_version )or su_available 

        return {
        "available":available ,
        "has_magisk_app":has_magisk_app ,
        "magisk_version":magisk_version ,
        "zygisk":zygisk_state ,
        "su_available":su_available ,
        "modules":modules 
        }

    def check_inspeckage (self ,serial :Optional [str ]=None )->Dict [str ,Any ]:
        serial =self .pick_device (serial )
        pkgs =self ._pm_list (serial )
        inspeckage_present ="mobi.acpm.inspeckage"in pkgs 

        version =None 
        if inspeckage_present :
            version_info =self ._try_shell (
            ["dumpsys","package","mobi.acpm.inspeckage","|","grep","versionName"],
            serial 
            )
            if version_info :
                version_match =re .search (r'versionName=([^\s]+)',version_info )
                if version_match :
                    version =version_match .group (1 )

        return {
        "present":inspeckage_present ,
        "version":version 
        }

    def check_frida (self ,serial :Optional [str ]=None )->Dict [str ,Any ]:
        serial =self .pick_device (serial )


        frida_process =self ._try_shell (["ps","|","grep","frida-server"],serial )
        frida_running =bool (frida_process and "frida-server"in frida_process )


        frida_binary =(
        self ._try_shell (["ls","/data/local/tmp/frida-server"],serial )or 
        self ._try_shell (["which","frida-server"],serial )
        )


        version =None 
        if frida_binary :
            version_output =self ._try_shell ([frida_binary ,"--version"],serial )
            if version_output :
                version =version_output .strip ()

        return {
        "present":bool (frida_binary ),
        "running":frida_running ,
        "version":version ,
        "binary_path":frida_binary if frida_binary else None 
        }



    def objection_command (self ,package :str )->str :
        return f"objection -g {package } explore"

    def r2frida_commands (self ,package :str )->Dict [str ,str ]:
        return {
        "spawn":f"r2 frida://spawn/usb/{package }",
        "attach":f"r2 frida://attach/usb/{package }",
        }

    def jadx_gui_commands (self ,apk_path :str ,sources_dir :Optional [str ]=None )->Dict [str ,str ]:
        cmds ={"apk":f"jadx-gui {apk_path }"}
        if sources_dir :
            cmds ["sources"]=f"jadx-gui {sources_dir }"
        return cmds 

    def frida_commands (self ,package :str )->Dict [str ,str ]:
        return {
        "spawn":f"frida -U -f {package } -l script.js",
        "attach":f"frida -U -n {package } -l script.js",
        "list":"frida-ps -Ua"
        }



    def _pm_list (self ,serial :Optional [str ]=None )->List [str ]:
        cp =self ._run (["shell","pm","list","packages"],timeout =15 ,serial =serial )
        pkgs :List [str ]=[]
        for line in cp .stdout .splitlines ():
            if line .startswith ("package:"):
                pkgs .append (line .split (":",1 )[1 ].strip ())
        return pkgs 

    def _getprop (self ,name :str ,serial :Optional [str ]=None )->Optional [str ]:
        cp =self ._run (["shell","getprop",name ],timeout =10 ,serial =serial )
        v =(cp .stdout or "").strip ()
        return v or None 

    def _try_shell (self ,args :List [str ],serial :Optional [str ]=None )->Optional [str ]:
        try :
            cp =self ._run (["shell"]+args ,timeout =10 ,serial =serial )
            out =(cp .stdout or cp .stderr or "").strip ()
            return out or None 
        except AdbCommandError :
            return None 


def _main ()->int :
    import argparse ,json 
    p =argparse .ArgumentParser (description ="ADB device orchestrator")
    p .add_argument ("--verbose","-v",action ="store_true",help ="Enable verbose logging")
    sub =p .add_subparsers (dest ="cmd",required =True )

    sp_list =sub .add_parser ("list",help ="List devices")
    sp_list .add_argument ("--json",action ="store_true")
    sp_list .add_argument ("--refresh",action ="store_true",help ="Refresh device cache")

    sp_install =sub .add_parser ("install",help ="Install APK")
    sp_install .add_argument ("apk")
    sp_install .add_argument ("--serial")
    sp_install .add_argument ("--grant",action ="store_true")
    sp_install .add_argument ("--no-reinstall",action ="store_true",help ="Don't reinstall if app exists")

    sp_uninstall =sub .add_parser ("uninstall",help ="Uninstall package")
    sp_uninstall .add_argument ("package")
    sp_uninstall .add_argument ("--serial")
    sp_uninstall .add_argument ("--keep-data",action ="store_true",help ="Keep app data after uninstall")

    sp_launch =sub .add_parser ("launch",help ="Launch app")
    sp_launch .add_argument ("package")
    sp_launch .add_argument ("--serial")
    sp_launch .add_argument ("--activity",help ="Specific activity to launch")

    sp_stop =sub .add_parser ("stop",help ="Stop app")
    sp_stop .add_argument ("package")
    sp_stop .add_argument ("--serial")

    sp_clear =sub .add_parser ("clear",help ="Clear app data")
    sp_clear .add_argument ("package")
    sp_clear .add_argument ("--serial")

    sp_screenshot =sub .add_parser ("screenshot",help ="Take screenshot")
    sp_screenshot .add_argument ("--output",help ="Output path")
    sp_screenshot .add_argument ("--serial")

    sp_record =sub .add_parser ("record",help ="Record screen")
    sp_record .add_argument ("--output",help ="Output path")
    sp_record .add_argument ("--duration",type =int ,default =10 ,help ="Recording duration in seconds")
    sp_record .add_argument ("--serial")

    sp_reboot =sub .add_parser ("reboot",help ="Reboot device")
    sp_reboot .add_argument ("--serial")
    sp_reboot .add_argument ("--mode",choices =["bootloader","recovery","fastboot"],help ="Reboot mode")

    sp_checks =sub .add_parser ("checks",help ="Module checks")
    sp_checks .add_argument ("--serial")
    sp_checks .add_argument ("--format",choices =["json","text"],default ="text")

    args =p .parse_args ()
    orch =DeviceOrchestrator ()


    if args .verbose :
        logger .setLevel (logging .DEBUG )

    if args .cmd =="list":
        devices =[d .to_dict ()for d in orch .list_devices (refresh_cache =args .refresh )]
        if args .json :
            print (json .dumps ({"devices":devices },indent =2 ))
        else :
            if not devices :
                print ("No devices connected")
            for d in devices :
                print (f"- {d .get ('serial')} (model={d .get ('model')}, product={d .get ('product')})")
                if d .get ('android_version'):
                    print (f"  Android {d .get ('android_version')} (API {d .get ('api_level')})")
                if d .get ('battery_level')is not None :
                    print (f"  Battery: {d .get ('battery_level')}%")
        return 0 

    if args .cmd =="install":
        res =orch .install_apk (args .apk ,
        serial =args .serial ,
        grant_runtime_perms =args .grant ,
        reinstall =not args .no_reinstall )
        print ((res .get ("stdout")or "").strip ())
        if not res .get ("success"):
            print ((res .get ("stderr")or "").strip ())
            return 2 
        return 0 

    if args .cmd =="uninstall":
        res =orch .uninstall (args .package ,serial =args .serial ,keep_data =args .keep_data )
        print ((res .get ("stdout")or "").strip ())
        if not res .get ("success"):
            print ((res .get ("stderr")or "").strip ())
            return 2 
        return 0 

    if args .cmd =="launch":
        res =orch .launch_app (args .package ,activity =args .activity ,serial =args .serial )
        if res .get ("success"):
            print (f"Successfully launched {args .package }")
        else :
            print (f"Failed to launch {args .package }")
            print ((res .get ("stderr")or "").strip ())
            return 2 
        return 0 

    if args .cmd =="stop":
        res =orch .stop_app (args .package ,serial =args .serial )
        if res .get ("success"):
            print (f"Successfully stopped {args .package }")
        else :
            print (f"Failed to stop {args .package }")
            return 2 
        return 0 

    if args .cmd =="clear":
        res =orch .clear_app_data (args .package ,serial =args .serial )
        if res .get ("success"):
            print (f"Successfully cleared data for {args .package }")
        else :
            print (f"Failed to clear data for {args .package }")
            return 2 
        return 0 

    if args .cmd =="screenshot":
        res =orch .take_screenshot (output_path =args .output ,serial =args .serial )
        if res .get ("success"):
            print (f"Screenshot saved to {res .get ('path')}")
        else :
            print (f"Failed to take screenshot: {res .get ('error')}")
            return 2 
        return 0 

    if args .cmd =="record":
        res =orch .screen_record (output_path =args .output ,duration =args .duration ,serial =args .serial )
        if res .get ("success"):
            print (f"Screen recording saved to {res .get ('path')}")
        else :
            print (f"Failed to record screen: {res .get ('error')}")
            return 2 
        return 0 

    if args .cmd =="reboot":
        res =orch .reboot (serial =args .serial ,mode =args .mode )
        if res .get ("success"):
            print (f"Device reboot initiated{' to '+args .mode if args .mode else ''}")
        else :
            print (f"Failed to reboot device: {res .get ('error')}")
            return 2 
        return 0 

    if args .cmd =="checks":
        summary =orch .check_modules (args .serial )
        if args .format =="json":
            print (json .dumps (summary ,indent =2 ))
        else :
            def yn (v ):
                return "YES"if v else "NO"
            print (f"Xposed/LSPosed: {yn (summary ['xposed_lsposed'].get ('available'))}")
            if summary ['xposed_lsposed'].get ('available'):
                print (f"  Version: {summary ['xposed_lsposed'].get ('version')or 'unknown'}")

            print (f"Magisk/Zygisk: {yn (summary ['magisk_zygisk'].get ('available'))}")
            if summary ['magisk_zygisk'].get ('available'):
                print (f"  Version: {summary ['magisk_zygisk'].get ('magisk_version')or 'unknown'}")
                print (f"  Zygisk: {summary ['magisk_zygisk'].get ('zygisk')or 'disabled'}")
                if summary ['magisk_zygisk'].get ('modules'):
                    print (f"  Modules: {', '.join (summary ['magisk_zygisk'].get ('modules'))}")

            print (f"Inspeckage: {yn (summary ['inspeckage'].get ('present'))}")
            if summary ['inspeckage'].get ('present'):
                print (f"  Version: {summary ['inspeckage'].get ('version')or 'unknown'}")

            print (f"Frida: {yn (summary ['frida'].get ('present'))}")
            if summary ['frida'].get ('present'):
                print (f"  Running: {yn (summary ['frida'].get ('running'))}")
                print (f"  Version: {summary ['frida'].get ('version')or 'unknown'}")
        return 0 

    return 0 


if __name__ =="__main__":
    import sys as _sys 
    _sys .exit (_main ())
