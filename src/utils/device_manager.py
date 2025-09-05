#!/usr/bin/env python3

import subprocess 
import json 
import time 
import os 
import re 
from pathlib import Path 
from typing import Dict ,List ,Optional ,Tuple ,Union ,Any 
from dataclasses import dataclass ,asdict 

try :
    from .logger import get_logger 
except ImportError :

    import logging 
    def get_logger ():
        return logging .getLogger (__name__ )


@dataclass 
class DeviceInfo :
    serial :str 
    state :str 
    product :str =""
    model :str =""
    device :str =""
    transport_id :str =""
    usb :str =""

    def to_dict (self )->Dict [str ,str ]:
        return asdict (self )


class DeviceManager :

    def __init__ (self ,adb_path :Optional [str ]=None ,timeout :int =30 ):
        self .logger =get_logger ()
        self .adb_path =adb_path or self ._find_adb ()
        self .timeout =timeout 

        if not self .adb_path :
            raise RuntimeError ("ADB not found. Please install Android SDK platform tools.")

        self .logger .debug (f"Using ADB at: {self .adb_path }")

    def _find_adb (self )->Optional [str ]:
        try :
            result =subprocess .run (['which','adb'],capture_output =True ,text =True )
            if result .returncode ==0 :
                return result .stdout .strip ()
        except Exception :
            pass 


        common_paths =[
        "/usr/bin/adb",
        "/usr/local/bin/adb",
        "~/Android/Sdk/platform-tools/adb",
        "~/Library/Android/sdk/platform-tools/adb",
        ]

        for path in common_paths :
            expanded_path =Path (path ).expanduser ()
            if expanded_path .exists ():
                return str (expanded_path )

        return None 

    def _run_adb_command (self ,args :List [str ],device :Optional [str ]=None ,
    capture_output :bool =True ,timeout :Optional [int ]=None )->subprocess .CompletedProcess :
        cmd =[self .adb_path ]

        if device :
            cmd .extend (['-s',device ])

        cmd .extend (args )

        self .logger .debug (f"Running ADB command: {' '.join (cmd )}")

        try :
            result =subprocess .run (
            cmd ,
            capture_output =capture_output ,
            text =True ,
            timeout =timeout or self .timeout 
            )
            return result 
        except subprocess .TimeoutExpired :
            self .logger .error (f"ADB command timed out: {' '.join (cmd )}")
            raise 
        except Exception as e :
            self .logger .error (f"ADB command failed: {e }")
            raise 

    def list_devices (self )->List [DeviceInfo ]:
        self .logger .info ("Listing connected devices...")

        try :
            result =self ._run_adb_command (['devices','-l'])

            if result .returncode !=0 :
                self .logger .error (f"Failed to list devices: {result .stderr }")
                return []

            devices =[]
            lines =result .stdout .strip ().split ('\n')[1 :]

            for line in lines :
                if not line .strip ():
                    continue 


                parts =line .split ()
                if len (parts )>=2 :
                    serial =parts [0 ]
                    state =parts [1 ]


                    device_info =DeviceInfo (serial =serial ,state =state )


                    for part in parts [2 :]:
                        if ':'in part :
                            key ,value =part .split (':',1 )
                            if hasattr (device_info ,key ):
                                setattr (device_info ,key ,value )

                    devices .append (device_info )

            self .logger .info (f"Found {len (devices )} device(s)")
            return devices 

        except Exception as e :
            self .logger .error (f"Error listing devices: {e }")
            return []

    def get_device_info (self ,device :str )->Optional [Dict [str ,str ]]:
        self .logger .debug (f"Getting device info for: {device }")

        try :

            result =self ._run_adb_command (['shell','getprop'],device =device )

            if result .returncode !=0 :
                self .logger .error (f"Failed to get device properties: {result .stderr }")
                return None 

            properties ={}
            for line in result .stdout .strip ().split ('\n'):
                match =re .match (r'\[([^\]]+)\]: \[([^\]]*)\]',line )
                if match :
                    key ,value =match .groups ()
                    properties [key ]=value 

            return properties 

        except Exception as e :
            self .logger .error (f"Error getting device info: {e }")
            return None 

    def install_apk (self ,apk_path :str ,device :Optional [str ]=None ,
    grant_permissions :bool =False ,replace :bool =True )->bool :
        self .logger .info (f"Installing APK: {apk_path }")

        if not Path (apk_path ).exists ():
            self .logger .error (f"APK file not found: {apk_path }")
            return False 

        try :
            args =['install']

            if replace :
                args .append ('-r')

            if grant_permissions :
                args .append ('-g')

            args .append (apk_path )

            result =self ._run_adb_command (args ,device =device )

            if result .returncode ==0 and 'Success'in result .stdout :
                self .logger .success (f"APK installed successfully on device {device or 'default'}")
                return True 
            else :
                self .logger .error (f"APK installation failed: {result .stderr or result .stdout }")
                return False 

        except Exception as e :
            self .logger .error (f"Error installing APK: {e }")
            return False 

    def uninstall_package (self ,package_name :str ,device :Optional [str ]=None )->bool :
        self .logger .info (f"Uninstalling package: {package_name }")

        try :
            result =self ._run_adb_command (['uninstall',package_name ],device =device )

            if result .returncode ==0 and 'Success'in result .stdout :
                self .logger .success (f"Package {package_name } uninstalled successfully")
                return True 
            else :
                self .logger .error (f"Package uninstallation failed: {result .stderr or result .stdout }")
                return False 

        except Exception as e :
            self .logger .error (f"Error uninstalling package: {e }")
            return False 

    def start_app (self ,package_name :str ,activity :Optional [str ]=None ,
    device :Optional [str ]=None )->bool :
        if activity :
            component =f"{package_name }/{activity }"
        else :
            component =package_name 

        self .logger .info (f"Starting app: {component }")

        try :
            result =self ._run_adb_command (
            ['shell','am','start','-n',component ],
            device =device 
            )

            if result .returncode ==0 :
                self .logger .success (f"App {component } started successfully")
                return True 
            else :
                self .logger .error (f"Failed to start app: {result .stderr }")
                return False 

        except Exception as e :
            self .logger .error (f"Error starting app: {e }")
            return False 

    def stop_app (self ,package_name :str ,device :Optional [str ]=None )->bool :
        self .logger .info (f"Stopping app: {package_name }")

        try :
            result =self ._run_adb_command (
            ['shell','am','force-stop',package_name ],
            device =device 
            )

            if result .returncode ==0 :
                self .logger .success (f"App {package_name } stopped successfully")
                return True 
            else :
                self .logger .error (f"Failed to stop app: {result .stderr }")
                return False 

        except Exception as e :
            self .logger .error (f"Error stopping app: {e }")
            return False 

    def pull_file (self ,device_path :str ,local_path :str ,
    device :Optional [str ]=None )->bool :
        self .logger .debug (f"Pulling file: {device_path } -> {local_path }")

        try :
            result =self ._run_adb_command (
            ['pull',device_path ,local_path ],
            device =device 
            )

            if result .returncode ==0 :
                self .logger .success (f"File pulled successfully: {local_path }")
                return True 
            else :
                self .logger .error (f"Failed to pull file: {result .stderr }")
                return False 

        except Exception as e :
            self .logger .error (f"Error pulling file: {e }")
            return False 

    def push_file (self ,local_path :str ,device_path :str ,
    device :Optional [str ]=None )->bool :
        self .logger .debug (f"Pushing file: {local_path } -> {device_path }")

        if not Path (local_path ).exists ():
            self .logger .error (f"Local file not found: {local_path }")
            return False 

        try :
            result =self ._run_adb_command (
            ['push',local_path ,device_path ],
            device =device 
            )

            if result .returncode ==0 :
                self .logger .success (f"File pushed successfully: {device_path }")
                return True 
            else :
                self .logger .error (f"Failed to push file: {result .stderr }")
                return False 

        except Exception as e :
            self .logger .error (f"Error pushing file: {e }")
            return False 

    def shell_command (self ,command :str ,device :Optional [str ]=None )->Tuple [bool ,str ]:
        self .logger .debug (f"Executing shell command: {command }")

        try :
            result =self ._run_adb_command (['shell',command ],device =device )

            if result .returncode ==0 :
                return True ,result .stdout 
            else :
                self .logger .error (f"Shell command failed: {result .stderr }")
                return False ,result .stderr 

        except Exception as e :
            self .logger .error (f"Error executing shell command: {e }")
            return False ,str (e )

    def is_device_ready (self ,device :str )->bool :
        try :
            devices =self .list_devices ()
            for dev in devices :
                if dev .serial ==device and dev .state =='device':
                    return True 
            return False 
        except Exception :
            return False 

    def wait_for_device (self ,device :Optional [str ]=None ,timeout :int =60 )->bool :
        self .logger .info (f"Waiting for device to be ready...")

        try :
            args =['wait-for-device']
            result =self ._run_adb_command (args ,device =device ,timeout =timeout )

            if result .returncode ==0 :
                self .logger .success ("Device is ready")
                return True 
            else :
                self .logger .error ("Device wait timed out")
                return False 

        except Exception as e :
            self .logger .error (f"Error waiting for device: {e }")
            return False 

    def get_package_info (self ,package_name :str ,device :Optional [str ]=None )->Optional [Dict [str ,Any ]]:
        self .logger .debug (f"Getting package info for: {package_name }")

        try :
            success ,output =self .shell_command (
            f"dumpsys package {package_name }",
            device =device 
            )

            if success :

                info ={
                'package_name':package_name ,
                'version_name':None ,
                'version_code':None ,
                'first_install_time':None ,
                'last_update_time':None ,
                'installer':None ,
                'permissions':[]
                }

                for line in output .split ('\n'):
                    line =line .strip ()
                    if 'versionName='in line :
                        info ['version_name']=line .split ('versionName=')[1 ]
                    elif 'versionCode='in line :
                        info ['version_code']=line .split ('versionCode=')[1 ].split ()[0 ]
                    elif 'firstInstallTime='in line :
                        info ['first_install_time']=line .split ('firstInstallTime=')[1 ]
                    elif 'lastUpdateTime='in line :
                        info ['last_update_time']=line .split ('lastUpdateTime=')[1 ]
                    elif 'installerPackageName='in line :
                        info ['installer']=line .split ('installerPackageName=')[1 ]
                    elif line .startswith ('android.permission.'):
                        info ['permissions'].append (line )

                return info 
            else :
                return None 

        except Exception as e :
            self .logger .error (f"Error getting package info: {e }")
            return None 
