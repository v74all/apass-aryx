#!/usr/bin/env python3
from __future__ import annotations 

import argparse 
import json 
import os 
import re 
import shlex 
import shutil 
import subprocess 
import sys 
import time 
import traceback 
from concurrent .futures import ThreadPoolExecutor ,as_completed 
from dataclasses import dataclass ,field 
from datetime import datetime 
from pathlib import Path 
from typing import Any ,Dict ,List ,Optional ,Tuple ,Union ,cast 
import xml .etree .ElementTree as ET 


ARTIFACTS_DIR =Path ("static_analysis_output/artifacts")
BADGING_PATH =ARTIFACTS_DIR /"badging.txt"
MANIFEST_DECODED_PATH =ARTIFACTS_DIR /"AndroidManifest.decoded.xml"
RESOURCES_PATH =ARTIFACTS_DIR /"resources.arsc.decoded"
FOUND_DOMAINS_PATH =Path ("found_domains.txt")
STRINGS_PATH =ARTIFACTS_DIR /"strings.xml"
CLASSES_DEX_PATH =ARTIFACTS_DIR /"classes.dex"


@dataclass 
class AnalysisConfig :
    apk_path :str 
    package_name :str 
    output_dir :Optional [str ]=None 
    timeout :int =180 
    analyze_permissions :bool =True 
    analyze_resources :bool =True 
    analyze_strings :bool =True 
    analyze_cert :bool =True 
    verbose :bool =False 
    max_workers :int =4 


class EnhancedDataExtractor :
    def __init__ (self ,config :AnalysisConfig )->None :
        self .config =config 
        self .apk_path =config .apk_path 
        self .package_name =config .package_name 
        self .timestamp =datetime .now ().strftime ("%Y%m%d_%H%M%S")
        self .output_dir =Path (config .output_dir )if config .output_dir else Path (f"comprehensive_analysis_{self .timestamp }")
        self .output_dir .mkdir (parents =True ,exist_ok =True )
        self .log_file =self .output_dir /"analysis.log"
        self .analysis_start_time =time .time ()
        self .total_tasks =0 
        self .completed_tasks =0 

    def log (self ,msg :str ,level :str ="INFO")->None :
        line =f"[{datetime .now ().isoformat (sep =' ',timespec ='seconds')}] {level }: {msg }\n"
        if level =="DEBUG"and not self .config .verbose :
            pass 
        else :
            sys .stdout .write (line )
        try :
            with self .log_file .open ("a",encoding ="utf-8")as f :
                f .write (line )
        except Exception as e :
            sys .stderr .write (f"Warning: Failed to write to log file: {e }\n")

    def update_progress (self ,task_name :str )->None :
        self .completed_tasks +=1 
        progress =(self .completed_tasks /self .total_tasks )*100 if self .total_tasks >0 else 0 
        elapsed =time .time ()-self .analysis_start_time 
        self .log (f"Completed task: {task_name } - Progress: {progress :.1f}% ({self .completed_tasks }/{self .total_tasks }) - Elapsed: {elapsed :.1f}s",
        level ="PROGRESS")

    def run_command (self ,command :str ,timeout :Optional [int ]=None )->Tuple [int ,str ,str ]:
        if timeout is None :
            timeout =self .config .timeout 

        try :
            self .log (f"Running command: {command }",level ="DEBUG")
            proc =subprocess .run (
            command if isinstance (command ,list )else shlex .split (command ),
            stdout =subprocess .PIPE ,
            stderr =subprocess .PIPE ,
            timeout =timeout ,
            check =False ,
            text =True ,
            )
            if proc .returncode !=0 :
                self .log (f"Command returned non-zero exit code {proc .returncode }: {command }",level ="WARN")
                self .log (f"stderr: {proc .stderr }",level ="DEBUG")

            return proc .returncode ,proc .stdout ,proc .stderr 
        except subprocess .TimeoutExpired :
            self .log (f"Command timed out after {timeout }s: {command }",level ="ERROR")
            return 124 ,"",f"Timed out after {timeout }s"
        except Exception as e :
            self .log (f"Command failed: {command } - Error: {e }",level ="ERROR")
            self .log (traceback .format_exc (),level ="DEBUG")
            return 1 ,"",str (e )

    def _parse_badging (self )->Dict [str ,Any ]:
        info :Dict [str ,Any ]={}
        permissions =[]
        activities =[]
        services =[]
        receivers =[]

        if not BADGING_PATH .exists ():
            self .log ("Badging file not found, attempting to generate with aapt",level ="DEBUG")
            if shutil .which ("aapt"):
                rc ,out ,err =self .run_command (f"aapt dump badging {shlex .quote (self .apk_path )}")
                if rc ==0 :
                    try :
                        badging_path =self .output_dir /"aapt_badging.txt"
                        badging_path .write_text (out ,encoding ="utf-8")
                        self .log (f"Generated badging file at {badging_path }",level ="INFO")
                        txt =out 
                    except Exception as e :
                        self .log (f"Failed to write badging output: {e }",level ="WARN")
                        return info 
                else :
                    self .log ("Failed to extract badging with aapt",level ="WARN")
                    return info 
            else :
                self .log ("aapt not available in PATH",level ="WARN")
                return info 
        else :
            try :
                txt =BADGING_PATH .read_text (encoding ="utf-8",errors ="ignore")
            except Exception as e :
                self .log (f"Failed to read badging file: {e }",level ="WARN")
                return info 

        try :

            for line in txt .splitlines ():
                line =line .strip ()
                if line .startswith ("package: "):

                    parts =dict (
                    (p .split ("=")[0 ].strip (),p .split ("=")[1 ].strip ("'"))
                    for p in [kv for kv in line .replace ("package:","").split ()if "="in kv ]
                    )
                    info .update ({
                    "package_name":parts .get ("name",""),
                    "version_code":parts .get ("versionCode",""),
                    "version_name":parts .get ("versionName",""),
                    "compileSdkVersion":parts .get ("compileSdkVersion",""),
                    "compileSdkVersionCodename":parts .get ("compileSdkVersionCodename",""),
                    })
                elif line .startswith ("sdkVersion:"):
                    info ["min_sdk"]=line .split (":",1 )[1 ].strip ("' ")
                elif line .startswith ("targetSdkVersion:"):
                    info ["target_sdk"]=line .split (":",1 )[1 ].strip ("' ")
                elif line .startswith ("application: "):
                    match =re .search (r"label='([^']*)'",line )
                    if match :
                        info ["app_name"]=match .group (1 )
                elif line .startswith ("uses-permission: "):
                    match =re .search (r"name='([^']*)'",line )
                    if match :
                        permissions .append (match .group (1 ))
                elif line .startswith ("activity: "):
                    match =re .search (r"name='([^']*)'",line )
                    if match :
                        activities .append (match .group (1 ))
                elif line .startswith ("service: "):
                    match =re .search (r"name='([^']*)'",line )
                    if match :
                        services .append (match .group (1 ))
                elif line .startswith ("receiver: "):
                    match =re .search (r"name='([^']*)'",line )
                    if match :
                        receivers .append (match .group (1 ))


            if self .config .analyze_permissions and permissions :
                info ["permissions"]=permissions 
            if activities :
                info ["activities"]=activities 
            if services :
                info ["services"]=services 
            if receivers :
                info ["receivers"]=receivers 

        except Exception as e :
            self .log (f"Failed parsing badging data: {e }",level ="WARN")
            self .log (traceback .format_exc (),level ="DEBUG")

        return info 

    def _parse_manifest_decoded (self )->Dict [str ,Any ]:
        info :Dict [str ,Any ]={}
        if not MANIFEST_DECODED_PATH .exists ():
            return info 

        try :

            tree =ET .parse (MANIFEST_DECODED_PATH )
            root =tree .getroot ()


            ns ={'android':'http://schemas.android.com/apk/res/android'}


            package =root .get ('package')
            if package :
                info ["manifest_package"]=package 


            if self .config .analyze_permissions :
                permissions =[]
                for perm in root .findall ('.//uses-permission',ns ):
                    name =perm .get ('{http://schemas.android.com/apk/res/android}name')
                    if name :
                        permissions .append (name )
                if permissions :
                    info ["manifest_permissions"]=permissions 


                exported_components =[]
                for comp_type in ['activity','service','receiver','provider']:
                    for comp in root .findall (f'.//{comp_type }',ns ):
                        exported =comp .get ('{http://schemas.android.com/apk/res/android}exported')
                        name =comp .get ('{http://schemas.android.com/apk/res/android}name')
                        if exported =='true'and name :
                            exported_components .append (f"{comp_type }:{name }")
                if exported_components :
                    info ["exported_components"]=exported_components 

        except ET .ParseError as e :
            self .log (f"XML parsing error in manifest: {e }",level ="WARN")

            try :
                txt =MANIFEST_DECODED_PATH .read_text (encoding ="utf-8",errors ="ignore")

                if "A: package="in txt :
                    start =txt .find ("A: package=")
                    if start !=-1 :
                        frag =txt [start :start +200 ]
                        q1 =frag .find ('"')
                        q2 =frag .find ('"',q1 +1 )if q1 !=-1 else -1 
                        if q1 !=-1 and q2 !=-1 :
                            info ["manifest_package"]=frag [q1 +1 :q2 ]

                if self .config .analyze_permissions :
                    permissions =[]
                    perm_matches =re .findall (r'uses-permission.*?name="([^"]*)"',txt )
                    if perm_matches :
                        permissions .extend (perm_matches )
                    if permissions :
                        info ["manifest_permissions"]=permissions 

                    exported_components =[]
                    exported_matches =re .findall (r'(activity|service|receiver|provider).*?android:exported="true".*?android:name="([^"]*)"',txt )
                    if exported_matches :
                        exported_components =[f"{comp_type }:{name }"for comp_type ,name in exported_matches ]
                    if exported_components :
                        info ["exported_components"]=exported_components 
            except Exception as fallback_e :
                self .log (f"Fallback parsing also failed: {fallback_e }",level ="WARN")
        except Exception as e :
            self .log (f"Failed parsing AndroidManifest.decoded.xml: {e }",level ="WARN")
            self .log (traceback .format_exc (),level ="DEBUG")

        return info 

    def _read_found_domains (self )->Dict [str ,list ]:
        domains =[]
        if FOUND_DOMAINS_PATH .exists ():
            try :
                domains =[l .strip ()for l in FOUND_DOMAINS_PATH .read_text (encoding ="utf-8").splitlines ()if l .strip ()]

                domains =list (dict .fromkeys (domains ))
            except Exception as e :
                self .log (f"Failed to read domains file: {e }",level ="WARN")
        return {"domains":domains }

    def _analyze_strings (self )->Dict [str ,Any ]:
        result :Dict [str ,Any ]={}

        if not self .config .analyze_strings :
            return result 


        if not STRINGS_PATH .exists ()and shutil .which ("strings"):
            self .log ("Extracting strings from APK",level ="INFO")
            rc ,out ,err =self .run_command (f"strings {shlex .quote (self .apk_path )}")
            if rc ==0 :
                try :
                    strings_path =self .output_dir /"extracted_strings.txt"
                    strings_path .write_text (out ,encoding ="utf-8")
                    self .log (f"Extracted strings to {strings_path }",level ="INFO")


                    api_keys =self ._find_api_keys (out )
                    urls =self ._find_urls (out )

                    if api_keys :
                        result ["potential_api_keys"]=api_keys 
                    if urls :
                        result ["urls_in_strings"]=urls 

                except Exception as e :
                    self .log (f"Failed to analyze strings: {e }",level ="WARN")

        return result 

    def _find_api_keys (self ,text :str )->List [str ]:

        patterns =[
        r'([a-zA-Z0-9_-]{20,40})',
        r'AIza[0-9A-Za-z-_]{35}',
        r'sk_live_[0-9a-zA-Z]{24}',
        r'key-[0-9a-zA-Z]{32}',
        r'[0-9a-f]{32}',
        ]

        potential_keys =set ()
        for pattern in patterns :
            matches =re .findall (pattern ,text )
            for match in matches :

                if len (match )>=20 and not match .startswith (('http','www','/'))and '/'not in match :
                    potential_keys .add (match )

        return list (potential_keys )[:20 ]

    def _find_urls (self ,text :str )->List [str ]:
        url_pattern =r'https?://[^\s"\'\)\}]+\.[^\s"\'\)\}]+'
        urls =re .findall (url_pattern ,text )

        unique_urls =list (dict .fromkeys (urls ))
        return unique_urls [:30 ]

    def _analyze_certificate (self )->Dict [str ,Any ]:
        cert_info :Dict [str ,Any ]={}

        if not self .config .analyze_cert :
            return cert_info 

        if shutil .which ("keytool")and shutil .which ("unzip"):
            self .log ("Analyzing APK certificate",level ="INFO")
            temp_dir =self .output_dir /"cert_extract"
            temp_dir .mkdir (exist_ok =True )


            rc ,out ,err =self .run_command (f"unzip -q -o {shlex .quote (self .apk_path )} 'META-INF/*.RSA' 'META-INF/*.DSA' 'META-INF/*.EC' -d {temp_dir }")

            if rc ==0 or "warning"in err .lower ():
                cert_files =list (temp_dir .glob ("META-INF/*.RSA"))+list (temp_dir .glob ("META-INF/*.DSA"))+list (temp_dir .glob ("META-INF/*.EC"))

                if cert_files :
                    cert_file =cert_files [0 ]
                    rc ,out ,err =self .run_command (f"keytool -printcert -file {cert_file }")

                    if rc ==0 :
                        cert_path =self .output_dir /"certificate_info.txt"
                        cert_path .write_text (out ,encoding ="utf-8")


                        owner_match =re .search (r"Owner: (.*)",out )
                        issuer_match =re .search (r"Issuer: (.*)",out )
                        valid_from_match =re .search (r"Valid from: (.*)",out )
                        valid_to_match =re .search (r"Valid until: (.*)",out )

                        if owner_match :
                            cert_info ["owner"]=owner_match .group (1 )
                        if issuer_match :
                            cert_info ["issuer"]=issuer_match .group (1 )
                        if valid_from_match :
                            cert_info ["valid_from"]=valid_from_match .group (1 )
                        if valid_to_match :
                            cert_info ["valid_to"]=valid_to_match .group (1 )

        return cert_info 

    def extract_static (self )->dict :
        data ={
        "apk":self .apk_path ,
        "package":self .package_name ,
        "artifacts_present":ARTIFACTS_DIR .exists (),
        "analysis_timestamp":self .timestamp ,
        }


        analysis_tasks ={
        "badging":self ._parse_badging ,
        "manifest":self ._parse_manifest_decoded ,
        "domains":self ._read_found_domains ,
        }


        if self .config .analyze_strings :
            analysis_tasks ["strings"]=self ._analyze_strings 
        if self .config .analyze_cert :
            analysis_tasks ["certificate"]=self ._analyze_certificate 

        self .total_tasks =len (analysis_tasks )
        self .log (f"Starting static analysis with {self .total_tasks } tasks",level ="INFO")


        if self .config .max_workers >1 :
            results ={}
            with ThreadPoolExecutor (max_workers =self .config .max_workers )as executor :
                future_to_task ={executor .submit (task_func ):task_name 
                for task_name ,task_func in analysis_tasks .items ()}

                for future in as_completed (future_to_task ):
                    task_name =future_to_task [future ]
                    try :
                        result =future .result ()
                        results [task_name ]=result 
                        self .update_progress (task_name )
                    except Exception as e :
                        self .log (f"Task {task_name } failed: {e }",level ="ERROR")
                        self .log (traceback .format_exc (),level ="DEBUG")
                        self .update_progress (f"{task_name } (failed)")
        else :

            results ={}
            for task_name ,task_func in analysis_tasks .items ():
                try :
                    results [task_name ]=task_func ()
                    self .update_progress (task_name )
                except Exception as e :
                    self .log (f"Task {task_name } failed: {e }",level ="ERROR")
                    self .log (traceback .format_exc (),level ="DEBUG")
                    self .update_progress (f"{task_name } (failed)")


        if "badging"in results :
            data ["badging"]=results ["badging"]

        if "manifest"in results :
            data ["manifest"]=results ["manifest"]

        if "domains"in results :
            data .update (results ["domains"])

        if "strings"in results :
            data ["strings_analysis"]=results ["strings"]

        if "certificate"in results :
            data ["certificate"]=results ["certificate"]


        try :
            data ["apk_size_bytes"]=os .path .getsize (self .apk_path )
            data ["apk_size_mb"]=round (data ["apk_size_bytes"]/(1024 *1024 ),2 )
        except Exception as e :
            self .log (f"Failed to get APK size: {e }",level ="WARN")


        data ["analysis_duration_seconds"]=round (time .time ()-self .analysis_start_time ,2 )

        return data 

    def run (self )->Path :
        self .log (f"Starting comprehensive analysis of {self .apk_path }")
        start_time =time .time ()

        try :
            static =self .extract_static ()

            report ={
            "timestamp":self .timestamp ,
            "apk":self .apk_path ,
            "package":self .package_name ,
            "static":static ,
            "dynamic":{"executed":False },
            "network":{"observed_endpoints":static .get ("domains",[])},
            "behavior":{},
            "analysis_duration":round (time .time ()-start_time ,2 ),
            }

            json_path =self .output_dir /"comprehensive_report.json"
            json_path .write_text (json .dumps (report ,ensure_ascii =False ,indent =2 ),encoding ="utf-8")


            txt_path =self .output_dir /"analysis_report.txt"
            with txt_path .open ("w",encoding ="utf-8")as f :
                f .write (f"APK Analysis Report\n{'='*80 }\n\n")
                f .write (f"APK: {self .apk_path }\n")
                f .write (f"Package: {self .package_name }\n")
                f .write (f"Timestamp: {self .timestamp }\n")
                f .write (f"Analysis Duration: {report ['analysis_duration']} seconds\n\n")


                if "badging"in static :
                    f .write (f"APK Information\n{'-'*80 }\n")
                    badging =static ["badging"]
                    f .write (f"App Name: {badging .get ('app_name','Unknown')}\n")
                    f .write (f"Version: {badging .get ('version_name','Unknown')} (code: {badging .get ('version_code','Unknown')})\n")
                    f .write (f"Min SDK: {badging .get ('min_sdk','Unknown')}\n")
                    f .write (f"Target SDK: {badging .get ('target_sdk','Unknown')}\n")
                    f .write (f"APK Size: {static .get ('apk_size_mb','Unknown')} MB\n\n")


                if "badging"in static and "permissions"in static ["badging"]:
                    f .write (f"Permissions\n{'-'*80 }\n")
                    for perm in static ["badging"]["permissions"]:
                        f .write (f"- {perm }\n")
                    f .write ("\n")


                domains =report ["network"]["observed_endpoints"]
                f .write (f"Network Endpoints\n{'-'*80 }\n")
                if domains :
                    for domain in domains :
                        f .write (f"- {domain }\n")
                else :
                    f .write ("No network endpoints detected.\n")
                f .write ("\n")


                if "certificate"in static :
                    f .write (f"Certificate Information\n{'-'*80 }\n")
                    cert =static ["certificate"]
                    f .write (f"Owner: {cert .get ('owner','Unknown')}\n")
                    f .write (f"Issuer: {cert .get ('issuer','Unknown')}\n")
                    f .write (f"Valid From: {cert .get ('valid_from','Unknown')}\n")
                    f .write (f"Valid To: {cert .get ('valid_to','Unknown')}\n\n")

            self .log (f"Analysis completed successfully. Reports written to {self .output_dir }")
            return json_path 

        except Exception as e :
            self .log (f"Analysis failed: {e }",level ="ERROR")
            self .log (traceback .format_exc (),level ="DEBUG")
            error_report ={
            "timestamp":self .timestamp ,
            "apk":self .apk_path ,
            "package":self .package_name ,
            "error":str (e ),
            "error_type":type (e ).__name__ ,
            }
            error_path =self .output_dir /"error_report.json"
            error_path .write_text (json .dumps (error_report ,ensure_ascii =False ,indent =2 ),encoding ="utf-8")
            return error_path 


def parse_args ()->AnalysisConfig :
    parser =argparse .ArgumentParser (description ="Enhanced APK Analysis Tool")
    parser .add_argument ("apk_path",help ="Path to the APK file")
    parser .add_argument ("package_name",help ="Package name of the APK")
    parser .add_argument ("-o","--output-dir",help ="Custom output directory")
    parser .add_argument ("-t","--timeout",type =int ,default =180 ,help ="Command timeout in seconds (default: 180)")
    parser .add_argument ("--skip-permissions",action ="store_true",help ="Skip permission analysis")
    parser .add_argument ("--skip-resources",action ="store_true",help ="Skip resource analysis")
    parser .add_argument ("--skip-strings",action ="store_true",help ="Skip strings analysis")
    parser .add_argument ("--skip-cert",action ="store_true",help ="Skip certificate analysis")
    parser .add_argument ("-v","--verbose",action ="store_true",help ="Enable verbose logging")
    parser .add_argument ("-w","--workers",type =int ,default =4 ,help ="Number of worker threads (default: 4)")

    args =parser .parse_args ()

    return AnalysisConfig (
    apk_path =args .apk_path ,
    package_name =args .package_name ,
    output_dir =args .output_dir ,
    timeout =args .timeout ,
    analyze_permissions =not args .skip_permissions ,
    analyze_resources =not args .skip_resources ,
    analyze_strings =not args .skip_strings ,
    analyze_cert =not args .skip_cert ,
    verbose =args .verbose ,
    max_workers =args .workers 
    )


def main ()->None :
    try :
        if len (sys .argv )>1 and sys .argv [1 ]in ["-h","--help"]:

            config =parse_args ()
        elif len (sys .argv )<3 :
            print ("Usage: python3 enhanced_data_extractor.py <apk_path> <package_name> [options]",file =sys .stderr )
            print ("Example: python3 enhanced_data_extractor.py apps.apk com.xnotice.app",file =sys .stderr )
            print ("Run with --help for more options",file =sys .stderr )
            sys .exit (2 )
        else :
            config =parse_args ()

        if not os .path .exists (config .apk_path ):
            print (f"APK not found: {config .apk_path }",file =sys .stderr )
            sys .exit (2 )

        EnhancedDataExtractor (config ).run ()

    except KeyboardInterrupt :
        print ("\nAnalysis interrupted by user.",file =sys .stderr )
        sys .exit (1 )
    except Exception as e :
        print (f"Error: {e }",file =sys .stderr )
        if "--verbose"in sys .argv or "-v"in sys .argv :
            traceback .print_exc ()
        sys .exit (1 )


if __name__ =="__main__":
    main ()
