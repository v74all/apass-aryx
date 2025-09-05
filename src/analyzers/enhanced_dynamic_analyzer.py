#!/usr/bin/env python3

import sys 
import os 
import json 
import time 
import subprocess 
import threading 
import hashlib 
import base64 
import sqlite3 
from pathlib import Path 
from datetime import datetime ,timedelta 
from typing import Dict ,List ,Optional ,Any ,Set ,Tuple 
from collections import defaultdict ,deque 
from dataclasses import dataclass ,asdict 
from concurrent .futures import ThreadPoolExecutor 
import frida 
import re 
import psutil 
from rich .console import Console 
from rich .table import Table 
from rich .progress import Progress ,BarColumn ,TextColumn ,TimeElapsedColumn 
from rich .live import Live 
from rich .layout import Layout 
from rich .panel import Panel 

@dataclass 
class ThreatIndicator :
    id :str 
    type :str 
    severity :str 
    confidence :float 
    description :str 
    timestamp :str 
    evidence :Dict [str ,Any ]
    risk_score :int 

@dataclass 
class PerformanceMetrics :
    cpu_usage :float 
    memory_usage :float 
    network_io :Tuple [int ,int ]
    disk_io :Tuple [int ,int ]
    timestamp :str 

class ConfigManager :

    DEFAULT_CONFIG ={
    'monitoring':{
    'api_rate_limit':1000 ,
    'memory_dump_threshold':50 ,
    'network_timeout':30 ,
    'file_watch_paths':['/data/data/','/sdcard/','/system/'],
    'crypto_algorithms_blacklist':['DES','MD5','SHA1','RC4']
    },
    'detection':{
    'evasion_techniques':True ,
    'code_injection':True ,
    'privilege_escalation':True ,
    'data_exfiltration':True ,
    'c2_communication':True 
    },
    'scoring':{
    'base_weights':{
    'api_abuse':0.25 ,
    'network_suspicious':0.20 ,
    'file_operations':0.15 ,
    'crypto_weak':0.10 ,
    'behavior_malicious':0.30 
    },
    'severity_multipliers':{
    'critical':4.0 ,
    'high':3.0 ,
    'medium':2.0 ,
    'low':1.0 
    }
    },
    'output':{
    'formats':['json','html','csv','xml'],
    'include_screenshots':True ,
    'memory_dumps':False ,
    'detailed_logs':True 
    }
    }

    def __init__ (self ,config_path :Optional [str ]=None ):
        self .config =self .DEFAULT_CONFIG .copy ()
        if config_path and Path (config_path ).exists ():
            self .load_config (config_path )

    def load_config (self ,config_path :str ):
        try :
            with open (config_path ,'r')as f :
                user_config =json .load (f )
            self ._merge_config (self .config ,user_config )
        except Exception as e :
            print (f"[-] Warning: Failed to load config: {e }")

    def _merge_config (self ,base :dict ,override :dict ):
        for key ,value in override .items ():
            if key in base and isinstance (base [key ],dict )and isinstance (value ,dict ):
                self ._merge_config (base [key ],value )
            else :
                base [key ]=value 

class AdvancedThreatDetector :

    def __init__ (self ,config :ConfigManager ):
        self .config =config 
        self .indicators =[]
        self .behavior_patterns =defaultdict (list )
        self .time_series_data =defaultdict (deque )
        self .anomaly_baseline ={}

    def analyze_api_sequence (self ,api_calls :List [Dict ])->List [ThreatIndicator ]:
        indicators =[]


        priv_esc_pattern =['getSystemService','checkCallingPermission','Runtime.exec']
        if self ._detect_sequence_pattern (api_calls ,priv_esc_pattern ):
            indicators .append (ThreatIndicator (
            id =f"priv_esc_{int (time .time ())}",
            type ="privilege_escalation",
            severity ="high",
            confidence =0.85 ,
            description ="Detected privilege escalation attempt via API sequence",
            timestamp =datetime .now ().isoformat (),
            evidence ={'pattern':priv_esc_pattern ,'calls':len (api_calls )},
            risk_score =75 
            ))


        exfil_pattern =['getDeviceId','getSubscriberId','sendTextMessage']
        if self ._detect_sequence_pattern (api_calls ,exfil_pattern ):
            indicators .append (ThreatIndicator (
            id =f"data_exfil_{int (time .time ())}",
            type ="data_exfiltration",
            severity ="critical",
            confidence =0.90 ,
            description ="Detected potential data exfiltration pattern",
            timestamp =datetime .now ().isoformat (),
            evidence ={'pattern':exfil_pattern ,'calls':len (api_calls )},
            risk_score =90 
            ))

        return indicators 

    def _detect_sequence_pattern (self ,api_calls :List [Dict ],pattern :List [str ])->bool :
        api_names =[call .get ('api','')for call in api_calls ]
        pattern_index =0 

        for api_name in api_names :
            if pattern_index <len (pattern )and pattern [pattern_index ]in api_name :
                pattern_index +=1 
                if pattern_index ==len (pattern ):
                    return True 
        return False 

    def analyze_network_behavior (self ,network_events :List [Dict ])->List [ThreatIndicator ]:
        indicators =[]


        connection_freq =defaultdict (int )
        for event in network_events :
            host =event .get ('host','')
            if host :
                connection_freq [host ]+=1 


        for host ,freq in connection_freq .items ():
            if freq >10 :
                indicators .append (ThreatIndicator (
                id =f"c2_comm_{hash (host )}",
                type ="c2_communication",
                severity ="high",
                confidence =min (0.6 +(freq /100 ),0.95 ),
                description =f"High frequency connections to {host } ({freq } connections)",
                timestamp =datetime .now ().isoformat (),
                evidence ={'host':host ,'frequency':freq },
                risk_score =min (60 +freq ,95 )
                ))

        return indicators 

    def analyze_temporal_patterns (self ,events :List [Dict ])->List [ThreatIndicator ]:
        indicators =[]


        event_groups =defaultdict (list )
        for event in events :
            event_type =event .get ('type','unknown')
            timestamp =event .get ('timestamp',time .time ())
            event_groups [event_type ].append (timestamp )


        for event_type ,timestamps in event_groups .items ():
            if len (timestamps )>50 :
                time_diffs =[timestamps [i +1 ]-timestamps [i ]for i in range (len (timestamps )-1 )]
                avg_interval =sum (time_diffs )/len (time_diffs )if time_diffs else 0 

                if avg_interval <0.1 :
                    indicators .append (ThreatIndicator (
                    id =f"rapid_events_{event_type }_{int (time .time ())}",
                    type ="evasion_technique",
                    severity ="medium",
                    confidence =0.70 ,
                    description =f"Rapid {event_type } events detected (avg: {avg_interval :.3f}s)",
                    timestamp =datetime .now ().isoformat (),
                    evidence ={'event_type':event_type ,'count':len (timestamps ),'avg_interval':avg_interval },
                    risk_score =55 
                    ))

        return indicators 

class PerformanceMonitor :

    def __init__ (self ):
        self .metrics_history =deque (maxlen =1000 )
        self .monitoring =False 
        self .monitor_thread =None 

    def start_monitoring (self ,interval :float =1.0 ):
        self .monitoring =True 
        self .monitor_thread =threading .Thread (target =self ._monitor_loop ,args =(interval ,))
        self .monitor_thread .daemon =True 
        self .monitor_thread .start ()

    def stop_monitoring (self ):
        self .monitoring =False 
        if self .monitor_thread :
            self .monitor_thread .join (timeout =2.0 )

    def _monitor_loop (self ,interval :float ):
        while self .monitoring :
            try :
                cpu_percent =psutil .cpu_percent (interval =0.1 )
                memory_info =psutil .virtual_memory ()
                net_io =psutil .net_io_counters ()
                disk_io =psutil .disk_io_counters ()

                metrics =PerformanceMetrics (
                cpu_usage =cpu_percent ,
                memory_usage =memory_info .percent ,
                network_io =(net_io .bytes_sent ,net_io .bytes_recv )if net_io else (0 ,0 ),
                disk_io =(disk_io .read_bytes ,disk_io .write_bytes )if disk_io else (0 ,0 ),
                timestamp =datetime .now ().isoformat ()
                )

                self .metrics_history .append (metrics )
                time .sleep (interval )

            except Exception as e :
                print (f"Performance monitoring error: {e }")
                time .sleep (interval )

    def get_current_metrics (self )->Optional [PerformanceMetrics ]:
        return self .metrics_history [-1 ]if self .metrics_history else None 

    def get_average_metrics (self )->Dict [str ,float ]:
        if not self .metrics_history :
            return {}

        cpu_avg =sum (m .cpu_usage for m in self .metrics_history )/len (self .metrics_history )
        mem_avg =sum (m .memory_usage for m in self .metrics_history )/len (self .metrics_history )

        return {
        'cpu_average':cpu_avg ,
        'memory_average':mem_avg ,
        'sample_count':len (self .metrics_history )
        }

class EnhancedDynamicAnalyzer :

    def __init__ (self ,device_id :str =None ,config_path :str =None ):
        self .device_id =device_id 
        self .device =None 
        self .session =None 
        self .script =None 
        self .console =Console ()


        self .config =ConfigManager (config_path )
        self .threat_detector =AdvancedThreatDetector (self .config )
        self .performance_monitor =PerformanceMonitor ()


        self .analysis_id =None 
        self .output_dir =None 
        self .start_time =None 
        self .duration =0 
        self .current_package =None 
        self .analysis_status ="idle"


        self .events =deque (maxlen =10000 )
        self .events_lock =threading .Lock ()
        self .api_calls =deque (maxlen =5000 )
        self .network_activity =deque (maxlen =2000 )
        self .file_operations =deque (maxlen =2000 )
        self .crypto_operations =deque (maxlen =1000 )
        self .behavior_patterns =deque (maxlen =1000 )
        self .memory_analysis_data ={}


        self .stats ={
        'events_per_second':0 ,
        'total_events':0 ,
        'api_calls_count':0 ,
        'network_requests':0 ,
        'file_operations_count':0 ,
        'crypto_operations_count':0 ,
        'threat_indicators_count':0 
        }


        self .results ={
        'metadata':{
        'analyzer_version':'5.0',
        'timestamp':datetime .now ().isoformat (),
        'device_id':device_id ,
        'duration_seconds':0 ,
        'config_checksum':self ._get_config_checksum ()
        },
        'runtime_info':{},
        'performance_metrics':{},
        'behavioral_summary':{},
        'threat_indicators':[],
        'advanced_patterns':{},
        'threat_score':0 ,
        'confidence_score':0 ,
        'iocs':{
        'network':[],
        'file':[],
        'crypto':[],
        'command':[],
        'registry':[],
        'process':[]
        },
        'timeline':[],
        'statistics':{}
        }


        self .frida_script =self .load_frida_script ()
        self .aux_scripts =self .load_aux_scripts ()
        self .device_external_dump_dir =None 
        self .local_dump_dir =None 

    def _get_config_checksum (self )->str :
        config_str =json .dumps (self .config .config ,sort_keys =True )
        return hashlib .sha256 (config_str .encode ()).hexdigest ()[:16 ]

    def load_frida_script (self )->str :

        script_path =Path (__file__ ).parent .parent .parent /"scripts"/"frida"/"comprehensive_analysis.js"
        if not script_path .exists ():

            script_path =Path (__file__ ).parent .parent .parent /"scripts"/"frida"/"advanced_malware_analyzer.js"

        if not script_path .exists ():
            raise FileNotFoundError (f"Frida script not found at {script_path }")

        with open (script_path ,'r')as f :
            return f .read ()

    def load_aux_scripts (self )->dict :
        base =Path (__file__ ).parent .parent .parent /"scripts"/"frida"
        scripts ={}
        for name in ["dex_dumper.js","bypass_dlopen.js","crypto_file_bypass_dump.js"]:
            p =base /name 
            if p .exists ():
                scripts [name ]=p .read_text ()
        return scripts 

    def connect_device (self )->bool :
        try :
            if self .device_id :
                self .device =frida .get_device (self .device_id )
            else :

                devices =frida .enumerate_devices ()
                usb_devices =[d for d in devices if d .type =='usb']
                if usb_devices :
                    self .device =usb_devices [0 ]
                else :

                    emulator_devices =[d for d in devices if 'emulator'in d .name .lower ()]
                    if emulator_devices :
                        self .device =emulator_devices [0 ]
                    else :
                        print ("[-] No suitable device found")
                        return False 

            print (f"[+] Connected to device: {self .device .name }")
            return True 

        except Exception as e :
            print (f"[-] Failed to connect to device: {e }")
            return False 

    def install_and_launch_app (self ,apk_path :str ,package_name :str )->bool :
        try :

            resolved_pkg =self .get_apk_package_name (apk_path )or package_name 
            if not resolved_pkg :
                print ("[-] Unable to determine package name from APK")
                return False 
            self .current_package =resolved_pkg 


            print (f"[*] Installing APK: {Path (apk_path ).name }")
            install_result =subprocess .run ([
            'adb','install','-r',apk_path 
            ],capture_output =True ,text =True ,timeout =60 )

            if install_result .returncode !=0 :
                print (f"[-] APK installation failed: {install_result .stderr }")
                return False 

            print (f"[+] APK installed successfully")


            print (f"[*] Launching application: {resolved_pkg }")
            launch_result =subprocess .run ([
            'adb','shell','monkey','-p',resolved_pkg ,'-c',
            'android.intent.category.LAUNCHER','1'
            ],capture_output =True ,text =True ,timeout =30 )

            if launch_result .returncode !=0 :

                main_activity =self .get_apk_launchable_activity (apk_path )
                if main_activity :

                    pkg_for_activity =resolved_pkg 
                    if main_activity .startswith ('.'):
                        cls =main_activity 
                    elif '.'in main_activity :

                        pkg_for_activity =main_activity .rsplit ('.',1 )[0 ]
                        cls =main_activity 
                    else :
                        cls =main_activity 
                    component =f"{pkg_for_activity }/{cls }"
                    print (f"[*] Fallback launch via am start: {component }")
                    am_result =subprocess .run ([
                    'adb','shell','am','start','-n',component 
                    ],capture_output =True ,text =True ,timeout =30 )
                    if am_result .returncode !=0 :
                        print (f"[-] Failed to launch via am: {am_result .stderr or am_result .stdout }")
                        return False 
                else :
                    print (f"[-] Failed to launch application: {launch_result .stderr or launch_result .stdout }")
                    return False 

            print (f"[+] Application launched successfully")
            time .sleep (3 )

            return True 

        except Exception as e :
            print (f"[-] Failed to install/launch app: {e }")
            return False 

    def get_apk_package_name (self ,apk_path :str )->Optional [str ]:
        try :
            result =subprocess .run ([
            'aapt','dump','badging',apk_path 
            ],capture_output =True ,text =True ,timeout =20 )
            if result .returncode ==0 :
                m =re .search (r"package: name='([^']+)'",result .stdout )
                if m :
                    return m .group (1 )
        except Exception :
            pass 
        return None 

    def get_apk_launchable_activity (self ,apk_path :str )->Optional [str ]:
        try :
            result =subprocess .run ([
            'aapt','dump','badging',apk_path 
            ],capture_output =True ,text =True ,timeout =20 )
            if result .returncode ==0 :
                m =re .search (r"launchable-activity: name='([^']+)'",result .stdout )
                if m :
                    return m .group (1 )
        except Exception :
            pass 
        return None 

    def attach_to_app (self ,package_name :str )->bool :
        max_retries =3 
        retry_delay =2.0 

        for attempt in range (max_retries ):
            try :
                target_package =self .current_package or package_name 
                self .console .print (f"[cyan][*] Attaching to application: {target_package } (attempt {attempt +1 })[/cyan]")


                applications =self .device .enumerate_applications ()
                target_app =None 

                for app in applications :
                    if app .identifier ==target_package :
                        target_app =app 
                        break 

                if not target_app :
                    self .console .print (f"[red][-] Application not found: {target_package }[/red]")
                    if attempt <max_retries -1 :
                        time .sleep (retry_delay )
                        continue 
                    return False 


                self .session =self .device .attach (target_app .pid )
                self .console .print (f"[green][+] Attached to PID: {target_app .pid }[/green]")


                self .console .print (f"[cyan][*] Injecting enhanced Frida script...[/cyan]")

                self .script =self .session .create_script (self .frida_script )


                self .script .on ('message',self .on_message )


                self .script .load ()


                for aux_name ,aux_src in self .aux_scripts .items ():
                    try :
                        aux =self .session .create_script (aux_src )
                        aux .on ('message',self .on_message )
                        aux .load ()
                        self .console .print (f"[green][+] Loaded aux script {aux_name }[/green]")
                    except Exception as e :
                        self .console .print (f"[yellow][!] Failed to load aux script {aux_name }: {e }[/yellow]")


                try :

                    test_result =self .script .exports .test_functionality ()
                    if test_result .get ('status')!='ok':
                        raise Exception (f"Script functionality test failed: {test_result }")
                except Exception as e :
                    self .console .print (f"[yellow][!] Script test warning: {e }[/yellow]")

                self .console .print (f"[green][+] Enhanced Frida script loaded successfully[/green]")
                return True 

            except frida .ProcessNotFoundError :
                self .console .print (f"[red][-] Process not found for {target_package }[/red]")
                if attempt <max_retries -1 :
                    time .sleep (retry_delay )
                    continue 
                return False 
            except frida .ServerNotRunningError :
                self .console .print (f"[red][-] Frida server not running on device[/red]")
                return False 
            except Exception as e :
                self .console .print (f"[red][-] Attachment failed (attempt {attempt +1 }): {e }[/red]")
                if attempt <max_retries -1 :
                    time .sleep (retry_delay )
                    continue 
                return False 

        return False 

    def on_message (self ,message ,data ):
        if message ['type']=='error':
            self .console .print (f"[bold red][FRIDA ERROR][/bold red] {message .get ('description','No description')}")

            self ._log_error (message )
            return 

        if message ['type']=='send':
            try :
                event =json .loads (message ['payload'])


                with self .events_lock :
                    self .events .append (event )
                    self .stats ['total_events']+=1 


                self ._categorize_event (event )


                self ._real_time_threat_analysis (event )


                self .process_event (event )


                if event .get ('type')=='dump_saved':
                    path =event .get ('payload',{}).get ('path')
                    if path :

                        from pathlib import PurePosixPath 
                        try :
                            p =PurePosixPath (path )
                            self .device_external_dump_dir =str (p .parent )
                        except Exception :
                            pass 

            except json .JSONDecodeError as e :
                self .console .print (f"[yellow][FRIDA RAW][/yellow] {message ['payload']}")

                self ._log_malformed_message (message ['payload'])
            except Exception as e :
                self .console .print (f"[red]Error processing Frida message: {e }[/red]")

    def _log_error (self ,message :Dict [str ,Any ]):
        try :
            errs =self .results .setdefault ('frida_errors',[])
            errs .append ({
            'description':message .get ('description'),
            'stack':message .get ('stack'),
            'fileName':message .get ('fileName'),
            'lineNumber':message .get ('lineNumber')
            })
        except Exception :
            pass 

    def _log_malformed_message (self ,payload :str ):
        try :
            raws =self .results .setdefault ('frida_raw_messages',[])
            if len (raws )<50 :
                raws .append (payload )
        except Exception :
            pass 

    def _categorize_event (self ,event :Dict ):
        event_type =event .get ('type')

        if event_type =='api_call':
            self .api_calls .append (event )
            self .stats ['api_calls_count']+=1 
        elif event_type =='network':
            self .network_activity .append (event )
            self .stats ['network_requests']+=1 
        elif event_type =='file_access':
            self .file_operations .append (event )
            self .stats ['file_operations_count']+=1 
        elif event_type =='crypto':
            self .crypto_operations .append (event )
            self .stats ['crypto_operations_count']+=1 
        elif event_type in ['behavior','pattern']:
            self .behavior_patterns .append (event )

    def _real_time_threat_analysis (self ,event :Dict ):
        try :

            event_type =event .get ('type')
            payload =event .get ('payload',{})


            if event_type =='api_call':
                api_name =payload .get ('api','')
                if any (keyword in api_name .lower ()for keyword in ['su','root','admin','superuser']):
                    self ._add_threat_indicator (
                    type ="privilege_escalation",
                    severity ="high",
                    description =f"Potential privilege escalation via {api_name }",
                    evidence =payload 
                    )


            elif event_type =='network':
                url =payload .get ('url','')
                if any (suspicious in url .lower ()for suspicious in ['.onion','.tk','.ml']):
                    self ._add_threat_indicator (
                    type ="suspicious_network",
                    severity ="medium",
                    description =f"Connection to suspicious domain: {url }",
                    evidence =payload 
                    )

        except Exception as e :
            self .console .print (f"[red]Real-time threat analysis error: {e }[/red]")

    def _add_threat_indicator (self ,type :str ,severity :str ,description :str ,evidence :Dict ):
        indicator =ThreatIndicator (
        id =f"{type }_{int (time .time ())}_{hash (description )%10000 }",
        type =type ,
        severity =severity ,
        confidence =0.8 ,
        description =description ,
        timestamp =datetime .now ().isoformat (),
        evidence =evidence ,
        risk_score =self ._calculate_indicator_risk_score (severity ,type )
        )

        self .threat_detector .indicators .append (indicator )
        self .stats ['threat_indicators_count']+=1 

    def process_event (self ,event :Dict ):
        event_type =event .get ('type')
        payload =event .get ('payload',{})


        self .print_event (event )


        if event_type =='network':
            url =payload .get ('url')
            if url and url not in self .results ['iocs']['network']:
                self .results ['iocs']['network'].append (url )
        elif event_type =='file_access':
            path =payload .get ('path')
            if path and path not in self .results ['iocs']['file']:
                self .results ['iocs']['file'].append (path )
        elif event_type =='crypto':
            algo =payload .get ('transformation')or payload .get ('algorithm')
            if algo and algo not in self .results ['iocs']['crypto']:
                self .results ['iocs']['crypto'].append (algo )
        elif event_type =='command':
            cmd =payload .get ('command')
            if cmd and cmd not in self .results ['iocs']['command']:
                self .results ['iocs']['command'].append (cmd )

    def print_event (self ,event :Dict ):
        event_type =event .get ('type','unknown').upper ()
        payload =event .get ('payload',{})

        color_map ={
        'INFO':'cyan',
        'CRYPTO':'magenta',
        'FILE_ACCESS':'yellow',
        'NETWORK':'blue',
        'COMMAND':'red',
        'CODE_LOADING':'purple',
        'INTENT':'green',
        'WEBVIEW':'dark_orange',
        'EVASION':'bold red',
        }
        color =color_map .get (event_type ,'white')

        msg =f"[[{color }]{event_type }[/{color }]] "
        details =", ".join (f"[b]{k }[/b]={v }"for k ,v in payload .items ()if k !='stack')
        self .console .print (f"{msg }{details }")

        if 'stack'in payload :
            self .console .print (f"[dim]{payload ['stack']}[/dim]")

    def collect_monitoring_data (self ):
        pass 

    def perform_memory_analysis (self ):
        try :
            print (f"[*] Performing memory analysis...")


            patterns =[
            "41 50 4b",
            "64 65 78",
            "50 4b 03 04",
            "4d 5a",
            "7f 45 4c 46"
            ]

            memory_findings =[]

            for pattern in patterns :
                try :
                    results =self .script .exports .search_memory (pattern )
                    if results and not results .get ('error'):
                        memory_findings .append ({
                        'pattern':pattern ,
                        'matches':len (results ),
                        'addresses':results [:10 ]
                        })
                except Exception :
                    continue 

            self .results ['memory_analysis']['patterns']=memory_findings 


            if memory_findings :
                print (f"[+] Found {len (memory_findings )} suspicious memory patterns")

        except Exception as e :
            print (f"[-] Memory analysis failed: {e }")

    def analyze_behavior (self ):
        print (f"[*] Analyzing application behavior...")


        api_analysis =self .analyze_api_calls ()
        self .results ['api_monitoring']=api_analysis 


        network_analysis =self .analyze_network_activity ()
        self .results ['network_analysis']=network_analysis 


        file_analysis =self .analyze_file_operations ()
        self .results ['file_analysis']=file_analysis 


        crypto_analysis =self .analyze_crypto_operations ()
        self .results ['crypto_analysis']=crypto_analysis 


        behavior_analysis =self .analyze_behavior_patterns ()
        self .results ['behavior_analysis']=behavior_analysis 


        self .results ['threat_indicators']=self .generate_threat_indicators ()


        self .results ['threat_score']=self .calculate_threat_score ()

    def analyze_api_calls (self )->Dict [str ,Any ]:
        analysis ={
        'total_calls':len (self .api_calls ),
        'unique_apis':len (set (call ['api']for call in self .api_calls )),
        'api_categories':{},
        'suspicious_apis':[],
        'call_frequency':{}
        }


        categories ={
        'network':['java.net','okhttp','ConnectivityManager'],
        'file':['java.io.File','FileOutputStream','FileInputStream'],
        'crypto':['javax.crypto','MessageDigest','KeyGenerator'],
        'system':['Runtime.exec','ProcessBuilder','Process.kill'],
        'privacy':['TelephonyManager','LocationManager','AccountManager'],
        'communication':['SmsManager','TelecomManager'],
        'browser':['WebView']
        }

        for call in self .api_calls :
            api =call ['api']


            for category ,keywords in categories .items ():
                if any (keyword in api for keyword in keywords ):
                    analysis ['api_categories'][category ]=analysis ['api_categories'].get (category ,0 )+1 


            analysis ['call_frequency'][api ]=analysis ['call_frequency'].get (api ,0 )+1 


        suspicious_keywords =['exec','kill','su','root','admin']
        for call in self .api_calls :
            if any (keyword in call ['api'].lower ()for keyword in suspicious_keywords ):
                analysis ['suspicious_apis'].append (call )

        return analysis 

    def analyze_network_activity (self )->Dict [str ,Any ]:
        analysis ={
        'total_connections':len (self .network_activity ),
        'unique_hosts':set (),
        'connection_types':{},
        'suspicious_connections':[],
        'domains':[]
        }

        for activity in self .network_activity :
            conn_type =activity .get ('type','unknown')
            analysis ['connection_types'][conn_type ]=analysis ['connection_types'].get (conn_type ,0 )+1 


            if activity .get ('url'):
                try :
                    from urllib .parse import urlparse 
                    parsed =urlparse (activity ['url'])
                    if parsed .hostname :
                        analysis ['unique_hosts'].add (parsed .hostname )
                        analysis ['domains'].append (parsed .hostname )
                except :
                    pass 

            elif activity .get ('address'):

                addr =activity ['address']
                if '/'in addr :
                    host =addr .split ('/')[0 ]
                    analysis ['unique_hosts'].add (host )
                    analysis ['domains'].append (host )

        analysis ['unique_hosts']=list (analysis ['unique_hosts'])


        suspicious_tlds =['.tk','.ml','.ga','.cf','.onion']
        for domain in analysis ['domains']:
            if any (domain .endswith (tld )for tld in suspicious_tlds ):
                analysis ['suspicious_connections'].append ({
                'domain':domain ,
                'reason':'suspicious_tld'
                })

        return analysis 

    def analyze_file_operations (self )->Dict [str ,Any ]:
        analysis ={
        'total_operations':len (self .file_operations ),
        'read_operations':0 ,
        'write_operations':0 ,
        'accessed_files':set (),
        'suspicious_files':[],
        'file_patterns':{}
        }

        for op in self .file_operations :
            op_type =op .get ('type','unknown')
            filename =op .get ('filename','')


            if 'read'in op_type :
                analysis ['read_operations']+=1 
            elif 'write'in op_type :
                analysis ['write_operations']+=1 


            if filename :
                analysis ['accessed_files'].add (filename )


                suspicious_patterns =[
                '/data/local/tmp/',
                '/sdcard/',
                '.so',
                '.dex',
                '.apk',
                '/system/',
                '/root/'
                ]

                for pattern in suspicious_patterns :
                    if pattern in filename :
                        analysis ['suspicious_files'].append ({
                        'filename':filename ,
                        'pattern':pattern ,
                        'operation':op_type 
                        })


                        analysis ['file_patterns'][pattern ]=analysis ['file_patterns'].get (pattern ,0 )+1 

        analysis ['accessed_files']=list (analysis ['accessed_files'])

        return analysis 

    def analyze_crypto_operations (self )->Dict [str ,Any ]:
        analysis ={
        'total_operations':len (self .crypto_operations ),
        'cipher_operations':0 ,
        'hash_operations':0 ,
        'algorithms':{},
        'suspicious_crypto':[]
        }

        for op in self .crypto_operations :
            op_type =op .get ('type','unknown')
            algorithm =op .get ('algorithm','unknown')


            if 'cipher'in op_type :
                analysis ['cipher_operations']+=1 
            elif 'hash'in op_type :
                analysis ['hash_operations']+=1 


            analysis ['algorithms'][algorithm ]=analysis ['algorithms'].get (algorithm ,0 )+1 


            weak_algorithms =['DES','MD5','SHA1']
            if any (weak in algorithm for weak in weak_algorithms ):
                analysis ['suspicious_crypto'].append ({
                'algorithm':algorithm ,
                'reason':'weak_algorithm',
                'operation':op_type 
                })

        return analysis 

    def analyze_behavior_patterns (self )->Dict [str ,Any ]:
        analysis ={
        'total_patterns':len (self .behavior_patterns ),
        'severity_counts':{},
        'pattern_types':{},
        'timeline':[]
        }

        for pattern in self .behavior_patterns :
            pattern_type =pattern .get ('type','unknown')
            severity =pattern .get ('severity','unknown')


            analysis ['severity_counts'][severity ]=analysis ['severity_counts'].get (severity ,0 )+1 


            analysis ['pattern_types'][pattern_type ]=analysis ['pattern_types'].get (pattern_type ,0 )+1 


            analysis ['timeline'].append ({
            'timestamp':pattern .get ('timestamp'),
            'type':pattern_type ,
            'severity':severity ,
            'description':pattern .get ('command',pattern .get ('description',''))
            })


        analysis ['timeline'].sort (key =lambda x :x .get ('timestamp',''))

        return analysis 

    def generate_threat_indicators (self )->List [Dict [str ,str ]]:
        indicators =[]


        api_analysis =self .results .get ('api_monitoring',{})
        if api_analysis .get ('suspicious_apis'):
            indicators .append ({
            'type':'suspicious_api_usage',
            'description':f"Detected {len (api_analysis ['suspicious_apis'])} suspicious API calls",
            'severity':'high'
            })


        network_analysis =self .results .get ('network_analysis',{})
        if network_analysis .get ('suspicious_connections'):
            indicators .append ({
            'type':'suspicious_network',
            'description':f"Connections to {len (network_analysis ['suspicious_connections'])} suspicious domains",
            'severity':'medium'
            })


        file_analysis =self .results .get ('file_analysis',{})
        if file_analysis .get ('suspicious_files'):
            indicators .append ({
            'type':'suspicious_file_access',
            'description':f"Access to {len (file_analysis ['suspicious_files'])} suspicious files",
            'severity':'medium'
            })


        crypto_analysis =self .results .get ('crypto_analysis',{})
        if crypto_analysis .get ('suspicious_crypto'):
            indicators .append ({
            'type':'weak_crypto',
            'description':f"Usage of {len (crypto_analysis ['suspicious_crypto'])} weak crypto algorithms",
            'severity':'low'
            })


        behavior_analysis =self .results .get ('behavior_analysis',{})
        severity_counts =behavior_analysis .get ('severity_counts',{})

        if severity_counts .get ('high',0 )>0 :
            indicators .append ({
            'type':'high_risk_behavior',
            'description':f"Detected {severity_counts ['high']} high-risk behaviors",
            'severity':'critical'
            })

        return indicators 

    def calculate_threat_score (self )->int :
        score =0 


        api_analysis =self .results .get ('api_monitoring',{})
        score +=min (len (api_analysis .get ('suspicious_apis',[]))*5 ,25 )


        network_analysis =self .results .get ('network_analysis',{})
        score +=min (len (network_analysis .get ('suspicious_connections',[]))*3 ,15 )


        file_analysis =self .results .get ('file_analysis',{})
        score +=min (len (file_analysis .get ('suspicious_files',[]))*2 ,10 )


        crypto_analysis =self .results .get ('crypto_analysis',{})
        score +=min (len (crypto_analysis .get ('suspicious_crypto',[])),10 )


        behavior_analysis =self .results .get ('behavior_analysis',{})
        severity_counts =behavior_analysis .get ('severity_counts',{})

        score +=severity_counts .get ('critical',0 )*20 
        score +=severity_counts .get ('high',0 )*10 
        score +=severity_counts .get ('medium',0 )*5 
        score +=severity_counts .get ('low',0 )*2 

        return min (score ,100 )

    def run_analysis (self ,apk_path :str ,package_name :str ,duration :int ,
    output_dir :str ,analysis_id :str )->bool :
        self .output_dir =Path (output_dir )
        self .analysis_id =analysis_id 
        self .duration =duration 
        self .start_time =datetime .now ()
        self .analysis_status ="running"

        self .results ['metadata']['duration_seconds']=duration 
        resolved_pkg =self .get_apk_package_name (apk_path )or package_name 
        self .current_package =resolved_pkg 
        self .results ['metadata']['package_name']=resolved_pkg 


        self .performance_monitor .start_monitoring (interval =2.0 )

        try :
            with Progress (
            TextColumn ("[progress.description]{task.description}"),
            BarColumn (),
            TextColumn ("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn (),
            console =self .console 
            )as progress :


                setup_task =progress .add_task ("[cyan]Setting up analysis...",total =4 )


                progress .update (setup_task ,description ="[cyan]Connecting to device...")
                if not self .connect_device ():
                    return False 
                progress .advance (setup_task )


                progress .update (setup_task ,description ="[cyan]Installing and launching app...")
                if not self .install_and_launch_app (apk_path ,resolved_pkg ):
                    return False 
                progress .advance (setup_task )


                progress .update (setup_task ,description ="[cyan]Attaching Frida instrumentation...")
                if not self .attach_to_app (resolved_pkg ):
                    return False 
                progress .advance (setup_task )


                progress .update (setup_task ,description ="[cyan]Starting behavioral monitoring...")
                progress .advance (setup_task )


                monitor_task =progress .add_task ("[green]Monitoring application behavior...",total =duration )

                start_time =time .time ()
                last_stats_update =start_time 

                while time .time ()-start_time <duration :
                    elapsed =time .time ()-start_time 
                    progress .update (monitor_task ,completed =int (elapsed ))


                    if time .time ()-last_stats_update >=5 :
                        self ._update_statistics ()
                        self ._display_live_stats ()
                        last_stats_update =time .time ()


                    if self .stats ['threat_indicators_count']>10 :
                        self .console .print ("[bold red]⚠️  High number of threat indicators detected![/bold red]")

                    time .sleep (1 )

                progress .update (monitor_task ,completed =duration )


                analysis_task =progress .add_task ("[yellow]Analyzing collected data...",total =5 )


                progress .update (analysis_task ,description ="[yellow]Performing memory analysis...")
                self .perform_enhanced_memory_analysis ()
                progress .advance (analysis_task )


                progress .update (analysis_task ,description ="[yellow]Running advanced threat detection...")
                self .perform_advanced_threat_detection ()
                progress .advance (analysis_task )


                progress .update (analysis_task ,description ="[yellow]Analyzing behavior patterns...")
                self .analyze_behavior ()
                progress .advance (analysis_task )


                progress .update (analysis_task ,description ="[yellow]Generating comprehensive report...")
                self .generate_comprehensive_timeline ()
                progress .advance (analysis_task )


                progress .update (analysis_task ,description ="[yellow]Saving analysis results...")
                self .save_enhanced_results ()
                progress .advance (analysis_task )

            self .analysis_status ="completed"
            self ._display_final_summary ()

            return True 

        except KeyboardInterrupt :
            self .console .print ("[yellow][!] Analysis interrupted by user[/yellow]")
            self .analysis_status ="interrupted"
            return False 
        except Exception as e :
            self .console .print (f"[red][-] Dynamic analysis failed: {e }[/red]")
            self .analysis_status ="failed"
            return False 

        finally :

            self .performance_monitor .stop_monitoring ()

            try :
                self ._pull_device_dumps ()
            except Exception as e :
                self .console .print (f"[yellow][!] Pull dumps failed: {e }[/yellow]")
            self ._cleanup_analysis ()

    def _ensure_local_dump_dir (self )->Path :
        if not self .output_dir :
            return Path ('analysis_results_dumps')
        d =Path (self .output_dir )/'artifacts'/'decrypted'
        d .mkdir (parents =True ,exist_ok =True )
        self .local_dump_dir =str (d )
        return d 

    def _pull_device_dumps (self ):
        if not self .device_external_dump_dir :
            return 
        local_dir =self ._ensure_local_dump_dir ()

        try :
            ls =subprocess .run (['adb','shell','ls','-1',self .device_external_dump_dir ],capture_output =True ,text =True ,timeout =15 )
            if ls .returncode !=0 :
                return 
            for line in ls .stdout .splitlines ():
                name =line .strip ()
                if not name :
                    continue 
                remote =f"{self .device_external_dump_dir }/{name }"
                subprocess .run (['adb','pull',remote ,str (local_dir )],capture_output =True ,text =True ,timeout =60 )
        except Exception :
            pass 

    def _update_statistics (self ):
        current_time =time .time ()
        elapsed =current_time -time .mktime (self .start_time .timetuple ())

        if elapsed >0 :
            self .stats ['events_per_second']=self .stats ['total_events']/elapsed 


        current_metrics =self .performance_monitor .get_current_metrics ()
        if current_metrics :
            self .results ['performance_metrics']['current']=asdict (current_metrics )

    def _display_live_stats (self ):
        table =Table (title ="Live Analysis Statistics",show_header =True )
        table .add_column ("Metric",style ="cyan")
        table .add_column ("Value",style ="green")

        table .add_row ("Total Events",str (self .stats ['total_events']))
        table .add_row ("Events/Second",f"{self .stats ['events_per_second']:.2f}")
        table .add_row ("API Calls",str (self .stats ['api_calls_count']))
        table .add_row ("Network Requests",str (self .stats ['network_requests']))
        table .add_row ("File Operations",str (self .stats ['file_operations_count']))
        table .add_row ("Threat Indicators",str (self .stats ['threat_indicators_count']))


        current_metrics =self .performance_monitor .get_current_metrics ()
        if current_metrics :
            table .add_row ("CPU Usage",f"{current_metrics .cpu_usage :.1f}%")
            table .add_row ("Memory Usage",f"{current_metrics .memory_usage :.1f}%")

        self .console .print (table )

    def perform_enhanced_memory_analysis (self ):
        try :
            self .console .print ("[cyan][*] Performing enhanced memory analysis...[/cyan]")

            memory_results ={
            'heap_analysis':{},
            'code_regions':{},
            'suspicious_patterns':[],
            'dynamic_loading':[],
            'memory_protections':{}
            }


            enhanced_patterns ={
            'executables':['4d 5a','7f 45 4c 46'],
            'archives':['50 4b 03 04','1f 8b 08'],
            'android_specific':['64 65 78 0a','41 50 4b'],
            'encryption':['53 61 6c 74 65 64 5f 5f'],
            'urls':['68 74 74 70 3a 2f 2f','68 74 74 70 73 3a 2f 2f']
            }

            for category ,patterns in enhanced_patterns .items ():
                category_findings =[]
                for pattern in patterns :
                    try :
                        results =self .script .exports .enhanced_memory_search (pattern ,category )
                        if results and isinstance (results ,list ):
                            category_findings .extend (results )
                    except Exception as e :
                        self .console .print (f"[yellow][!] Memory search warning for {pattern }: {e }[/yellow]")

                if category_findings :
                    memory_results ['suspicious_patterns'].append ({
                    'category':category ,
                    'matches':len (category_findings ),
                    'samples':category_findings [:5 ]
                    })


            try :
                heap_info =self .script .exports .analyze_heap ()
                if heap_info :
                    memory_results ['heap_analysis']=heap_info 
            except Exception as e :
                self .console .print (f"[yellow][!] Heap analysis warning: {e }[/yellow]")


            try :
                dynamic_code =self .script .exports .detect_dynamic_loading ()
                if dynamic_code :
                    memory_results ['dynamic_loading']=dynamic_code 
            except Exception as e :
                self .console .print (f"[yellow][!] Dynamic loading detection warning: {e }[/yellow]")

            self .results ['memory_analysis']=memory_results 

            if memory_results ['suspicious_patterns']:
                self .console .print (f"[green][+] Found {len (memory_results ['suspicious_patterns'])} categories of suspicious patterns[/green]")

        except Exception as e :
            self .console .print (f"[red][-] Enhanced memory analysis failed: {e }[/red]")

    def perform_advanced_threat_detection (self ):
        try :
            self .console .print ("[cyan][*] Running advanced threat detection...[/cyan]")

            all_indicators =[]


            api_indicators =self .threat_detector .analyze_api_sequence (list (self .api_calls ))
            all_indicators .extend (api_indicators )


            network_indicators =self .threat_detector .analyze_network_behavior (list (self .network_activity ))
            all_indicators .extend (network_indicators )


            temporal_indicators =self .threat_detector .analyze_temporal_patterns (list (self .events ))
            all_indicators .extend (temporal_indicators )


            behavioral_indicators =self ._analyze_advanced_behavioral_patterns ()
            all_indicators .extend (behavioral_indicators )


            self .results ['threat_indicators']=[asdict (indicator )for indicator in all_indicators ]
            self .results ['advanced_patterns']=self ._generate_advanced_pattern_report ()

            self .console .print (f"[green][+] Generated {len (all_indicators )} threat indicators[/green]")

        except Exception as e :
            self .console .print (f"[red][-] Advanced threat detection failed: {e }[/red]")

    def _display_final_summary (self ):
        self .console .print ("\n"+"="*60 )
        self .console .print ("[bold cyan]ENHANCED DYNAMIC ANALYSIS COMPLETE[/bold cyan]")
        self .console .print ("="*60 )


        summary_table =Table (title ="Analysis Summary",show_header =True )
        summary_table .add_column ("Metric",style ="cyan")
        summary_table .add_column ("Value",style ="green")
        summary_table .add_column ("Status",style ="yellow")

        threat_score =self .results ['threat_score']
        risk_level =self .get_risk_level (threat_score )
        confidence =self .results ['confidence_score']

        summary_table .add_row ("Package",self .current_package or "Unknown","✓")
        summary_table .add_row ("Duration",f"{self .duration }s","✓")
        summary_table .add_row ("Events Collected",str (self .stats ['total_events']),"✓")
        summary_table .add_row ("Threat Score",f"{threat_score }/100",self ._get_status_emoji (threat_score ))
        summary_table .add_row ("Risk Level",risk_level ,self ._get_risk_emoji (risk_level ))
        summary_table .add_row ("Confidence",f"{confidence :.1f}%","✓")
        summary_table .add_row ("Threat Indicators",str (len (self .results ['threat_indicators'])),"⚠️"if len (self .results ['threat_indicators'])>5 else "✓")

        self .console .print (summary_table )


        avg_metrics =self .performance_monitor .get_average_metrics ()
        if avg_metrics :
            perf_table =Table (title ="Performance Summary",show_header =True )
            perf_table .add_column ("Resource",style ="cyan")
            perf_table .add_column ("Average Usage",style ="green")

            perf_table .add_row ("CPU",f"{avg_metrics .get ('cpu_average',0 ):.1f}%")
            perf_table .add_row ("Memory",f"{avg_metrics .get ('memory_average',0 ):.1f}%")
            perf_table .add_row ("Samples",str (avg_metrics .get ('sample_count',0 )))

            self .console .print (perf_table )

        self .console .print (f"\n[green][+] Results saved to: {self .output_dir }[/green]")

    def _calculate_indicator_risk_score (self ,severity :str ,indicator_type :str )->int :
        base_score =50 
        multiplier =self .config .config ['scoring']['severity_multipliers'].get (severity ,1.0 )
        return int (base_score *multiplier )

    def generate_comprehensive_timeline (self ):
        timeline =[]
        for event in self .events :
            timeline .append ({
            'timestamp':event .get ('timestamp',datetime .now ().isoformat ()),
            'type':event .get ('type'),
            'details':event .get ('payload')
            })
        self .results ['timeline']=sorted (timeline ,key =lambda x :x ['timestamp'])

    def save_enhanced_results (self ):
        if not self .output_dir :
            return 
        output_file =self .output_dir /f"{self .analysis_id }_results.json"
        with open (output_file ,'w')as f :
            json .dump (self .results ,f ,indent =2 )

    def get_risk_level (self ,score :int )->str :
        if score >=80 :
            return "Critical"
        elif score >=60 :
            return "High"
        elif score >=40 :
            return "Medium"
        elif score >=20 :
            return "Low"
        else :
            return "Safe"

    def _get_status_emoji (self ,score :int )->str :
        if score >70 :
            return "🔴"
        elif score >40 :
            return "🟡"
        else :
            return "🟢"

    def _get_risk_emoji (self ,level :str )->str :
        emojis ={"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢","Safe":"🟢"}
        return emojis .get (level ,"❓")

    def _cleanup_analysis (self ):
        if self .session :
            try :
                self .session .detach ()
            except Exception :
                pass 
        self .session =None 
        self .script =None 

def main ():
    if len (sys .argv )<3 :
        print ("Usage: enhanced_dynamic_analyzer.py <apk_path> <package_name> [-d duration] [-o output_dir] [--device-id id]")
        return 1 

    apk_path =sys .argv [1 ]
    package_name =sys .argv [2 ]
    duration =60 
    output_dir ="dynamic_analysis_output"
    device_id =None 


    for i ,arg in enumerate (sys .argv [3 :],3 ):
        if arg =="-d"and i +1 <len (sys .argv ):
            duration =int (sys .argv [i +1 ])
        elif arg =="-o"and i +1 <len (sys .argv ):
            output_dir =sys .argv [i +1 ]
        elif arg =="--device-id"and i +1 <len (sys .argv ):
            device_id =sys .argv [i +1 ]


    analyzer =EnhancedDynamicAnalyzer (device_id )
    analysis_id =f"dynamic_{datetime .now ().strftime ('%Y%m%d_%H%M%S')}"
    success =analyzer .run_analysis (apk_path ,package_name ,duration ,output_dir ,analysis_id )

    return 0 if success else 1 


if __name__ =="__main__":
    sys .exit (main ())
