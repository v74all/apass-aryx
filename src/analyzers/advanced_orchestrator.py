#!/usr/bin/env python3

import os 
import sys 
import subprocess 
import time 
import json 
import argparse 
import threading 
import logging 
import hashlib 
import yaml 
import asyncio 
import concurrent .futures 
from pathlib import Path 
from datetime import datetime ,timedelta 
from typing import Dict ,List ,Optional ,Tuple 
from dataclasses import dataclass ,asdict 
from queue import Queue 

@dataclass 
class ThreatIndicator :
    source :str 
    category :str 
    description :str 
    severity :str 
    confidence :float 
    timestamp :str 
    iocs :List [str ]=None 

@dataclass 
class AnalysisConfig :
    analysis_duration :int =300 
    max_parallel_tools :int =4 
    enable_real_time_monitoring :bool =True 
    threat_intelligence_enabled :bool =True 
    auto_cleanup :bool =True 
    advanced_correlation :bool =True 
    generate_yara_rules :bool =True 
    memory_dump_analysis :bool =True 

class RealTimeMonitor :
    def __init__ (self ,orchestrator ):
        self .orchestrator =orchestrator 
        self .alerts_queue =Queue ()
        self .monitoring_active =False 
        self .alert_thresholds ={
        'high_risk_api_calls':10 ,
        'network_connections':20 ,
        'file_operations':50 ,
        'process_injections':1 
        }

    def start_monitoring (self ):
        self .monitoring_active =True 
        monitor_thread =threading .Thread (target =self ._monitor_loop )
        monitor_thread .daemon =True 
        monitor_thread .start ()

    def stop_monitoring (self ):
        self .monitoring_active =False 

    def _monitor_loop (self ):
        while self .monitoring_active :
            try :

                self ._check_critical_indicators ()
                time .sleep (5 )
            except Exception as e :
                logging .error (f"Monitoring error: {e }")

    def _check_critical_indicators (self ):

        try :
            result =subprocess .run (['adb','logcat','-d','-s','ActivityManager'],
            capture_output =True ,text =True ,timeout =10 )
            if result .returncode ==0 :
                self ._analyze_logcat_output (result .stdout )
        except :
            pass 

    def _analyze_logcat_output (self ,logcat_output ):
        critical_keywords =['permission','root','su','exploit','shell']
        for line in logcat_output .split ('\n'):
            if any (keyword in line .lower ()for keyword in critical_keywords ):
                alert ={
                'type':'system_activity',
                'severity':'medium',
                'message':f"Suspicious system activity: {line [:100 ]}",
                'timestamp':datetime .now ().isoformat ()
                }
                self .alerts_queue .put (alert )

class ThreatIntelligence :
    def __init__ (self ):
        self .malware_databases ={
        'virustotal':'https://www.virustotal.com/vtapi/v2/',
        'abuse_ch':'https://urlhaus-api.abuse.ch/v1/',
        }

    async def check_hash_reputation (self ,file_hash :str )->Dict :

        return {
        'known_malware':False ,
        'detection_ratio':0 ,
        'first_seen':None ,
        'last_seen':None ,
        'threat_names':[]
        }

    async def check_domain_reputation (self ,domain :str )->Dict :

        return {
        'malicious':False ,
        'category':'unknown',
        'risk_score':0 ,
        'first_seen':None 
        }

class AdvancedScoring :
    def __init__ (self ):
        self .weights ={
        'static_analysis':0.25 ,
        'dynamic_analysis':0.35 ,
        'memory_analysis':0.20 ,
        'network_analysis':0.20 
        }

        self .severity_scores ={
        'critical':10 ,
        'high':7 ,
        'medium':4 ,
        'low':1 
        }

    def calculate_threat_score (self ,threats :List [ThreatIndicator ])->Dict :
        if not threats :
            return {'overall_score':0 ,'risk_level':'minimal','breakdown':{}}

        category_scores ={}
        total_weighted_score =0 


        for threat in threats :
            source =threat .source 
            if source not in category_scores :
                category_scores [source ]=0 

            severity_score =self .severity_scores .get (threat .severity ,1 )
            confidence_factor =threat .confidence /100.0 
            category_scores [source ]+=severity_score *confidence_factor 


        for source ,score in category_scores .items ():
            weight =self .weights .get (source ,0.1 )
            total_weighted_score +=score *weight 


        overall_score =min (100 ,total_weighted_score *5 )

        risk_level =self ._determine_risk_level (overall_score )

        return {
        'overall_score':round (overall_score ,2 ),
        'risk_level':risk_level ,
        'breakdown':category_scores ,
        'threat_count':len (threats ),
        'confidence_avg':sum (t .confidence for t in threats )/len (threats )
        }

    def _determine_risk_level (self ,score :float )->str :
        if score >=80 :
            return 'critical'
        elif score >=60 :
            return 'high'
        elif score >=30 :
            return 'medium'
        elif score >=10 :
            return 'low'
        else :
            return 'minimal'

class MalwareAnalysisOrchestrator :
    def __init__ (self ,apk_path :str ,package_name :str ,config :AnalysisConfig =None ):
        self .apk_path =apk_path 
        self .package_name =package_name 
        self .config =config or AnalysisConfig ()


        self .analysis_dir =Path ('advanced_analysis_'+datetime .now ().strftime ('%Y%m%d_%H%M%S'))
        self .analysis_dir .mkdir (exist_ok =True )
        self ._setup_logging ()


        self .real_time_monitor =RealTimeMonitor (self )if self .config .enable_real_time_monitoring else None 
        self .threat_intel =ThreatIntelligence ()if self .config .threat_intelligence_enabled else None 
        self .scoring_engine =AdvancedScoring ()

        self .tools ={
        'static':{
        'path':'advanced_static_analyzer.py',
        'status':'pending',
        'output':None 
        },
        'dynamic_comprehensive':{
        'path':'advanced_malware_analyzer.js',
        'status':'pending',
        'process':None 
        },
        'memory_analysis':{
        'path':'memory_analyzer.js',
        'status':'pending',
        'process':None 
        },
        'network_analysis':{
        'path':'network_analyzer.js',
        'status':'pending',
        'process':None 
        }
        }

        self .results ={
        'metadata':{
        'start_time':datetime .now ().isoformat (),
        'apk_path':apk_path ,
        'package_name':package_name ,
        'analysis_id':self .analysis_dir .name ,
        'config':asdict (self .config )
        },
        'static_analysis':{},
        'dynamic_analysis':{},
        'memory_analysis':{},
        'network_analysis':{},
        'consolidated_threats':[],
        'threat_score':{},
        'real_time_alerts':[],
        'threat_intelligence':{},
        'recommendations':[],
        'yara_rules':[],
        'timeline':[]
        }

    def _setup_logging (self ):
        log_file =self .analysis_dir /'orchestrator.log'
        logging .basicConfig (
        level =logging .INFO ,
        format ='%(asctime)s - %(levelname)s - %(message)s',
        handlers =[
        logging .FileHandler (log_file ),
        logging .StreamHandler (sys .stdout )
        ]
        )
        self .logger =logging .getLogger (__name__ )

    def check_prerequisites (self ):
        self .logger .info ("Checking prerequisites...")

        required_commands =['adb','frida','python3']
        missing =[]

        for cmd in required_commands :
            try :
                result =subprocess .run (['which',cmd ],capture_output =True ,text =True ,timeout =10 )
                if result .returncode !=0 :
                    missing .append (cmd )
            except subprocess .TimeoutExpired :
                self .logger .error (f"Timeout checking {cmd }")
                missing .append (cmd )

        if missing :
            self .logger .error (f"Missing required tools: {', '.join (missing )}")
            return False 


        try :
            result =subprocess .run (['adb','devices'],capture_output =True ,text =True ,timeout =10 )
            if 'device'not in result .stdout :
                self .logger .error ("No Android device connected")
                return False 
        except subprocess .TimeoutExpired :
            self .logger .error ("Timeout checking adb devices")
            return False 


        try :
            result =subprocess .run (['frida-ps','-U'],capture_output =True ,text =True ,timeout =10 )
            if result .returncode !=0 :
                self .logger .error ("Frida server not running on device")
                return False 
        except subprocess .TimeoutExpired :
            self .logger .error ("Timeout checking frida-ps")
            return False 

        self .logger .info ("All prerequisites met")
        return True 

    def run_static_analysis (self ):
        self .logger .info ("Starting static analysis...")

        try :
            cmd =[
            'python3',self .tools ['static']['path'],
            self .apk_path ,
            '-o',str (self .analysis_dir /'static')
            ]

            result =subprocess .run (cmd ,capture_output =True ,text =True ,timeout =300 )

            if result .returncode ==0 :
                self .tools ['static']['status']='completed'
                self .logger .info ("Static analysis completed")


                static_dir =self .analysis_dir /'static'
                if static_dir .exists ():
                    json_files =list (static_dir .glob ('static_analysis_*.json'))
                    if json_files :
                        with open (json_files [0 ])as f :
                            self .results ['static_analysis']=json .load (f )
            else :
                self .tools ['static']['status']='failed'
                self .logger .error (f"Static analysis failed: {result .stderr }")

        except subprocess .TimeoutExpired :
            self .tools ['static']['status']='timeout'
            self .logger .error ("Static analysis timed out")
        except Exception as e :
            self .tools ['static']['status']='error'
            self .logger .error (f"Static analysis error: {e }")

    def start_dynamic_analysis (self ):
        self .logger .info ("Starting dynamic analysis...")


        try :
            cmd =[
            'frida','-U','-f',self .package_name ,
            '-l',self .tools ['dynamic_comprehensive']['path'],
            '--no-pause'
            ]

            process =subprocess .Popen (
            cmd ,
            stdout =subprocess .PIPE ,
            stderr =subprocess .PIPE ,
            text =True 
            )

            self .tools ['dynamic_comprehensive']['process']=process 
            self .tools ['dynamic_comprehensive']['status']='running'
            self .logger .info ("Comprehensive dynamic analysis started")

        except Exception as e :
            self .logger .error (f"Failed to start dynamic analysis: {e }")
            self .tools ['dynamic_comprehensive']['status']='failed'

    def start_memory_analysis (self ):
        self .logger .info ("Starting memory analysis...")


        time .sleep (10 )

        try :
            cmd =[
            'frida','-U',self .package_name ,
            '-l',self .tools ['memory_analysis']['path']
            ]

            process =subprocess .Popen (
            cmd ,
            stdout =subprocess .PIPE ,
            stderr =subprocess .PIPE ,
            text =True 
            )

            self .tools ['memory_analysis']['process']=process 
            self .tools ['memory_analysis']['status']='running'
            self .logger .info ("Memory analysis started")

        except Exception as e :
            self .logger .error (f"Failed to start memory analysis: {e }")
            self .tools ['memory_analysis']['status']='failed'

    def start_network_analysis (self ):
        self .logger .info ("Starting network analysis...")


        time .sleep (15 )

        try :
            cmd =[
            'frida','-U',self .package_name ,
            '-l',self .tools ['network_analysis']['path']
            ]

            process =subprocess .Popen (
            cmd ,
            stdout =subprocess .PIPE ,
            stderr =subprocess .PIPE ,
            text =True 
            )

            self .tools ['network_analysis']['process']=process 
            self .tools ['network_analysis']['status']='running'
            self .logger .info ("Network analysis started")

        except Exception as e :
            self .logger .error (f"Failed to start network analysis: {e }")
            self .tools ['network_analysis']['status']='failed'

    def monitor_processes (self ):
        self .logger .info ("Monitoring analysis processes...")

        analysis_duration =self .config .analysis_duration 
        start_time =time .time ()

        while time .time ()-start_time <analysis_duration :
            time .sleep (10 )


            for tool_name ,tool_info in self .tools .items ():
                if 'process'in tool_info and tool_info ['process']:
                    process =tool_info ['process']

                    if process .poll ()is not None :

                        if process .returncode ==0 :
                            tool_info ['status']='completed'
                            self .logger .info (f"{tool_name } analysis completed")
                        else :
                            tool_info ['status']='failed'
                            self .logger .error (f"{tool_name } analysis failed")
                        tool_info ['process']=None 


            running_count =sum (1 for t in self .tools .values ()if t ['status']=='running')
            self .logger .info (f"Analysis running... {running_count } active processes")

        self .logger .info ("Analysis time limit reached, stopping processes...")
        self .stop_all_processes ()

    def stop_all_processes (self ):
        for tool_name ,tool_info in self .tools .items ():
            if 'process'in tool_info and tool_info ['process']:
                try :
                    tool_info ['process'].terminate ()
                    tool_info ['process'].wait (timeout =10 )
                    tool_info ['status']='stopped'
                    self .logger .info (f"Stopped {tool_name } process")
                except :
                    tool_info ['process'].kill ()
                    tool_info ['status']='killed'
                    self .logger .info (f"Killed {tool_name } process")

    def collect_results (self ):
        self .logger .info ("Collecting analysis results...")


        device_storage_paths =[
        '/storage/emulated/0/Android/data/'+self .package_name +'/files/',
        '/sdcard/Download/',
        '/storage/emulated/0/Download/'
        ]


        for storage_path in device_storage_paths :
            try :

                result =subprocess .run ([
                'adb','shell','ls',storage_path 
                ],capture_output =True ,text =True )

                if result .returncode ==0 :
                    files =result .stdout .strip ().split ('\n')


                    analysis_files =[f for f in files if any (keyword in f for keyword in [
                    'comprehensive_analysis','memory_analysis','network_analysis',
                    'malware_analysis','advanced_analysis'
                    ])]


                    for file in analysis_files :
                        if file .strip ():
                            self .pull_file_from_device (storage_path +file ,file )

            except Exception as e :
                self .logger .warning (f"Error collecting from {storage_path }: {e }")

    def pull_file_from_device (self ,device_path ,local_filename ):
        try :
            local_path =self .analysis_dir /local_filename 
            result =subprocess .run ([
            'adb','pull',device_path ,str (local_path )
            ],capture_output =True ,text =True )

            if result .returncode ==0 :
                self .logger .info (f"Pulled: {local_filename }")


                if local_filename .endswith ('.json'):
                    try :
                        with open (local_path )as f :
                            data =json .load (f )

                        if 'comprehensive'in local_filename :
                            self .results ['dynamic_analysis']=data 
                        elif 'memory'in local_filename :
                            self .results ['memory_analysis']=data 
                        elif 'network'in local_filename :
                            self .results ['network_analysis']=data 

                    except Exception as e :
                        self .logger .warning (f"Failed to parse {local_filename }: {e }")

            else :
                self .logger .error (f"Failed to pull {device_path }: {result .stderr }")

        except Exception as e :
            self .logger .warning (f"Error pulling {device_path }: {e }")

    def consolidate_findings (self ):
        self .logger .info ("Consolidating analysis findings...")

        threats =[]


        if 'threat_indicators'in self .results ['static_analysis']:
            for threat in self .results ['static_analysis']['threat_indicators']:
                threats .append ({
                'source':'static',
                'type':'capability',
                'description':threat ,
                'severity':'medium'
                })


        if 'threats'in self .results ['dynamic_analysis']:
            dynamic_threats =self .results ['dynamic_analysis']['threats']
            for category ,threat_list in dynamic_threats .items ():
                for threat in threat_list :
                    threats .append ({
                    'source':'dynamic',
                    'type':category ,
                    'description':str (threat ),
                    'severity':'high'
                    })


        if 'payloads'in self .results ['memory_analysis']:
            suspicious_payloads =self .results ['memory_analysis']['payloads'].get ('suspicious',[])
            for payload in suspicious_payloads :
                threats .append ({
                'source':'memory',
                'type':'payload',
                'description':f"Suspicious payload: {payload .get ('identifier','unknown')}",
                'severity':'high'
                })


        if 'threats'in self .results ['network_analysis']:
            network_threats =self .results ['network_analysis']['threats']
            for category ,threat_list in network_threats .items ():
                for threat in threat_list :
                    threats .append ({
                    'source':'network',
                    'type':category ,
                    'description':str (threat ),
                    'severity':'high'
                    })

        self .results ['consolidated_threats']=threats 


        self .generate_recommendations ()

    def generate_recommendations (self ):
        recommendations =[]

        threat_count =len (self .results ['consolidated_threats'])
        high_severity_count =len ([t for t in self .results ['consolidated_threats']if t ['severity']=='high'])

        if threat_count >10 :
            recommendations .append ("HIGH RISK: This sample shows multiple threat indicators across all analysis methods")
            recommendations .append ("Recommend immediate containment and detailed forensic analysis")
        elif threat_count >5 :
            recommendations .append ("MEDIUM RISK: Multiple suspicious behaviors detected")
            recommendations .append ("Monitor closely and consider additional analysis")
        else :
            recommendations .append ("LOW RISK: Limited threat indicators detected")

        if high_severity_count >0 :
            recommendations .append (f"Detected {high_severity_count } high-severity threats requiring immediate attention")


        if any (t ['source']=='network'for t in self .results ['consolidated_threats']):
            recommendations .append ("Block identified malicious domains and IP addresses")
            recommendations .append ("Monitor network traffic for similar communication patterns")

        if any (t ['source']=='memory'for t in self .results ['consolidated_threats']):
            recommendations .append ("Implement additional memory protection mechanisms")
            recommendations .append ("Consider advanced anti-evasion techniques")

        self .results ['recommendations']=recommendations 

    def generate_final_report (self ):
        self .logger .info ("Generating final report...")

        self .results ['metadata']['end_time']=datetime .now ().isoformat ()


        json_report_path =self .analysis_dir /'consolidated_analysis_report.json'
        with open (json_report_path ,'w')as f :
            json .dump (self .results ,f ,indent =2 )


        text_report_path =self .analysis_dir /'analysis_summary_report.txt'
        self .generate_text_report (text_report_path )


        ioc_report_path =self .analysis_dir /'consolidated_iocs.txt'
        self .generate_ioc_report (ioc_report_path )

        self .logger .info (f"Final reports generated in: {self .analysis_dir }")
        self .logger .info (f"    JSON Report: {json_report_path }")
        self .logger .info (f"    Summary Report: {text_report_path }")
        self .logger .info (f"    IOC Report: {ioc_report_path }")

    def generate_text_report (self ,output_path ):
        with open (output_path ,'w')as f :
            f .write ("="*80 +"\n")
            f .write ("ADVANCED MALWARE ANALYSIS REPORT\n")
            f .write ("="*80 +"\n\n")

            f .write (f"Analysis ID: {self .results ['metadata']['analysis_id']}\n")
            f .write (f"Target APK: {self .apk_path }\n")
            f .write (f"Package: {self .package_name }\n")
            f .write (f"Analysis Start: {self .results ['metadata']['start_time']}\n")
            f .write (f"Analysis End: {self .results ['metadata']['end_time']}\n\n")


            f .write ("ANALYSIS TOOLS STATUS\n")
            f .write ("-"*30 +"\n")
            for tool_name ,tool_info in self .tools .items ():
                f .write (f"  {tool_name }: {tool_info ['status']}\n")
            f .write ("\n")


            f .write ("THREAT SUMMARY\n")
            f .write ("-"*20 +"\n")
            f .write (f"Total threats detected: {len (self .results ['consolidated_threats'])}\n")

            severity_counts ={}
            for threat in self .results ['consolidated_threats']:
                severity =threat ['severity']
                severity_counts [severity ]=severity_counts .get (severity ,0 )+1 

            for severity ,count in severity_counts .items ():
                f .write (f"  {severity .upper ()}: {count }\n")
            f .write ("\n")


            f .write ("RECOMMENDATIONS\n")
            f .write ("-"*20 +"\n")
            for i ,rec in enumerate (self .results ['recommendations'],1 ):
                f .write (f"{i }. {rec }\n")
            f .write ("\n")


            if self .results ['consolidated_threats']:
                f .write ("DETAILED THREAT ANALYSIS\n")
                f .write ("-"*30 +"\n")
                for i ,threat in enumerate (self .results ['consolidated_threats'],1 ):
                    f .write (f"{i }. [{threat ['source'].upper ()}] {threat ['description']}\n")
                    f .write (f"   Severity: {threat ['severity'].upper ()}\n")
                    f .write (f"   Type: {threat ['type']}\n\n")

    def generate_ioc_report (self ,output_path ):
        with open (output_path ,'w')as f :
            f .write (f"# Consolidated IOCs - {datetime .now ().isoformat ()}\n\n")


            f .write ("## Package Information\n")
            f .write (f"{self .package_name }\n\n")


            if 'metadata'in self .results ['static_analysis']and 'file_hashes'in self .results ['static_analysis']['metadata']:
                f .write ("## File Hashes\n")
                for algo ,hash_val in self .results ['static_analysis']['metadata']['file_hashes'].items ():
                    f .write (f"{algo .upper ()}: {hash_val }\n")
                f .write ("\n")


            network_domains =set ()
            network_ips =set ()

            if 'artifacts'in self .results ['network_analysis']:
                artifacts =self .results ['network_analysis']['artifacts']
                for domain in artifacts .get ('domains',[]):
                    network_domains .add (domain ['value'])
                for ip in artifacts .get ('ips',[]):
                    network_ips .add (ip ['value'])

            if network_domains :
                f .write ("## Domains\n")
                for domain in sorted (network_domains ):
                    f .write (f"{domain }\n")
                f .write ("\n")

            if network_ips :
                f .write ("## IP Addresses\n")
                for ip in sorted (network_ips ):
                    f .write (f"{ip }\n")
                f .write ("\n")

    async def run_parallel_analysis (self ):
        self .logger .info ("Starting parallel analysis execution")

        tasks =[]


        tasks .append (self ._run_async_static_analysis ())


        await asyncio .sleep (10 )


        if self .config .max_parallel_tools >1 :
            tasks .extend ([
            self ._run_async_dynamic_analysis (),
            self ._run_async_memory_analysis (),
            self ._run_async_network_analysis ()
            ])
        else :

            await self ._run_async_dynamic_analysis ()
            await self ._run_async_memory_analysis ()
            await self ._run_async_network_analysis ()


        if tasks :
            results =await asyncio .gather (*tasks ,return_exceptions =True )


            for i ,result in enumerate (results ):
                if isinstance (result ,Exception ):
                    self .logger .error (f"Task {i } failed: {result }")

    async def _run_async_static_analysis (self ):
        loop =asyncio .get_event_loop ()
        with concurrent .futures .ThreadPoolExecutor ()as executor :
            await loop .run_in_executor (executor ,self .run_static_analysis )

    async def _run_async_dynamic_analysis (self ):
        loop =asyncio .get_event_loop ()
        with concurrent .futures .ThreadPoolExecutor ()as executor :
            await loop .run_in_executor (executor ,self .start_dynamic_analysis )

    async def _run_async_memory_analysis (self ):
        await asyncio .sleep (15 )
        loop =asyncio .get_event_loop ()
        with concurrent .futures .ThreadPoolExecutor ()as executor :
            await loop .run_in_executor (executor ,self .start_memory_analysis )

    async def _run_async_network_analysis (self ):
        await asyncio .sleep (20 )
        loop =asyncio .get_event_loop ()
        with concurrent .futures .ThreadPoolExecutor ()as executor :
            await loop .run_in_executor (executor ,self .start_network_analysis )

    def enhanced_consolidate_findings (self ):
        self .logger .info ("Performing enhanced threat consolidation")

        threats =[]
        timeline_events =[]


        if 'threat_indicators'in self .results ['static_analysis']:
            for threat_data in self .results ['static_analysis']['threat_indicators']:
                threat =ThreatIndicator (
                source ='static',
                category ='capability',
                description =str (threat_data ),
                severity ='medium',
                confidence =75.0 ,
                timestamp =datetime .now ().isoformat ()
                )
                threats .append (threat )


        if 'threats'in self .results ['dynamic_analysis']:
            for category ,threat_list in self .results ['dynamic_analysis']['threats'].items ():
                for threat_data in threat_list :
                    severity =self ._determine_dynamic_threat_severity (category ,threat_data )
                    confidence =self ._calculate_threat_confidence (threat_data )

                    threat =ThreatIndicator (
                    source ='dynamic',
                    category =category ,
                    description =str (threat_data ),
                    severity =severity ,
                    confidence =confidence ,
                    timestamp =datetime .now ().isoformat ()
                    )
                    threats .append (threat )


        if 'payloads'in self .results ['memory_analysis']:
            for payload in self .results ['memory_analysis']['payloads'].get ('suspicious',[]):
                threat =ThreatIndicator (
                source ='memory',
                category ='payload',
                description =f"Suspicious payload: {payload .get ('identifier','unknown')}",
                severity ='high',
                confidence =85.0 ,
                timestamp =datetime .now ().isoformat (),
                iocs =[payload .get ('identifier','')]
                )
                threats .append (threat )


        if 'threats'in self .results ['network_analysis']:
            for category ,threat_list in self .results ['network_analysis']['threats'].items ():
                for threat_data in threat_list :
                    threat =ThreatIndicator (
                    source ='network',
                    category =category ,
                    description =str (threat_data ),
                    severity ='high',
                    confidence =90.0 ,
                    timestamp =datetime .now ().isoformat ()
                    )
                    threats .append (threat )


        if self .config .advanced_correlation :
            threats =self ._correlate_threats (threats )


        self .results ['threat_score']=self .scoring_engine .calculate_threat_score (threats )
        self .results ['consolidated_threats']=[asdict (t )for t in threats ]


        self .generate_enhanced_recommendations (threats )


        if self .config .generate_yara_rules :
            self .generate_yara_rules (threats )

    def _determine_dynamic_threat_severity (self ,category :str ,threat_data )->str :
        high_risk_categories =['code_injection','process_manipulation','privilege_escalation']
        medium_risk_categories =['network_communication','file_operations']

        if category in high_risk_categories :
            return 'high'
        elif category in medium_risk_categories :
            return 'medium'
        else :
            return 'low'

    def _calculate_threat_confidence (self ,threat_data )->float :

        confidence =70.0 


        if isinstance (threat_data ,dict ):
            if 'confidence'in threat_data :
                confidence =threat_data ['confidence']
            elif 'certainty'in threat_data :
                confidence =threat_data ['certainty']

        return min (100.0 ,max (0.0 ,confidence ))

    def _correlate_threats (self ,threats :List [ThreatIndicator ])->List [ThreatIndicator ]:

        time_windows ={}

        for threat in threats :
            timestamp =datetime .fromisoformat (threat .timestamp .replace ('Z','+00:00'))
            window_key =timestamp .replace (second =0 ,microsecond =0 )

            if window_key not in time_windows :
                time_windows [window_key ]=[]
            time_windows [window_key ].append (threat )


        correlated_threats =[]

        for window_threats in time_windows .values ():
            if len (window_threats )>3 :

                for threat in window_threats :
                    threat .confidence =min (100.0 ,threat .confidence *1.2 )

            correlated_threats .extend (window_threats )

        return correlated_threats 

    def generate_enhanced_recommendations (self ,threats :List [ThreatIndicator ]):
        recommendations =[]

        threat_score =self .results ['threat_score']
        risk_level =threat_score ['risk_level']


        if risk_level =='critical':
            recommendations .extend ([
            "CRITICAL ALERT: Immediate containment required",
            "Isolate affected systems from network",
            "Initiate incident response procedures",
            "Collect forensic evidence before system cleanup"
            ])
        elif risk_level =='high':
            recommendations .extend ([
            "HIGH RISK: Enhanced monitoring required",
            "Review and strengthen security controls",
            "Consider quarantine measures"
            ])


        categories =set (t .category for t in threats )

        if 'network_communication'in categories :
            recommendations .append ("Block identified C2 domains and IP addresses")
            recommendations .append ("Implement network segmentation")

        if 'code_injection'in categories :
            recommendations .append ("Deploy advanced endpoint protection")
            recommendations .append ("Enable application whitelisting")

        if 'privilege_escalation'in categories :
            recommendations .append ("Review and restrict administrative privileges")
            recommendations .append ("Implement privilege access management")


        iocs =[ioc for threat in threats if threat .iocs for ioc in threat .iocs ]
        if iocs :
            recommendations .append (f"Add {len (iocs )} IOCs to threat intelligence feeds")

        self .results ['recommendations']=recommendations 

    def generate_yara_rules (self ,threats :List [ThreatIndicator ]):
        if not self .config .generate_yara_rules :
            return 

        yara_rules =[]


        if 'strings'in self .results ['static_analysis']:
            suspicious_strings =self .results ['static_analysis']['strings']

            rule =f"""
rule Malware_{self .package_name .replace ('.','_')}_{datetime .now ().strftime ('%Y%m%d')}
{{
    meta:
        description = "Auto-generated rule for {self .package_name }"
        date = "{datetime .now ().isoformat ()}"
        analysis_id = "{self .results ['metadata']['analysis_id']}"
        
    strings:"""

            for i ,string_data in enumerate (suspicious_strings [:10 ]):
                if isinstance (string_data ,str )and len (string_data )>4 :
                    rule +=f'\n        $str{i } = "{string_data }"'

            rule +="""
            
    condition:
        any of them
}"""
            yara_rules .append (rule )

        self .results ['yara_rules']=yara_rules 


        if yara_rules :
            yara_file =self .analysis_dir /'generated_rules.yar'
            with open (yara_file ,'w')as f :
                f .write ('\n\n'.join (yara_rules ))

    async def run_comprehensive_analysis (self ):
        self .logger .info (f"Starting enhanced comprehensive malware analysis")
        self .logger .info (f"Target: {self .package_name }")
        self .logger .info (f"APK: {self .apk_path }")
        self .logger .info (f"Output directory: {self .analysis_dir }")

        if not self .check_prerequisites ():
            return False 

        try :

            if self .real_time_monitor :
                self .real_time_monitor .start_monitoring ()


            self .logger .info ("=== PHASE 1: STATIC ANALYSIS ===")
            await self ._run_async_static_analysis ()


            self .logger .info ("=== PHASE 2: DYNAMIC ANALYSIS SETUP ===")
            self .logger .info ("Installing APK...")
            subprocess .run (['adb','install','-r',self .apk_path ],check =True )


            self .logger .info ("=== PHASE 3: PARALLEL DYNAMIC ANALYSIS ===")
            await self .run_parallel_analysis ()


            await asyncio .sleep (self .config .analysis_duration )


            self .logger .info ("=== PHASE 4: ENHANCED RESULTS PROCESSING ===")
            await asyncio .sleep (10 )

            self .collect_results ()
            self .enhanced_consolidate_findings ()


            if self .threat_intel :
                await self ._enrich_with_threat_intelligence ()

            self .generate_enhanced_reports ()


            if self .config .auto_cleanup :
                self ._cleanup_analysis_environment ()

            self .logger .info ("Enhanced comprehensive analysis completed!")
            self .logger .info (f"Results available in: {self .analysis_dir }")

            return True 

        except Exception as e :
            self .logger .error (f"Analysis failed: {e }")
            self .stop_all_processes ()
            return False 
        finally :
            if self .real_time_monitor :
                self .real_time_monitor .stop_monitoring ()

    async def _enrich_with_threat_intelligence (self ):
        self .logger .info ("Enriching findings with threat intelligence")


        if 'metadata'in self .results ['static_analysis']:
            file_hashes =self .results ['static_analysis']['metadata'].get ('file_hashes',{})
            for algo ,hash_val in file_hashes .items ():
                if algo .lower ()in ['sha256','md5']:
                    reputation =await self .threat_intel .check_hash_reputation (hash_val )
                    self .results ['threat_intelligence'][f'{algo }_reputation']=reputation 


        network_artifacts =self .results .get ('network_analysis',{}).get ('artifacts',{})
        domains =network_artifacts .get ('domains',[])

        for domain_data in domains [:5 ]:
            domain =domain_data .get ('value','')
            if domain :
                reputation =await self .threat_intel .check_domain_reputation (domain )
                self .results ['threat_intelligence'][f'domain_{domain }']=reputation 

    def generate_enhanced_reports (self ):
        self .logger .info ("Generating enhanced reports")

        self .results ['metadata']['end_time']=datetime .now ().isoformat ()


        json_report_path =self .analysis_dir /'enhanced_analysis_report.json'
        with open (json_report_path ,'w')as f :
            json .dump (self .results ,f ,indent =2 ,default =str )


        exec_report_path =self .analysis_dir /'executive_summary.txt'
        self ._generate_executive_summary (exec_report_path )


        tech_report_path =self .analysis_dir /'technical_analysis_report.txt'
        self ._generate_technical_report (tech_report_path )


        ioc_feed_path =self .analysis_dir /'ioc_feed.json'
        self ._generate_ioc_feed (ioc_feed_path )


        attack_mapping_path =self .analysis_dir /'mitre_attack_mapping.json'
        self ._generate_attack_mapping (attack_mapping_path )

        self .logger .info (f"Enhanced reports generated:")
        self .logger .info (f"  JSON Report: {json_report_path }")
        self .logger .info (f"  Executive Summary: {exec_report_path }")
        self .logger .info (f"  Technical Report: {tech_report_path }")
        self .logger .info (f"  IOC Feed: {ioc_feed_path }")
        self .logger .info (f"  MITRE ATT&CK: {attack_mapping_path }")

    def _generate_executive_summary (self ,output_path :Path ):
        with open (output_path ,'w')as f :
            f .write ("EXECUTIVE SUMMARY - MALWARE ANALYSIS\n")
            f .write ("="*50 +"\n\n")

            threat_score =self .results ['threat_score']
            f .write (f"OVERALL RISK ASSESSMENT: {threat_score ['risk_level'].upper ()}\n")
            f .write (f"Threat Score: {threat_score ['overall_score']}/100\n")
            f .write (f"Confidence Level: {threat_score .get ('confidence_avg',0 ):.1f}%\n\n")

            f .write ("KEY FINDINGS:\n")
            f .write (f"• {threat_score ['threat_count']} threat indicators identified\n")

            categories =set ()
            for threat in self .results ['consolidated_threats']:
                categories .add (threat ['category'])
            f .write (f"• Threat categories: {', '.join (categories )}\n")

            f .write ("\nIMMEDIATE ACTIONS REQUIRED:\n")
            for i ,rec in enumerate (self .results ['recommendations'][:3 ],1 ):
                f .write (f"{i }. {rec }\n")

    def _generate_technical_report (self ,output_path :Path ):
        with open (output_path ,'w')as f :
            f .write ("TECHNICAL ANALYSIS REPORT\n")
            f .write ("="*50 +"\n\n")

            f .write ("ANALYSIS CONFIGURATION\n")
            f .write ("-"*25 +"\n")
            config =self .results ['metadata']['config']
            f .write (f"Analysis Duration: {config ['analysis_duration']} seconds\n")
            f .write (f"Max Parallel Tools: {config ['max_parallel_tools']}\n")
            f .write (f"Real-time Monitoring: {config ['enable_real_time_monitoring']}\n")
            f .write (f"Threat Intelligence: {config ['threat_intelligence_enabled']}\n")
            f .write (f"Advanced Correlation: {config ['advanced_correlation']}\n")
            f .write (f"YARA Rule Generation: {config ['generate_yara_rules']}\n")
            f .write (f"Memory Dump Analysis: {config ['memory_dump_analysis']}\n")
            f .write (f"Auto Cleanup: {config ['auto_cleanup']}\n\n")

            f .write ("STATIC ANALYSIS RESULTS\n")
            f .write ("-"*25 +"\n")
            static =self .results ['static_analysis']
            if static :
                if 'metadata'in static :
                    f .write (f"File Size: {static ['metadata'].get ('file_size','N/A')} bytes\n")
                    f .write (f"Permissions: {', '.join (static ['metadata'].get ('permissions',[]))}\n")
                    f .write (f"Activities: {len (static ['metadata'].get ('activities',[]))}\n")
                    f .write (f"Services: {len (static ['metadata'].get ('services',[]))}\n")
                if 'threat_indicators'in static :
                    f .write (f"Threat Indicators: {len (static ['threat_indicators'])}\n")
                    for i ,indicator in enumerate (static ['threat_indicators'][:5 ],1 ):
                        f .write (f"  {i }. {indicator }\n")
            else :
                f .write ("No static analysis results available.\n")
            f .write ("\n")

            f .write ("DYNAMIC ANALYSIS RESULTS\n")
            f .write ("-"*25 +"\n")
            dynamic =self .results ['dynamic_analysis']
            if dynamic and 'threats'in dynamic :
                for category ,threats in dynamic ['threats'].items ():
                    f .write (f"{category .upper ()}: {len (threats )} threats\n")
                    for i ,threat in enumerate (threats [:3 ],1 ):
                        f .write (f"  {i }. {threat }\n")
            else :
                f .write ("No dynamic analysis results available.\n")
            f .write ("\n")

            f .write ("MEMORY ANALYSIS RESULTS\n")
            f .write ("-"*25 +"\n")
            memory =self .results ['memory_analysis']
            if memory and 'payloads'in memory :
                suspicious =memory ['payloads'].get ('suspicious',[])
                f .write (f"Suspicious Payloads: {len (suspicious )}\n")
                for i ,payload in enumerate (suspicious [:3 ],1 ):
                    f .write (f"  {i }. {payload .get ('identifier','Unknown')}\n")
            else :
                f .write ("No memory analysis results available.\n")
            f .write ("\n")

            f .write ("NETWORK ANALYSIS RESULTS\n")
            f .write ("-"*25 +"\n")
            network =self .results ['network_analysis']
            if network and 'threats'in network :
                for category ,threats in network ['threats'].items ():
                    f .write (f"{category .upper ()}: {len (threats )} threats\n")
                    for i ,threat in enumerate (threats [:3 ],1 ):
                        f .write (f"  {i }. {threat }\n")
            else :
                f .write ("No network analysis results available.\n")
            f .write ("\n")

            f .write ("THREAT INTELLIGENCE ENRICHMENT\n")
            f .write ("-"*35 +"\n")
            ti =self .results ['threat_intelligence']
            if ti :
                for key ,value in ti .items ():
                    f .write (f"{key }: {value }\n")
            else :
                f .write ("No threat intelligence data available.\n")
            f .write ("\n")

            f .write ("GENERATED YARA RULES\n")
            f .write ("-"*20 +"\n")
            yara =self .results ['yara_rules']
            if yara :
                for rule in yara :
                    f .write (f"{rule }\n\n")
            else :
                f .write ("No YARA rules generated.\n")

    async def run_comprehensive_analysis (self ):
        self .logger .info (f"Starting enhanced comprehensive malware analysis")
        self .logger .info (f"Target: {self .package_name }")
        self .logger .info (f"APK: {self .apk_path }")
        self .logger .info (f"Output directory: {self .analysis_dir }")

        if not self .check_prerequisites ():
            return False 

        try :

            if self .real_time_monitor :
                self .real_time_monitor .start_monitoring ()


            self .logger .info ("=== PHASE 1: STATIC ANALYSIS ===")
            await self ._run_async_static_analysis ()


            self .logger .info ("=== PHASE 2: DYNAMIC ANALYSIS SETUP ===")
            self .logger .info ("Installing APK...")
            subprocess .run (['adb','install','-r',self .apk_path ],check =True )


            self .logger .info ("=== PHASE 3: PARALLEL DYNAMIC ANALYSIS ===")
            await self .run_parallel_analysis ()


            await asyncio .sleep (self .config .analysis_duration )


            self .logger .info ("=== PHASE 4: ENHANCED RESULTS PROCESSING ===")
            await asyncio .sleep (10 )

            self .collect_results ()
            self .enhanced_consolidate_findings ()


            if self .threat_intel :
                await self ._enrich_with_threat_intelligence ()

            self .generate_enhanced_reports ()


            if self .config .auto_cleanup :
                self ._cleanup_analysis_environment ()

            self .logger .info ("Enhanced comprehensive analysis completed!")
            self .logger .info (f"Results available in: {self .analysis_dir }")

            return True 

        except Exception as e :
            self .logger .error (f"Analysis failed: {e }")
            self .stop_all_processes ()
            return False 
        finally :
            if self .real_time_monitor :
                self .real_time_monitor .stop_monitoring ()

    async def _enrich_with_threat_intelligence (self ):
        self .logger .info ("Enriching findings with threat intelligence")


        if 'metadata'in self .results ['static_analysis']:
            file_hashes =self .results ['static_analysis']['metadata'].get ('file_hashes',{})
            for algo ,hash_val in file_hashes .items ():
                if algo .lower ()in ['sha256','md5']:
                    reputation =await self .threat_intel .check_hash_reputation (hash_val )
                    self .results ['threat_intelligence'][f'{algo }_reputation']=reputation 


        network_artifacts =self .results .get ('network_analysis',{}).get ('artifacts',{})
        domains =network_artifacts .get ('domains',[])

        for domain_data in domains [:5 ]:
            domain =domain_data .get ('value','')
            if domain :
                reputation =await self .threat_intel .check_domain_reputation (domain )
                self .results ['threat_intelligence'][f'domain_{domain }']=reputation 

    def generate_enhanced_reports (self ):
        self .logger .info ("Generating enhanced reports")

        self .results ['metadata']['end_time']=datetime .now ().isoformat ()


        json_report_path =self .analysis_dir /'enhanced_analysis_report.json'
        with open (json_report_path ,'w')as f :
            json .dump (self .results ,f ,indent =2 ,default =str )


        exec_report_path =self .analysis_dir /'executive_summary.txt'
        self ._generate_executive_summary (exec_report_path )


        tech_report_path =self .analysis_dir /'technical_analysis_report.txt'
        self ._generate_technical_report (tech_report_path )


        ioc_feed_path =self .analysis_dir /'ioc_feed.json'
        self ._generate_ioc_feed (ioc_feed_path )


        attack_mapping_path =self .analysis_dir /'mitre_attack_mapping.json'
        self ._generate_attack_mapping (attack_mapping_path )

        self .logger .info (f"Enhanced reports generated:")
        self .logger .info (f"  JSON Report: {json_report_path }")
        self .logger .info (f"  Executive Summary: {exec_report_path }")
        self .logger .info (f"  Technical Report: {tech_report_path }")
        self .logger .info (f"  IOC Feed: {ioc_feed_path }")
        self .logger .info (f"  MITRE ATT&CK: {attack_mapping_path }")

    def _generate_executive_summary (self ,output_path :Path ):
        with open (output_path ,'w')as f :
            f .write ("EXECUTIVE SUMMARY - MALWARE ANALYSIS\n")
            f .write ("="*50 +"\n\n")

            threat_score =self .results ['threat_score']
            f .write (f"OVERALL RISK ASSESSMENT: {threat_score ['risk_level'].upper ()}\n")
            f .write (f"Threat Score: {threat_score ['overall_score']}/100\n")
            f .write (f"Confidence Level: {threat_score .get ('confidence_avg',0 ):.1f}%\n\n")

            f .write ("KEY FINDINGS:\n")
            f .write (f"• {threat_score ['threat_count']} threat indicators identified\n")

            categories =set ()
            for threat in self .results ['consolidated_threats']:
                categories .add (threat ['category'])
            f .write (f"• Threat categories: {', '.join (categories )}\n")

            f .write ("\nIMMEDIATE ACTIONS REQUIRED:\n")
            for i ,rec in enumerate (self .results ['recommendations'][:3 ],1 ):
                f .write (f"{i }. {rec }\n")

    def _generate_technical_report (self ,output_path :Path ):
        with open (output_path ,'w')as f :
            f .write ("TECHNICAL ANALYSIS REPORT\n")
            f .write ("="*50 +"\n\n")

            f .write ("ANALYSIS CONFIGURATION\n")
            f .write ("-"*25 +"\n")
            config =self .results ['metadata']['config']
            f .write (f"Analysis Duration: {config ['analysis_duration']} seconds\n")
            f .write (f"Max Parallel Tools: {config ['max_parallel_tools']}\n")
            f .write (f"Real-time Monitoring: {config ['enable_real_time_monitoring']}\n")
            f .write (f"Threat Intelligence: {config ['threat_intelligence_enabled']}\n")
            f .write (f"Advanced Correlation: {config ['advanced_correlation']}\n")
            f .write (f"YARA Rule Generation: {config ['generate_yara_rules']}\n")
            f .write (f"Memory Dump Analysis: {config ['memory_dump_analysis']}\n")
            f .write (f"Auto Cleanup: {config ['auto_cleanup']}\n\n")

            f .write ("STATIC ANALYSIS RESULTS\n")
            f .write ("-"*25 +"\n")
            static =self .results ['static_analysis']
            if static :
                if 'metadata'in static :
                    f .write (f"File Size: {static ['metadata'].get ('file_size','N/A')} bytes\n")
                    f .write (f"Permissions: {', '.join (static ['metadata'].get ('permissions',[]))}\n")
                    f .write (f"Activities: {len (static ['metadata'].get ('activities',[]))}\n")
                    f .write (f"Services: {len (static ['metadata'].get ('services',[]))}\n")
                if 'threat_indicators'in static :
                    f .write (f"Threat Indicators: {len (static ['threat_indicators'])}\n")
                    for i ,indicator in enumerate (static ['threat_indicators'][:5 ],1 ):
                        f .write (f"  {i }. {indicator }\n")
            else :
                f .write ("No static analysis results available.\n")
            f .write ("\n")

            f .write ("DYNAMIC ANALYSIS RESULTS\n")
            f .write ("-"*25 +"\n")
            dynamic =self .results ['dynamic_analysis']
            if dynamic and 'threats'in dynamic :
                for category ,threats in dynamic ['threats'].items ():
                    f .write (f"{category .upper ()}: {len (threats )} threats\n")
                    for i ,threat in enumerate (threats [:3 ],1 ):
                        f .write (f"  {i }. {threat }\n")
            else :
                f .write ("No dynamic analysis results available.\n")
            f .write ("\n")

            f .write ("MEMORY ANALYSIS RESULTS\n")
            f .write ("-"*25 +"\n")
            memory =self .results ['memory_analysis']
            if memory and 'payloads'in memory :
                suspicious =memory ['payloads'].get ('suspicious',[])
                f .write (f"Suspicious Payloads: {len (suspicious )}\n")
                for i ,payload in enumerate (suspicious [:3 ],1 ):
                    f .write (f"  {i }. {payload .get ('identifier','Unknown')}\n")
            else :
                f .write ("No memory analysis results available.\n")
            f .write ("\n")

            f .write ("NETWORK ANALYSIS RESULTS\n")
            f .write ("-"*25 +"\n")
            network =self .results ['network_analysis']
            if network and 'threats'in network :
                for category ,threats in network ['threats'].items ():
                    f .write (f"{category .upper ()}: {len (threats )} threats\n")
                    for i ,threat in enumerate (threats [:3 ],1 ):
                        f .write (f"  {i }. {threat }\n")
            else :
                f .write ("No network analysis results available.\n")
            f .write ("\n")

            f .write ("THREAT INTELLIGENCE ENRICHMENT\n")
            f .write ("-"*35 +"\n")
            ti =self .results ['threat_intelligence']
            if ti :
                for key ,value in ti .items ():
                    f .write (f"{key }: {value }\n")
            else :
                f .write ("No threat intelligence data available.\n")
            f .write ("\n")

            f .write ("GENERATED YARA RULES\n")
            f .write ("-"*20 +"\n")
            yara =self .results ['yara_rules']
            if yara :
                for rule in yara :
                    f .write (f"{rule }\n\n")
            else :
                f .write ("No YARA rules generated.\n")



    def check_prerequisites (self ):
        self .logger .info ("Checking prerequisites...")

        required_commands =['adb','frida','python3']
        missing =[]

        for cmd in required_commands :
            try :
                result =subprocess .run (['which',cmd ],capture_output =True ,text =True ,timeout =10 )
                if result .returncode !=0 :
                    missing .append (cmd )
            except subprocess .TimeoutExpired :
                self .logger .error (f"Timeout checking {cmd }")
                missing .append (cmd )

        if missing :
            self .logger .error (f"Missing required tools: {', '.join (missing )}")
            return False 


        try :
            result =subprocess .run (['adb','devices'],capture_output =True ,text =True ,timeout =10 )
            if 'device'not in result .stdout :
                self .logger .error ("No Android device connected")
                return False 
        except subprocess .TimeoutExpired :
            self .logger .error ("Timeout checking adb devices")
            return False 


        try :
            result =subprocess .run (['frida-ps','-U'],capture_output =True ,text =True ,timeout =10 )
            if result .returncode !=0 :
                self .logger .error ("Frida server not running on device")
                return False 
        except subprocess .TimeoutExpired :
            self .logger .error ("Timeout checking frida-ps")
            return False 

        self .logger .info ("All prerequisites met")
        return True 



    def run_static_analysis (self ):
        self .logger .info ("Starting static analysis...")

        try :
            cmd =[
            'python3',self .tools ['static']['path'],
            self .apk_path ,
            '-o',str (self .analysis_dir /'static')
            ]

            result =subprocess .run (cmd ,capture_output =True ,text =True ,timeout =300 )

            if result .returncode ==0 :
                self .tools ['static']['status']='completed'
                self .logger .info ("Static analysis completed")


                static_dir =self .analysis_dir /'static'
                if static_dir .exists ():
                    json_files =list (static_dir .glob ('static_analysis_*.json'))
                    if json_files :
                        with open (json_files [0 ])as f :
                            self .results ['static_analysis']=json .load (f )
            else :
                self .tools ['static']['status']='failed'
                self .logger .error (f"Static analysis failed: {result .stderr }")

        except subprocess .TimeoutExpired :
            self .tools ['static']['status']='timeout'
            self .logger .error ("Static analysis timed out")
        except Exception as e :
            self .tools ['static']['status']='error'
            self .logger .error (f"Static analysis error: {e }")


