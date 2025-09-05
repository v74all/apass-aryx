#!/usr/bin/env python3

import sys 
import os 
import json 
import subprocess 
import shutil 
import time 
import hashlib 
import re 
from pathlib import Path 
from datetime import datetime 
from typing import Dict ,List ,Optional ,Any 


try :
    from utils .progress_tracker import ProgressTracker ,update_progress ,set_progress_stage 
except ImportError :

    def update_progress (percentage :int ,task :str ,details :Optional [str ]=None ):
        print (f"Progress: {percentage }% - {task }")

    def set_progress_stage (stage_name :str ,percentage :int ,details :Optional [str ]=None ):
        print (f"Stage: {stage_name } ({percentage }%)")


try :
    from analyzers .tool_integrations import (
    run_androguard ,
    run_apkid ,
    run_quark ,
    run_yara_scan ,
    run_mobsf ,
    run_virustotal_lookup ,
    run_avclass ,
    check_cutter_r2frida ,
    check_ghidra ,
    check_qiling ,
    check_xposed_lsposed ,
    check_magisk_zygisk ,
    check_objection ,
    check_inspeckage ,
    check_radare2_rizin_r2frida ,
    check_jadx ,
    run_jadx_decompile ,
    ToolResult ,
    )
    from src .analyzers .enhanced_data_extractor import EnhancedDataExtractor 
    from src .analyzers .tool_integrations import run_all_tool_integrations 
    from src .utils .threat_intelligence import get_threat_intel_for_domains 
    from src .utils .report_generator import generate_unified_report 
except Exception :

    run_androguard =run_apkid =run_quark =run_yara_scan =None 
    run_mobsf =run_virustotal_lookup =run_avclass =None 
    check_cutter_r2frida =check_ghidra =check_qiling =None 
    check_xposed_lsposed =check_magisk_zygisk =None 
    check_objection =check_inspeckage =None 
    check_radare2_rizin_r2frida =check_jadx =None 
    run_jadx_decompile =None 
    ToolResult =Any 

class AdvancedAPKAnalyzer :

    def __init__ (self ,apk_path :str ):
        self .apk_path =Path (apk_path )
        self .timestamp =datetime .now ().strftime ("%Y%m%d_%H%M%S")
        self .analysis_id =f"advanced_analysis_{self .timestamp }"


        self .output_dir =Path ("analysis_results")/"unified_output"/self .analysis_id 
        self .output_dir .mkdir (parents =True ,exist_ok =True )


        self .static_dir =self .output_dir /"static"
        self .dynamic_dir =self .output_dir /"dynamic"
        self .network_dir =self .output_dir /"network"
        self .artifacts_dir =self .output_dir /"artifacts"
        self .reports_dir =self .output_dir /"reports"
        self .logs_dir =self .output_dir /"logs"

        for dir_path in [self .static_dir ,self .dynamic_dir ,self .network_dir ,
        self .artifacts_dir ,self .reports_dir ,self .logs_dir ]:
            dir_path .mkdir (exist_ok =True )


        self .results ={
        'metadata':{
        'analysis_id':self .analysis_id ,
        'timestamp':self .timestamp ,
        'apk_path':str (self .apk_path ),
        'analyzer_version':'6.0',
        'analysis_type':'comprehensive'
        },
        'file_analysis':{},
        'manifest_analysis':{},
        'permissions_analysis':{},
        'network_analysis':{},
        'security_analysis':{},
        'threat_intelligence':{},
        'external_tools':{},
        'summary':{}
        }

        self .log_file =self .logs_dir /"advanced_analysis.log"
        self .log (f"Advanced APK Analysis started for: {self .apk_path }")

    def log (self ,message :str ,level :str ="INFO"):
        timestamp =datetime .now ().strftime ("%Y-%m-%d %H:%M:%S")
        log_entry =f"[{timestamp }] {level }: {message }\n"
        print (f"[{level }] {message }")

        with open (self .log_file ,'a',encoding ='utf-8')as f :
            f .write (log_entry )

    def get_file_hashes (self )->Dict [str ,str ]:
        hashes ={}
        try :
            with open (self .apk_path ,'rb')as f :
                content =f .read ()
                hashes ['md5']=hashlib .md5 (content ).hexdigest ()
                hashes ['sha1']=hashlib .sha1 (content ).hexdigest ()
                hashes ['sha256']=hashlib .sha256 (content ).hexdigest ()
                hashes ['file_size']=len (content )
        except Exception as e :
            self .log (f"Failed to calculate hashes: {e }","ERROR")
        return hashes 

    def run_aapt_analysis (self )->Dict [str ,Any ]:
        self .log ("Running AAPT analysis...")

        aapt_results ={
        'package_info':{},
        'permissions':[],
        'activities':[],
        'services':[],
        'receivers':[],
        'providers':[],
        'features':[],
        'configurations':[]
        }


        try :
            result =subprocess .run ([
            'aapt','dump','badging',str (self .apk_path )
            ],capture_output =True ,text =True ,timeout =120 )

            if result .returncode ==0 :

                badging_file =self .artifacts_dir /"aapt_badging.txt"
                with open (badging_file ,'w')as f :
                    f .write (result .stdout )


                for line in result .stdout .split ('\n'):
                    line =line .strip ()

                    if line .startswith ('package:'):

                        parts =line .split ()
                        for part in parts :
                            if part .startswith ('name='):
                                aapt_results ['package_info']['name']=part .split ('=')[1 ].strip ("'\"")
                            elif part .startswith ('versionCode='):
                                aapt_results ['package_info']['version_code']=part .split ('=')[1 ].strip ("'\"")
                            elif part .startswith ('versionName='):
                                aapt_results ['package_info']['version_name']=part .split ('=')[1 ].strip ("'\"")
                            elif part .startswith ('platformBuildVersionName='):
                                aapt_results ['package_info']['platform_version']=part .split ('=')[1 ].strip ("'\"")

                    elif line .startswith ('uses-permission:'):

                        match =re .search (r"name='([^']+)'",line )
                        if match :
                            aapt_results ['permissions'].append (match .group (1 ))

                    elif line .startswith ('launchable-activity:'):

                        match =re .search (r"name='([^']+)'",line )
                        if match :
                            aapt_results ['activities'].append ({
                            'name':match .group (1 ),
                            'type':'launchable'
                            })

                    elif line .startswith ('uses-feature:'):

                        match =re .search (r"name='([^']+)'",line )
                        if match :
                            aapt_results ['features'].append (match .group (1 ))

        except Exception as e :
            self .log (f"AAPT badging failed: {e }","ERROR")


        try :
            result =subprocess .run ([
            'aapt','dump','permissions',str (self .apk_path )
            ],capture_output =True ,text =True ,timeout =60 )

            if result .returncode ==0 :
                permissions_file =self .artifacts_dir /"aapt_permissions.txt"
                with open (permissions_file ,'w')as f :
                    f .write (result .stdout )

        except Exception as e :
            self .log (f"AAPT permissions failed: {e }","WARNING")


        try :
            result =subprocess .run ([
            'aapt','dump','configurations',str (self .apk_path )
            ],capture_output =True ,text =True ,timeout =60 )

            if result .returncode ==0 :
                configs_file =self .artifacts_dir /"aapt_configurations.txt"
                with open (configs_file ,'w')as f :
                    f .write (result .stdout )


                for line in result .stdout .split ('\n'):
                    line =line .strip ()
                    if line and not line .startswith ('configurations:'):
                        aapt_results ['configurations'].append (line )

        except Exception as e :
            self .log (f"AAPT configurations failed: {e }","WARNING")

        return aapt_results 

    def run_strings_analysis (self )->Dict [str ,Any ]:
        self .log ("Running strings analysis...")

        strings_results ={
        'all_strings':[],
        'urls':[],
        'domains':[],
        'ip_addresses':[],
        'api_endpoints':[],
        'suspicious_strings':[],
        'crypto_strings':[]
        }

        try :

            result =subprocess .run ([
            'strings','-a','-n','4',str (self .apk_path )
            ],capture_output =True ,text =True ,timeout =120 )

            if result .returncode ==0 :
                strings_file =self .artifacts_dir /"strings_output.txt"
                with open (strings_file ,'w',encoding ='utf-8')as f :
                    f .write (result .stdout )

                lines =result .stdout .split ('\n')
                strings_results ['all_strings']=[line .strip ()for line in lines if line .strip ()]


                url_pattern =r'https?://[^\s<>"\'`|()[\]{}]+'
                domain_pattern =r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                ip_pattern =r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

                suspicious_keywords =[
                'password','secret','key','token','auth','login',
                'admin','root','shell','exploit','backdoor',
                'malware','virus','trojan','spy','steal'
                ]

                crypto_keywords =[
                'encrypt','decrypt','cipher','crypto','hash',
                'rsa','aes','des','md5','sha','ssl','tls'
                ]

                for string in strings_results ['all_strings']:

                    urls =re .findall (url_pattern ,string ,re .IGNORECASE )
                    strings_results ['urls'].extend (urls )


                    domains =re .findall (domain_pattern ,string ,re .IGNORECASE )
                    strings_results ['domains'].extend (domains )


                    ips =re .findall (ip_pattern ,string )
                    strings_results ['ip_addresses'].extend (ips )


                    for keyword in suspicious_keywords :
                        if keyword .lower ()in string .lower ():
                            strings_results ['suspicious_strings'].append (string )
                            break 


                    for keyword in crypto_keywords :
                        if keyword .lower ()in string .lower ():
                            strings_results ['crypto_strings'].append (string )
                            break 


                    if '/api/'in string .lower ()or 'api.'in string .lower ():
                        strings_results ['api_endpoints'].append (string )


                strings_results ['urls']=list (set (strings_results ['urls']))[:50 ]
                strings_results ['domains']=list (set (strings_results ['domains']))[:50 ]
                strings_results ['ip_addresses']=list (set (strings_results ['ip_addresses']))[:20 ]
                strings_results ['api_endpoints']=list (set (strings_results ['api_endpoints']))[:30 ]
                strings_results ['suspicious_strings']=list (set (strings_results ['suspicious_strings']))[:30 ]
                strings_results ['crypto_strings']=list (set (strings_results ['crypto_strings']))[:30 ]

        except Exception as e :
            self .log (f"Strings analysis failed: {e }","ERROR")

        return strings_results 

    def run_apktool_analysis (self )->Dict [str ,Any ]:
        self .log ("Attempting apktool analysis...")

        apktool_results ={
        'success':False ,
        'error':None ,
        'extracted_files':[]
        }

        try :

            subprocess .run (['apktool','--version'],capture_output =True ,check =True )


            extract_dir =self .artifacts_dir /"apktool_output"
            extract_dir .mkdir (exist_ok =True )


            result =subprocess .run ([
            'apktool','d',str (self .apk_path ),'-o',str (extract_dir ),'-f'
            ],capture_output =True ,text =True ,timeout =180 )

            if result .returncode ==0 :
                apktool_results ['success']=True 

                for file_path in extract_dir .rglob ('*'):
                    if file_path .is_file ():
                        apktool_results ['extracted_files'].append (str (file_path .relative_to (extract_dir )))

                self .log (f"Apktool extraction successful: {len (apktool_results ['extracted_files'])} files")
            else :
                apktool_results ['error']=result .stderr 
                self .log (f"Apktool failed: {result .stderr }","WARNING")

        except subprocess .CalledProcessError :
            self .log ("Apktool not available","WARNING")
            apktool_results ['error']="Apktool not installed"
        except Exception as e :
            apktool_results ['error']=str (e )
            self .log (f"Apktool analysis failed: {e }","WARNING")

        return apktool_results 

    def run_external_integrations (self )->Dict [str ,Any ]:
        self .log ("Phase 5b: External tool integrations (optional)")
        ext :Dict [str ,Any ]={}


        if run_androguard :
            res :ToolResult =run_androguard (str (self .apk_path ))
            ext ['androguard']=res .__dict__ if hasattr (res ,'__dict__')else res 


        if run_apkid :
            res =run_apkid (str (self .apk_path ))
            ext ['apkid']=res .__dict__ if hasattr (res ,'__dict__')else res 


        if run_quark :
            res =run_quark (str (self .apk_path ),self .artifacts_dir )
            ext ['quark']=res .__dict__ if hasattr (res ,'__dict__')else res 


        if run_yara_scan :

            rules_dirs =[Path ('resources/yara'),Path ('resources/yara/community')]
            res =run_yara_scan (str (self .apk_path ),rules_dirs )
            ext ['yara']=res .__dict__ if hasattr (res ,'__dict__')else res 


        if run_virustotal_lookup :
            sha256 =self .get_file_hashes ().get ('sha256')
            if sha256 :
                res =run_virustotal_lookup (sha256 ,self .artifacts_dir )
                ext ['virustotal']=res .__dict__ if hasattr (res ,'__dict__')else res 


        if run_mobsf :
            res =run_mobsf (str (self .apk_path ),self .artifacts_dir )
            ext ['mobsf']=res .__dict__ if hasattr (res ,'__dict__')else res 


        if run_avclass and 'virustotal'in ext :
            try :
                vt_file =self .artifacts_dir /'virustotal_response.json'
                if vt_file .exists ():
                    res =run_avclass (vt_file ,self .artifacts_dir )
                    ext ['avclass']=res .__dict__ if hasattr (res ,'__dict__')else res 
            except Exception as e :
                ext ['avclass']={"name":"avclass","available":True ,"success":False ,"data":{},"error":str (e )}


        if check_cutter_r2frida :
            res =check_cutter_r2frida ()
            ext ['cutter_r2frida']=res .__dict__ if hasattr (res ,'__dict__')else res 
        if check_ghidra :
            res =check_ghidra ()
            ext ['ghidra']=res .__dict__ if hasattr (res ,'__dict__')else res 
        if check_qiling :
            res =check_qiling ()
            ext ['qiling']=res .__dict__ if hasattr (res ,'__dict__')else res 


        if check_xposed_lsposed :
            res =check_xposed_lsposed ()
            ext ['xposed_lsposed']=res .__dict__ if hasattr (res ,'__dict__')else res 
        if check_magisk_zygisk :
            res =check_magisk_zygisk ()
            ext ['magisk_zygisk']=res .__dict__ if hasattr (res ,'__dict__')else res 
        if check_objection :
            res =check_objection ()
            ext ['objection']=res .__dict__ if hasattr (res ,'__dict__')else res 
        if check_inspeckage :
            res =check_inspeckage ()
            ext ['inspeckage']=res .__dict__ if hasattr (res ,'__dict__')else res 
        if check_radare2_rizin_r2frida :
            res =check_radare2_rizin_r2frida ()
            ext ['radare2_rizin_r2frida']=res .__dict__ if hasattr (res ,'__dict__')else res 
        if check_jadx :
            res =check_jadx ()
            ext ['jadx']=res .__dict__ if hasattr (res ,'__dict__')else res 

            if run_jadx_decompile and getattr (res ,'available',False ):
                try :
                    jd =run_jadx_decompile (str (self .apk_path ),self .artifacts_dir )
                    ext ['jadx_decompile']=jd .__dict__ if hasattr (jd ,'__dict__')else jd 
                except Exception as e :
                    ext ['jadx_decompile']={"name":"jadx_decompile","available":True ,"success":False ,"data":{},"error":str (e )}

        return ext 

    def analyze_permissions (self ,permissions :List [str ])->Dict [str ,Any ]:
        self .log ("Analyzing permissions...")


        dangerous_permissions ={
        'CAMERA':'Camera access',
        'RECORD_AUDIO':'Microphone access',
        'ACCESS_FINE_LOCATION':'Precise location',
        'ACCESS_COARSE_LOCATION':'Approximate location',
        'READ_CONTACTS':'Read contacts',
        'WRITE_CONTACTS':'Write contacts',
        'READ_SMS':'Read SMS',
        'SEND_SMS':'Send SMS',
        'CALL_PHONE':'Make phone calls',
        'READ_CALL_LOG':'Read call log',
        'WRITE_CALL_LOG':'Write call log',
        'READ_EXTERNAL_STORAGE':'Read external storage',
        'WRITE_EXTERNAL_STORAGE':'Write external storage'
        }

        high_risk_permissions ={
        'SYSTEM_ALERT_WINDOW':'Display over other apps',
        'DEVICE_ADMIN':'Device administrator',
        'BIND_DEVICE_ADMIN':'Bind device admin',
        'WRITE_SETTINGS':'Modify system settings',
        'WRITE_SECURE_SETTINGS':'Modify secure settings',
        'INSTALL_PACKAGES':'Install packages',
        'DELETE_PACKAGES':'Delete packages'
        }

        permission_analysis ={
        'total_permissions':len (permissions ),
        'dangerous_permissions':[],
        'high_risk_permissions':[],
        'normal_permissions':[],
        'unknown_permissions':[],
        'risk_score':0 
        }

        for perm in permissions :
            perm_short =perm .replace ('android.permission.','')

            if perm_short in dangerous_permissions :
                permission_analysis ['dangerous_permissions'].append ({
                'permission':perm ,
                'description':dangerous_permissions [perm_short ]
                })
                permission_analysis ['risk_score']+=2 
            elif perm_short in high_risk_permissions :
                permission_analysis ['high_risk_permissions'].append ({
                'permission':perm ,
                'description':high_risk_permissions [perm_short ]
                })
                permission_analysis ['risk_score']+=5 
            elif perm .startswith ('android.permission.'):
                permission_analysis ['normal_permissions'].append (perm )
            else :
                permission_analysis ['unknown_permissions'].append (perm )
                permission_analysis ['risk_score']+=1 

        return permission_analysis 

    def run_network_intelligence (self ,strings_data :Dict [str ,Any ])->Dict [str ,Any ]:
        self .log ("Running network intelligence analysis...")

        network_intel ={
        'domains_analysis':{},
        'urls_analysis':{},
        'ip_analysis':{},
        'suspicious_indicators':[],
        'reputation_data':{}
        }


        for domain in strings_data .get ('domains',[]):
            domain_info ={
            'domain':domain ,
            'tld':domain .split ('.')[-1 ]if '.'in domain else 'unknown',
            'subdomain_count':len (domain .split ('.'))-2 ,
            'suspicious':False 
            }


            suspicious_tlds =['tk','ml','ga','cf','bit']
            suspicious_patterns =['dyndns','no-ip','ddns','ngrok']

            if domain_info ['tld']in suspicious_tlds :
                domain_info ['suspicious']=True 
                network_intel ['suspicious_indicators'].append (f"Suspicious TLD: {domain }")

            for pattern in suspicious_patterns :
                if pattern in domain .lower ():
                    domain_info ['suspicious']=True 
                    network_intel ['suspicious_indicators'].append (f"Suspicious pattern in domain: {domain }")

            network_intel ['domains_analysis'][domain ]=domain_info 


        for url in strings_data .get ('urls',[]):
            url_info ={
            'url':url ,
            'protocol':url .split ('://')[0 ]if '://'in url else 'unknown',
            'domain':'',
            'path':'',
            'suspicious':False 
            }

            try :

                if '://'in url :
                    parts =url .split ('://',1 )[1 ].split ('/',1 )
                    url_info ['domain']=parts [0 ]
                    url_info ['path']='/'+parts [1 ]if len (parts )>1 else '/'


                if url_info ['protocol']=='http':
                    url_info ['suspicious']=True 
                    network_intel ['suspicious_indicators'].append (f"Non-HTTPS URL: {url }")

                suspicious_url_patterns =['download','payload','exploit','shell']
                for pattern in suspicious_url_patterns :
                    if pattern in url .lower ():
                        url_info ['suspicious']=True 
                        network_intel ['suspicious_indicators'].append (f"Suspicious URL pattern: {url }")

            except Exception :
                pass 

            network_intel ['urls_analysis'][url ]=url_info 

        return network_intel 

    def calculate_threat_score (self )->int :
        score =0 


        perm_analysis =self .results .get ('permissions_analysis',{})
        score +=len (perm_analysis .get ('dangerous_permissions',[]))*3 
        score +=len (perm_analysis .get ('high_risk_permissions',[]))*8 


        network_analysis =self .results .get ('network_analysis',{})
        score +=len (network_analysis .get ('suspicious_indicators',[]))*5 


        strings_data =self .results .get ('network_analysis',{}).get ('strings_data',{})
        score +=len (strings_data .get ('suspicious_strings',[]))*2 
        score +=len (strings_data .get ('crypto_strings',[]))*1 

        return min (score ,100 )

    def generate_comprehensive_report (self ):
        self .log ("Generating comprehensive report...")


        def _sanitize (obj ,max_items :int =int (os .environ .get ("APASS_REPORT_MAX_ITEMS","500"))):
            try :
                if isinstance (obj ,dict ):
                    return {k :_sanitize (v ,max_items )for k ,v in obj .items ()}
                if isinstance (obj ,list ):
                    if len (obj )>max_items :
                        head =[_sanitize (v ,max_items )for v in obj [:max_items //2 ]]
                        tail =[_sanitize (v ,max_items )for v in obj [-max_items //2 :]]
                        return head +[f"… truncated {len (obj )-max_items } items …"]+tail 
                    return [_sanitize (v ,max_items )for v in obj ]
                if isinstance (obj ,(set ,tuple )):
                    return _sanitize (list (obj ),max_items )
                if isinstance (obj ,Path ):
                    return str (obj )
                return obj 
            except Exception :
                return str (obj )


        threat_score =self .calculate_threat_score ()
        self .results ['summary']['threat_score']=threat_score 


        json_report =self .reports_dir /"comprehensive_report.json"
        try :
            safe_results =_sanitize (self .results )
            with open (json_report ,'w',encoding ='utf-8')as f :
                json .dump (safe_results ,f ,indent =2 ,default =str )
        except Exception as e :
            self .log (f"Failed to write JSON report: {e }","WARNING")


        text_report =self .reports_dir /"comprehensive_report.txt"
        try :
            with open (text_report ,'w',encoding ='utf-8')as f :
                f .write ("🔬 COMPREHENSIVE APK ANALYSIS REPORT\n")
                f .write ("="*60 +"\n\n")
                f .write (f"Analysis ID: {self .analysis_id }\n")
                f .write (f"Timestamp: {self .timestamp }\n")
                f .write (f"APK Path: {self .apk_path }\n")
                f .write (f"Threat Score: {threat_score }/100\n\n")


                if 'file_analysis'in self .results :
                    f .write ("📁 FILE ANALYSIS:\n")
                    f .write ("-"*30 +"\n")
                    file_info =self .results .get ('file_analysis')or {}
                    for key ,value in file_info .items ():
                        f .write (f"{key .upper ()}: {value }\n")
                    f .write ("\n")


                if 'manifest_analysis'in self .results :
                    f .write ("📱 PACKAGE INFORMATION:\n")
                    f .write ("-"*30 +"\n")
                    manifest =self .results .get ('manifest_analysis')or {}
                    pkg_info =manifest .get ('package_info',{})
                    for key ,value in pkg_info .items ():
                        f .write (f"{key .replace ('_',' ').title ()}: {value }\n")
                    f .write ("\n")


                if 'permissions_analysis'in self .results :
                    f .write ("🔐 PERMISSIONS ANALYSIS:\n")
                    f .write ("-"*30 +"\n")
                    perm_analysis =self .results .get ('permissions_analysis')or {}
                    f .write (f"Total Permissions: {perm_analysis .get ('total_permissions',0 )}\n")
                    f .write (f"Risk Score: {perm_analysis .get ('risk_score',0 )}\n\n")

                    dangerous =perm_analysis .get ('dangerous_permissions',[])or []
                    if dangerous :
                        f .write (f"⚠️  Dangerous Permissions ({len (dangerous )}):\n")
                        for perm in dangerous [:50 ]:
                            try :
                                f .write (f"  • {perm .get ('permission')}: {perm .get ('description')}\n")
                            except Exception :
                                continue 
                        f .write ("\n")

                    high_risk =perm_analysis .get ('high_risk_permissions',[])or []
                    if high_risk :
                        f .write (f"🚨 High Risk Permissions ({len (high_risk )}):\n")
                        for perm in high_risk [:50 ]:
                            try :
                                f .write (f"  • {perm .get ('permission')}: {perm .get ('description')}\n")
                            except Exception :
                                continue 
                        f .write ("\n")


                if 'network_analysis'in self .results :
                    f .write ("🌐 NETWORK ANALYSIS:\n")
                    f .write ("-"*30 +"\n")
                    network =self .results .get ('network_analysis')or {}

                    strings_data =network .get ('strings_data',{})or {}
                    f .write (f"URLs Found: {len (strings_data .get ('urls',[]))}\n")
                    f .write (f"Domains Found: {len (strings_data .get ('domains',[]))}\n")
                    f .write (f"IP Addresses: {len (strings_data .get ('ip_addresses',[]))}\n")
                    f .write (f"API Endpoints: {len (strings_data .get ('api_endpoints',[]))}\n\n")

                    network_intel =network .get ('network_intelligence',{})or {}
                    suspicious =network_intel .get ('suspicious_indicators',[])or []
                    if suspicious :
                        f .write (f"🚨 Suspicious Network Indicators ({len (suspicious )}):\n")
                        for indicator in suspicious [:50 ]:
                            f .write (f"  • {indicator }\n")
                        f .write ("\n")


                    domains =strings_data .get ('domains',[])or []
                    if domains :
                        f .write (f"🌍 Domains ({len (domains )}):\n")
                        for domain in domains [:50 ]:
                            f .write (f"  • {domain }\n")
                        f .write ("\n")

                    urls =strings_data .get ('urls',[])or []
                    if urls :
                        f .write (f"🔗 URLs ({len (urls )}):\n")
                        for url in urls [:50 ]:
                            f .write (f"  • {url }\n")
                        f .write ("\n")
        except Exception as e :
            self .log (f"Failed to write text report: {e }","WARNING")


        try :
            self .generate_html_report ()
        except Exception as e :
            self .log (f"Failed to generate HTML report: {e }","WARNING")


        try :
            csv_path =self .reports_dir /"summary.csv"
            lines =[
            "metric,value",
            f"threat_score,{self .results ['summary'].get ('threat_score',0 )}",
            f"dangerous_permissions,{len (self .results .get ('permissions_analysis',{}).get ('dangerous_permissions',[]))}",
            f"high_risk_permissions,{len (self .results .get ('permissions_analysis',{}).get ('high_risk_permissions',[]))}",
            f"domains,{len (self .results .get ('network_analysis',{}).get ('strings_data',{}).get ('domains',[]))}",
            f"urls,{len (self .results .get ('network_analysis',{}).get ('strings_data',{}).get ('urls',[]))}",
            ]
            csv_path .write_text ("\n".join (lines )+"\n",encoding ='utf-8')
        except Exception as e :
            self .log (f"CSV summary generation failed: {e }","WARNING")


        try :
            sarif ={
            "$schema":"https://json.schemastore.org/sarif-2.1.0.json",
            "version":"2.1.0",
            "runs":[
            {
            "tool":{"driver":{"name":"APASS ARYX Advanced Analyzer","version":"6.0"}},
            "results":[]
            }
            ]
            }
            results =sarif ["runs"][0 ]["results"]

            suspicious =self .results .get ('network_analysis',{}).get ('network_intelligence',{}).get ('suspicious_indicators',[])
            for item in suspicious :
                results .append ({
                "ruleId":"suspicious-network-indicator",
                "level":"warning",
                "message":{"text":str (item )},
                "locations":[
                {"physicalLocation":{"artifactLocation":{"uri":str (self .apk_path )}}}
                ]
                })
            (self .reports_dir /"findings.sarif").write_text (json .dumps (sarif ,indent =2 ),encoding ='utf-8')
        except Exception as e :
            self .log (f"SARIF generation failed: {e }","WARNING")


        summary_file =self .output_dir /"ANALYSIS_SUMMARY.txt"
        with open (summary_file ,'w',encoding ='utf-8')as f :
            f .write (f"APK ANALYSIS SUMMARY\n")
            f .write (f"==================\n\n")
            f .write (f"Analysis ID: {self .analysis_id }\n")
            f .write (f"Completed: {self .timestamp }\n")
            f .write (f"APK: {self .apk_path .name }\n")
            f .write (f"Threat Score: {threat_score }/100\n\n")
            f .write (f"📁 Results Location: {self .output_dir }\n")
            f .write (f"📊 Reports: {self .reports_dir }\n")
            f .write (f"🗂️  Artifacts: {self .artifacts_dir }\n")
            f .write (f"📝 Logs: {self .logs_dir }\n\n")
            f .write (f"Components Analyzed:\n")
            f .write (f"✅ File Analysis\n")
            f .write (f"✅ Manifest Analysis (AAPT)\n")
            f .write (f"✅ Permissions Analysis\n")
            f .write (f"✅ Strings Analysis\n")
            f .write (f"✅ Network Intelligence\n")
            f .write (f"✅ Security Assessment\n")

        self .log (f"Reports generated in: {self .reports_dir }")

    def generate_html_report (self ):
        threat_score =self .results ['summary'].get ('threat_score',0 )
        ext_tools =self .results .get ('external_tools',{})or {}
        pkg_name =(
        self .results .get ('manifest_analysis',{})
        .get ('package_info',{})
        .get ('name')
        )

        quick_cmds =[]

        jadx_info =ext_tools .get ('jadx',{})
        if isinstance (jadx_info ,dict )and (jadx_info .get ('available')or False ):
            quick_cmds .append ({
            'label':'Open in JADX-GUI (APK)',
            'cmd':f"jadx-gui {self .apk_path }"
            })

            jadx_dec =ext_tools .get ('jadx_decompile',{})
            out_dir =None 
            if isinstance (jadx_dec ,dict ):
                data =jadx_dec .get ('data',{})or {}
                out_dir =data .get ('out_dir')
            if out_dir :
                quick_cmds .append ({
                'label':'Open Decompiled Sources in JADX-GUI',
                'cmd':f"jadx-gui {out_dir }"
                })

        r2f =ext_tools .get ('radare2_rizin_r2frida',{})
        has_r2 =isinstance (r2f ,dict )and bool (r2f .get ('data',{}).get ('radare2')or r2f .get ('data',{}).get ('rizin'))
        if has_r2 and pkg_name :
            quick_cmds .append ({
            'label':'r2frida attach (USB)',
            'cmd':f"r2 frida://attach/usb/{pkg_name }"
            })
            quick_cmds .append ({
            'label':'r2frida spawn (USB)',
            'cmd':f"r2 frida://spawn/usb/{pkg_name }"
            })

        objection_info =ext_tools .get ('objection',{})
        if isinstance (objection_info ,dict )and (objection_info .get ('available')or False )and pkg_name :
            quick_cmds .append ({
            'label':'Objection Explore',
            'cmd':f"objection -g {pkg_name } explore"
            })


        if threat_score >=70 :
            risk_level ="HIGH"
            risk_color ="#f44336"
            risk_class ="risk-high"
        elif threat_score >=40 :
            risk_level ="MEDIUM"
            risk_color ="#ff9800"
            risk_class ="risk-medium"
        else :
            risk_level ="LOW"
            risk_color ="#4caf50"
            risk_class ="risk-low"

        html_content =f"""
<!DOCTYPE html>
<html>
<head>
    <title>APK Analysis Report - {self .analysis_id }</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .header p {{ margin: 5px 0; opacity: 0.9; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: {risk_color }; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        .section {{ background: white; margin: 20px 0; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .section h2 {{ color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
        .{risk_class } {{ border-left: 5px solid {risk_color }; }}
        .permissions-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }}
        .permission-item {{ background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 3px solid #007bff; }}
        .network-item {{ background: #f8f9fa; padding: 10px; margin: 5px 0; border-radius: 5px; font-family: monospace; }}
        .suspicious {{ background: #ffebee; border-left: 3px solid #f44336; }}
        .tag {{ display: inline-block; background: #e3f2fd; color: #1976d2; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; margin: 2px; }}
        .progress-bar {{ background: #e0e0e0; height: 20px; border-radius: 10px; overflow: hidden; margin: 10px 0; }}
        .progress-fill {{ height: 100%; background: {risk_color }; width: {threat_score }%; transition: width 0.3s ease; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #f5f5f5; font-weight: bold; }}
        .footer {{ text-align: center; margin-top: 30px; color: #666; }}
        .cmd {{ background: #f8f9fa; border: 1px solid #e0e0e0; padding: 8px 10px; border-radius: 6px; font-family: monospace; position: relative; }}
        .copy-btn {{ float: right; margin-left: 8px; background: #1976d2; color: #fff; border: 0; border-radius: 4px; padding: 4px 8px; cursor: pointer; }}
    </style>
    <script>
        function copyText(elementId) {{
            var el = document.getElementById(elementId);
            if (!el) return;
            var text = el.textContent || el.innerText;
            navigator.clipboard.writeText(text);
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔬 APK Analysis Report</h1>
            <p>Analysis ID: {self .analysis_id }</p>
            <p>Generated: {self .timestamp }</p>
            <p>Target: {self .apk_path .name }</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card {risk_class }">
                <div class="stat-value">{threat_score }/100</div>
                <div class="stat-label">Threat Score ({risk_level })</div>
                <div class="progress-bar">
                    <div class="progress-fill"></div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len (self .results .get ('permissions_analysis',{}).get ('dangerous_permissions',[]))}</div>
                <div class="stat-label">Dangerous Permissions</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len (self .results .get ('network_analysis',{}).get ('strings_data',{}).get ('domains',[]))}</div>
                <div class="stat-label">Domains Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len (self .results .get ('network_analysis',{}).get ('network_intelligence',{}).get ('suspicious_indicators',[]))}</div>
                <div class="stat-label">Suspicious Indicators</div>
            </div>
        </div>
"""


        if 'permissions_analysis'in self .results :
            perm_analysis =self .results ['permissions_analysis']
            html_content +=f"""
        <div class="section">
            <h2>🔐 Permissions Analysis</h2>
            <p>Total permissions: {perm_analysis .get ('total_permissions',0 )}</p>
            <div class="permissions-grid">
"""
            for perm in perm_analysis .get ('dangerous_permissions',[])[:10 ]:
                html_content +=f"""
                <div class="permission-item suspicious">
                    <strong>{perm ['permission']}</strong><br>
                    <small>{perm ['description']}</small>
                </div>
"""
            html_content +="""
            </div>
        </div>
"""

        if 'network_analysis'in self .results :
            network =self .results ['network_analysis']
            strings_data =network .get ('strings_data',{})
            html_content +=f"""
        <div class="section">
            <h2>🌐 Network Analysis</h2>
            <h3>Domains</h3>
"""
            for domain in strings_data .get ('domains',[])[:15 ]:
                html_content +=f'<div class="network-item">{domain }</div>'

            html_content +="<h3>URLs</h3>"
            for url in strings_data .get ('urls',[])[:10 ]:
                html_content +=f'<div class="network-item">{url }</div>'

            html_content +="</div>"


        if ext_tools :

            def _row (title :str ,key :str )->str :
                info =ext_tools .get (key ,{})
                if isinstance (info ,dict ):
                    avail ='YES'if info .get ('available')else 'NO'
                    succ ='OK'if info .get ('success')else '—'
                else :
                    avail =succ ='—'
                return f"<tr><td>{title }</td><td>{avail }</td><td>{succ }</td></tr>"

            html_content +="""
        <div class="section">
            <h2>🛠 Tooling Environment</h2>
            <table>
                <thead><tr><th>Tool</th><th>Available</th><th>Ready</th></tr></thead>
                <tbody>
            """
            html_content +=_row ('JADX/JADX-GUI','jadx')
            html_content +=_row ('Radare2/Rizin + r2frida','radare2_rizin_r2frida')
            html_content +=_row ('Objection','objection')
            html_content +=_row ('Xposed/LSPosed (device)','xposed_lsposed')
            html_content +=_row ('Magisk/Zygisk (device)','magisk_zygisk')
            html_content +=_row ('Inspeckage (device)','inspeckage')
            html_content +="""
                </tbody>
            </table>
            <div>
                <h3>Quick commands</h3>
            """
            for idx ,item in enumerate (quick_cmds ):
                el_id =f"cmd_{idx }"
                label =item .get ('label','Command')
                html_content +=f"""
                <div class="cmd-group">
                    <div><strong>{label }</strong></div>
                    <div class="cmd" id="{el_id }">{item ['cmd']}</div>
                    <button class="copy-btn" onclick="copyText('{el_id }')">Copy</button>
                </div>
                <div style="clear: both; height: 6px;"></div>
                """
            html_content +="""
            </div>
        </div>
            """


        env_json_path =self .results .get ('artifacts',{}).get ('environment_checks_json')
        if env_json_path :
            html_content +=f"""
        <div class="section">
            <h2>📄 Environment Checks (JSON)</h2>
            <p><a href="{env_json_path }">Download environment_checks.json</a></p>
        </div>
"""


        html_content +="""
        <div class="footer">
            <p>Generated by Advanced APK Analyzer v6.0</p>
        </div>
    </div>
</body>
</html>
"""

        html_report =self .reports_dir /"analysis_dashboard.html"
        with open (html_report ,'w',encoding ='utf-8')as f :
            f .write (html_content )

    def run_complete_analysis (self )->str :
        start_time =time .time ()

        try :

            set_progress_stage ("Initializing advanced analysis",5 ,f"Analyzing {self .apk_path .name }")


            self .log ("Phase 1: File Analysis")
            set_progress_stage ("Analyzing file structure",15 ,"Computing hashes and file metadata")
            self .results ['file_analysis']=self .get_file_hashes ()


            self .log ("Phase 2: AAPT Analysis")
            set_progress_stage ("Extracting manifest information",25 ,"Analyzing AndroidManifest.xml")
            self .results ['manifest_analysis']=self .run_aapt_analysis ()


            self .log ("Phase 3: Permissions Analysis")
            set_progress_stage ("Analyzing permissions",35 ,"Evaluating security permissions")
            permissions =self .results ['manifest_analysis'].get ('permissions',[])
            self .results ['permissions_analysis']=self .analyze_permissions (permissions )


            self .log ("Phase 4: Strings Analysis")
            set_progress_stage ("Extracting and analyzing strings",50 ,"Searching for URLs, IPs, and sensitive data")
            strings_data =self .run_strings_analysis ()


            self .log ("Phase 5: Network Intelligence")
            set_progress_stage ("Gathering network intelligence",65 ,"Analyzing network communications")
            network_intelligence =self .run_network_intelligence (strings_data )

            self .results ['network_analysis']={
            'strings_data':strings_data ,
            'network_intelligence':network_intelligence 
            }


            self .log ("Phase 6: Advanced Extraction (Optional)")
            set_progress_stage ("Running advanced extraction",75 ,"Decompiling with external tools")
            apktool_results =self .run_apktool_analysis ()
            self .results ['advanced_extraction']=apktool_results 


            self .log ("Phase 6b: External Tools (Optional)")
            set_progress_stage ("Running external security tools",85 ,"Integrating with security scanners")
            try :
                self .results ['external_tools']=self .run_external_integrations ()

                env_json =self .reports_dir /"environment_checks.json"
                with open (env_json ,'w',encoding ='utf-8')as _f :
                    json .dump (self .results .get ('external_tools',{}),_f ,indent =2 ,default =str )
                self .results .setdefault ('artifacts',{})['environment_checks_json']=str (env_json )
            except Exception as e :
                self .log (f"External integrations failed: {e }","WARNING")


            self .results ['summary']={
            'analysis_duration':time .time ()-start_time ,
            'components_completed':[
            'file_analysis',
            'manifest_analysis',
            'permissions_analysis',
            'strings_analysis',
            'network_intelligence',
            'advanced_extraction'
            ],
            'output_directory':str (self .output_dir ),
            'total_files_created':0 
            }


            self .log ("Phase 7: Report Generation")
            set_progress_stage ("Generating comprehensive reports",95 ,"Creating analysis reports")
            self .generate_comprehensive_report ()


            self .results ['summary']['total_files_created']=len (list (self .output_dir .rglob ('*')))


            json_report =self .reports_dir /"comprehensive_report.json"
            with open (json_report ,'w',encoding ='utf-8')as f :
                json .dump (self .results ,f ,indent =2 ,default =str )

            duration =time .time ()-start_time 
            self .log (f"Analysis completed successfully in {duration :.2f} seconds")
            self .log (f"All results consolidated in: {self .output_dir }")


            update_progress (100 ,"Analysis completed successfully")


            try :
                from analyzers .enhanced_data_extractor import EnhancedDataExtractor ,AnalysisConfig 
                cfg =AnalysisConfig (
                apk_path =str (self .apk_path ),
                package_name =self .results .get ('manifest_analysis',{}).get ('package_info',{}).get ('name','')or 
                self .results .get ('manifest_analysis',{}).get ('package_name','')or '',
                output_dir =str (self .artifacts_dir /'enhanced_extraction'),
                timeout =180 ,
                analyze_permissions =True ,
                analyze_resources =True ,
                analyze_strings =True ,
                analyze_cert =True ,
                verbose =False ,
                max_workers =4 ,
                )
                extractor =EnhancedDataExtractor (cfg )

                try :
                    extractor .run ()
                except AttributeError :

                    pass 
            except Exception as _e :
                self .log (f"Enhanced extractor skipped: {_e }","WARNING")

            return str (self .output_dir )

        except Exception as e :
            self .log (f"Analysis failed: {e }","ERROR")
            update_progress (100 ,f"Analysis failed: {str (e )}")
            return f"FAILED: {e }"

def main ():
    if len (sys .argv )!=2 :
        print ("Usage: python advanced_analysis.py <apk_path>")
        sys .exit (1 )

    apk_path =sys .argv [1 ]

    print ("🔬 Advanced APK Analysis Suite v6.0")
    print ("="*50 )

    analyzer =AdvancedAPKAnalyzer (apk_path )
    result =analyzer .run_complete_analysis ()

    if result .startswith ("FAILED"):
        print (f"❌ {result }")
        sys .exit (1 )
    else :
        print ("\n✅ Analysis completed successfully!")
        print (f"📁 Results location: {result }")
        print (f"📊 View reports in: {result }/reports/")
        print (f"📋 Quick summary: {result }/ANALYSIS_SUMMARY.txt")
        print (f"🌐 HTML dashboard: {result }/reports/analysis_dashboard.html")

if __name__ =="__main__":
    main ()
