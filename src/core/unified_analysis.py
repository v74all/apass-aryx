#!/usr/bin/env python3

import sys 
import os 
import json 
import subprocess 
import shutil 
import time 
import hashlib 
import zipfile 
from pathlib import Path 
from datetime import datetime 
from typing import Dict ,List ,Optional ,Any 
import xml .etree .ElementTree as ET 


try :
    from utils .progress_tracker import ProgressTracker ,update_progress ,set_progress_stage 
except ImportError :

    def update_progress (percentage :int ,task :str ,details :Optional [str ]=None ):
        print (f"Progress: {percentage }% - {task }")

    def set_progress_stage (stage_name :str ,percentage :int ,details :Optional [str ]=None ):
        print (f"Stage: {stage_name } ({percentage }%)")

class UnifiedAPKAnalyzer :

    def __init__ (self ,apk_path :str ):
        self .apk_path =Path (apk_path )
        self .timestamp =datetime .now ().strftime ("%Y%m%d_%H%M%S")

        job_id =os .environ .get ("APASS_JOB_ID")
        self .analysis_id =f"{('job_'+job_id +'_')if job_id else ''}unified_analysis_{self .timestamp }"


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
        'analyzer_version':'5.0'
        },
        'static_analysis':{},
        'dynamic_analysis':{},
        'network_analysis':{},
        'yara_matches':{},
        'threat_intelligence':{},
        'artifacts':{},
        'summary':{}
        }

        self .log_file =self .logs_dir /"unified_analysis.log"
        self .log (f"Unified APK Analysis started for: {self .apk_path }")

    def log (self ,message :str ,level :str ="INFO"):
        timestamp =datetime .now ().strftime ("%Y-%m-%d %H:%M:%S")
        log_entry =f"[{timestamp }] {level }: {message }\n"
        print (f"[{level }] {message }")

        with open (self .log_file ,'a',encoding ='utf-8')as f :
            f .write (log_entry )

    def validate_apk (self )->bool :
        if not self .apk_path .exists ():
            self .log (f"APK file not found: {self .apk_path }","ERROR")
            return False 

        if not self .apk_path .suffix .lower ()=='.apk':
            self .log (f"File is not an APK: {self .apk_path }","ERROR")
            return False 


        try :
            with zipfile .ZipFile (self .apk_path ,'r')as zf :
                if 'AndroidManifest.xml'not in zf .namelist ():
                    self .log ("Invalid APK: AndroidManifest.xml not found","ERROR")
                    return False 
        except zipfile .BadZipFile :
            self .log ("Invalid APK: Not a valid ZIP file","ERROR")
            return False 

        self .log ("APK validation successful")
        return True 

    def run_basic_extraction (self )->Dict [str ,Any ]:
        self .log ("Running basic APK extraction...")

        extraction_results ={
        'file_info':{},
        'manifest_info':{},
        'certificate_info':{},
        'extracted_files':[]
        }


        with open (self .apk_path ,'rb')as f :
            content =f .read ()
            extraction_results ['file_info']={
            'size':len (content ),
            'md5':hashlib .md5 (content ).hexdigest (),
            'sha1':hashlib .sha1 (content ).hexdigest (),
            'sha256':hashlib .sha256 (content ).hexdigest ()
            }


        extract_dir =self .artifacts_dir /"extracted_apk"
        extract_dir .mkdir (exist_ok =True )

        try :
            with zipfile .ZipFile (self .apk_path ,'r')as zf :
                zf .extractall (extract_dir )
                extraction_results ['extracted_files']=zf .namelist ()
        except Exception as e :
            self .log (f"Failed to extract APK: {e }","ERROR")


        try :
            result =subprocess .run ([
            'aapt','dump','badging',str (self .apk_path )
            ],capture_output =True ,text =True ,timeout =60 )

            if result .returncode ==0 :
                badging_file =self .artifacts_dir /"badging.txt"
                with open (badging_file ,'w')as f :
                    f .write (result .stdout )


                for line in result .stdout .split ('\n'):
                    if line .startswith ('package:'):
                        parts =line .split ()
                        for part in parts :
                            if part .startswith ('name='):
                                extraction_results ['manifest_info']['package_name']=part .split ('=')[1 ].strip ("'\"")
                            elif part .startswith ('versionCode='):
                                extraction_results ['manifest_info']['version_code']=part .split ('=')[1 ].strip ("'\"")
                            elif part .startswith ('versionName='):
                                extraction_results ['manifest_info']['version_name']=part .split ('=')[1 ].strip ("'\"")
        except Exception as e :
            self .log (f"AAPT analysis failed: {e }","WARNING")

        return extraction_results 

    def run_static_analysis (self )->Dict [str ,Any ]:
        self .log ("Running static analysis...")

        static_results ={
        'permissions':[],
        'activities':[],
        'services':[],
        'receivers':[],
        'providers':[],
        'strings':[],
        'urls':[],
        'suspicious_api_calls':[],
        'native_libraries':[]
        }


        static_analyzer_path =Path ("tools/python/enhanced_static_analyzer.py")
        if static_analyzer_path .exists ():
            try :
                result =subprocess .run ([
                sys .executable ,str (static_analyzer_path ),
                str (self .apk_path ),"com.xnotice.app"
                ],capture_output =True ,text =True ,timeout =300 ,cwd =Path .cwd ())

                if result .returncode ==0 :
                    self .log ("Static analysis completed successfully")

                    try :
                        output_data =json .loads (result .stdout )
                        static_results .update (output_data )
                    except json .JSONDecodeError :
                        static_results ['raw_output']=result .stdout 
                else :
                    self .log (f"Static analysis failed: {result .stderr }","ERROR")
                    static_results ['error']=result .stderr 
            except Exception as e :
                self .log (f"Failed to run static analyzer: {e }","ERROR")


        try :
            with zipfile .ZipFile (self .apk_path ,'r')as zf :
                for file_info in zf .filelist :
                    if file_info .filename .endswith ('.dex'):
                        with zf .open (file_info )as dex_file :
                            content =dex_file .read ()

                            strings =[]
                            current_string =""
                            for byte in content :
                                if 32 <=byte <=126 :
                                    current_string +=chr (byte )
                                else :
                                    if len (current_string )>5 :
                                        strings .append (current_string )
                                    current_string =""


                            interesting_strings =[]
                            for s in strings [:1000 ]:
                                if any (keyword in s .lower ()for keyword in 
                                ['http','https','api','key','password','token','secret']):
                                    interesting_strings .append (s )

                            static_results ['strings'].extend (interesting_strings )
        except Exception as e :
            self .log (f"Manual string extraction failed: {e }","WARNING")

        return static_results 

    def run_network_analysis (self )->Dict [str ,Any ]:
        self .log ("Running network analysis...")

        network_results ={
        'domains':[],
        'ip_addresses':[],
        'urls':[],
        'ssl_certificates':[],
        'network_security_config':{}
        }


        try :

            result =subprocess .run ([
            'strings',str (self .apk_path )
            ],capture_output =True ,text =True ,timeout =60 )

            if result .returncode ==0 :
                strings_content =result .stdout 


                import re 
                url_pattern =r'https?://[^\s<>"\'`|()[\]{}]+'
                domain_pattern =r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                ip_pattern =r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

                urls =re .findall (url_pattern ,strings_content )
                domains =re .findall (domain_pattern ,strings_content )
                ips =re .findall (ip_pattern ,strings_content )

                network_results ['urls']=list (set (urls ))
                network_results ['domains']=list (set (domains ))
                network_results ['ip_addresses']=list (set (ips ))

        except Exception as e :
            self .log (f"Network analysis failed: {e }","WARNING")

        return network_results 

    def run_security_analysis (self )->Dict [str ,Any ]:
        self .log ("Running security analysis...")

        security_results ={
        'threat_indicators':[],
        'suspicious_permissions':[],
        'crypto_usage':[],
        'anti_analysis':[],
        'risk_score':0 
        }


        if 'permissions'in self .results .get ('static_analysis',{}):
            suspicious_perms =[
            'SYSTEM_ALERT_WINDOW','DEVICE_ADMIN','BIND_DEVICE_ADMIN',
            'CAMERA','RECORD_AUDIO','ACCESS_FINE_LOCATION',
            'READ_SMS','SEND_SMS','CALL_PHONE','READ_CONTACTS'
            ]

            for perm in self .results ['static_analysis']['permissions']:
                if any (sus in perm for sus in suspicious_perms ):
                    security_results ['suspicious_permissions'].append (perm )


        risk_score =0 
        risk_score +=len (security_results ['suspicious_permissions'])*2 
        risk_score +=len (security_results ['threat_indicators'])*3 

        security_results ['risk_score']=min (risk_score ,100 )

        return security_results 

    def run_threat_intelligence (self )->Dict [str ,Any ]:
        self .log ("Running threat intelligence enrichment...")
        ti_summary :Dict [str ,Any ]={
        'risk_score':0 ,
        'ioc_count':0 ,
        'categories':[],
        'recommendations':[],
        'iocs':[]
        }
        try :

            from utils .threat_intelligence import ThreatIntelligence 
        except Exception as e :
            self .log (f"Threat intelligence not available: {e }","INFO")
            return ti_summary 

        try :
            ti =ThreatIntelligence ()
            iocs :list [tuple [str ,str ]]=[]
            net =self .results .get ('network_analysis',{})or {}
            for d in net .get ('domains',[])or []:
                if isinstance (d ,str ):
                    iocs .append ((d ,'domain'))
            for ip in net .get ('ip_addresses',[])or []:
                if isinstance (ip ,str ):
                    iocs .append ((ip ,'ip'))
            for u in net .get ('urls',[])or []:
                if isinstance (u ,str ):
                    iocs .append ((u ,'url'))


            file_info =(self .results .get ('artifacts',{})or {}).get ('file_info',{})
            sha256 =file_info .get ('sha256')if isinstance (file_info ,dict )else None 
            if isinstance (sha256 ,str ):
                iocs .append ((sha256 ,'hash'))

            if not iocs :
                return ti_summary 

            analyzed =ti .batch_analyze_iocs (iocs )
            report =ti .generate_threat_report (analyzed )
            ti_summary .update ({
            'risk_score':report .risk_score ,
            'ioc_count':len (report .iocs ),
            'categories':report .threat_categories ,
            'recommendations':report .recommendations ,
            'iocs':[
            {
            'value':i .value ,
            'type':i .type ,
            'confidence':i .confidence ,
            'threat_types':i .threat_types ,
            'tags':i .tags ,
            'source':i .source ,
            'first_seen':i .first_seen ,
            'last_seen':i .last_seen ,
            }for i in report .iocs 
            ]
            })


            try :
                (self .reports_dir /"threat_intel_report.json").write_text (
                json .dumps (ti_summary ,indent =2 ),encoding ='utf-8'
                )
            except Exception :
                pass 

        except Exception as e :
            self .log (f"Threat intelligence enrichment failed: {e }","WARNING")

        return ti_summary 

    def run_yara_scan (self )->Dict [str ,Any ]:
        self .log ("Running YARA scan...")
        findings :Dict [str ,Any ]={"matches":[]}
        try :
            import yara 
        except Exception as e :
            self .log (f"YARA not available: {e }","WARNING")
            return findings 


        rules_root_candidates =[
        Path .cwd ()/"resources"/"yara",
        Path (__file__ ).resolve ().parent .parent .parent /"resources"/"yara",
        ]
        rules_files :list [Path ]=[]
        for root in rules_root_candidates :
            try :
                if root .exists ():
                    rules_files .extend ([p for p in root .rglob ("*.yar")])
            except Exception :
                pass 

        if not rules_files :
            self .log ("No YARA rules found","INFO")
            return findings 


        try :
            rules_map ={f"r{i }":str (p )for i ,p in enumerate (rules_files )}
            rules =yara .compile (filepaths =rules_map )
        except Exception as e :
            self .log (f"Failed to compile YARA rules: {e }","WARNING")
            return findings 


        targets :list [Path ]=[self .apk_path ]
        try :
            if self .artifacts_dir .exists ():
                for p in self .artifacts_dir .rglob ("*"):
                    if p .is_file ()and p .stat ().st_size <=10 *1024 *1024 :
                        targets .append (p )
        except Exception :
            pass 

        for t in targets :
            try :
                matches =rules .match (str (t ))
                for m in matches or []:
                    findings ["matches"].append ({
                    "rule":getattr (m ,"rule","unknown"),
                    "tags":list (getattr (m ,"tags",[])or []),
                    "meta":dict (getattr (m ,"meta",{})or {}),
                    "target":str (t )
                    })
            except Exception :

                continue 

        self .log (f"YARA scan complete with {len (findings ['matches'])} matches")
        return findings 

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
                    seq =list (obj )
                    return _sanitize (seq ,max_items )
                if isinstance (obj ,Path ):
                    return str (obj )
                return obj 
            except Exception :
                return str (obj )


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
                f .write ("COMPREHENSIVE APK ANALYSIS REPORT\n")
                f .write ("="*50 +"\n\n")
                f .write (f"Analysis ID: {self .analysis_id }\n")
                f .write (f"Timestamp: {self .timestamp }\n")
                f .write (f"APK Path: {self .apk_path }\n\n")


                if 'metadata'in self .results :
                    f .write ("METADATA:\n")
                    f .write ("-"*20 +"\n")
                    for key ,value in (self .results .get ('metadata')or {}).items ():
                        f .write (f"{key }: {value }\n")
                    f .write ("\n")


                if 'static_analysis'in self .results :
                    f .write ("STATIC ANALYSIS:\n")
                    f .write ("-"*20 +"\n")
                    static =self .results .get ('static_analysis')or {}

                    if 'permissions'in static :
                        f .write (f"Permissions ({len (static .get ('permissions',[]))}):\n")
                        for perm in (static .get ('permissions')or [])[:20 ]:
                            f .write (f"  - {perm }\n")
                        f .write ("\n")

                    if 'urls'in static :
                        f .write (f"URLs Found ({len (static .get ('urls',[]))}):\n")
                        for url in (static .get ('urls')or [])[:10 ]:
                            f .write (f"  - {url }\n")
                        f .write ("\n")


                if 'network_analysis'in self .results :
                    f .write ("NETWORK ANALYSIS:\n")
                    f .write ("-"*20 +"\n")
                    network =self .results .get ('network_analysis')or {}

                    if 'domains'in network :
                        f .write (f"Domains ({len (network .get ('domains',[]))}):\n")
                        for domain in (network .get ('domains')or [])[:10 ]:
                            f .write (f"  - {domain }\n")
                        f .write ("\n")


                if 'security_analysis'in self .results :
                    f .write ("SECURITY ANALYSIS:\n")
                    f .write ("-"*20 +"\n")
                    security =self .results .get ('security_analysis')or {}
                    f .write (f"Risk Score: {security .get ('risk_score',0 )}/100\n")

                    if 'suspicious_permissions'in security :
                        f .write (f"Suspicious Permissions ({len (security .get ('suspicious_permissions',[]))}):\n")
                        for perm in (security .get ('suspicious_permissions')or [])[:50 ]:
                            f .write (f"  - {perm }\n")
                    f .write ("\n")


                ym =self .results .get ('yara_matches',{})
                if ym and ym .get ('matches'):
                    f .write ("YARA MATCHES:\n")
                    f .write ("-"*20 +"\n")
                    for m in (ym .get ('matches',[])or [])[:50 ]:
                        try :
                            rule =m .get ('rule')
                            target =m .get ('target')
                            tags =",".join (m .get ('tags',[]))
                            f .write (f"  - rule={rule } tags=[{tags }] file={target }\n")
                        except Exception :
                            continue 
                    f .write ("\n")
        except Exception as e :
            self .log (f"Failed to write text report: {e }","WARNING")


        html_report =self .reports_dir /"comprehensive_report.html"
        try :
            self .generate_html_report (html_report )
        except Exception as e :
            self .log (f"Failed to generate HTML report: {e }","WARNING")

        try :
            dash_report =self .reports_dir /"analysis_dashboard.html"
            if html_report .exists ():
                dash_report .write_text (html_report .read_text (encoding ='utf-8'),encoding ='utf-8')
        except Exception as e :
            self .log (f"Failed to mirror HTML report to dashboard name: {e }","WARNING")


        try :
            csv_path =self .reports_dir /"summary.csv"
            lines =[
            "metric,value",
            f"risk_score,{self .results .get ('security_analysis',{}).get ('risk_score',0 )}",
            f"permissions,{len (self .results .get ('static_analysis',{}).get ('permissions',[]))}",
            f"urls,{len (self .results .get ('network_analysis',{}).get ('urls',[]))}",
            f"domains,{len (self .results .get ('network_analysis',{}).get ('domains',[]))}",
            f"ip_addresses,{len (self .results .get ('network_analysis',{}).get ('ip_addresses',[]))}",
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
            "tool":{"driver":{"name":"APASS ARYX Unified Analyzer","version":"5.0"}},
            "results":[]
            }
            ]
            }
            results =sarif ["runs"][0 ]["results"]

            for perm in self .results .get ('security_analysis',{}).get ('suspicious_permissions',[])or []:
                results .append ({
                "ruleId":"suspicious-permission",
                "level":"warning",
                "message":{"text":f"Suspicious permission: {perm }"},
                "locations":[
                {"physicalLocation":{"artifactLocation":{"uri":str (self .apk_path )}}}
                ]
                })

            for url in self .results .get ('network_analysis',{}).get ('urls',[])or []:
                if isinstance (url ,str )and url .lower ().startswith ('http://'):
                    results .append ({
                    "ruleId":"insecure-url",
                    "level":"note",
                    "message":{"text":f"Non-HTTPS URL found: {url }"},
                    "locations":[
                    {"physicalLocation":{"artifactLocation":{"uri":str (self .apk_path )}}}
                    ]
                    })
            (self .reports_dir /"findings.sarif").write_text (json .dumps (sarif ,indent =2 ),encoding ='utf-8')
        except Exception as e :
            self .log (f"SARIF generation failed: {e }","WARNING")

        self .log (f"Reports generated in: {self .reports_dir }")

    def generate_html_report (self ,output_path :Path ):
        html_content =f"""
<!DOCTYPE html>
<html>
<head>
    <title>APK Analysis Report - {self .analysis_id }</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .risk-high {{ background: #ffebee; border-left: 5px solid #f44336; }}
        .risk-medium {{ background: #fff3e0; border-left: 5px solid #ff9800; }}
        .risk-low {{ background: #e8f5e8; border-left: 5px solid #4caf50; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f5f5f5; }}
        .code {{ background: #f5f5f5; padding: 10px; border-radius: 3px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔬 APK Analysis Report</h1>
        <p>Analysis ID: {self .analysis_id }</p>
        <p>Generated: {self .timestamp }</p>
        <p>Target: {self .apk_path .name }</p>
    </div>
    
    <div class="section">
        <h2>📋 Summary</h2>
        <p>Risk Score: <strong>{self .results .get ('security_analysis',{}).get ('risk_score',0 )}/100</strong></p>
        <p>Analysis completed with unified analyzer v5.0</p>
    </div>
    
    <div class="section">
        <h2>📊 Analysis Components</h2>
        <ul>
            <li>✅ Basic Extraction and Metadata</li>
            <li>✅ Static Analysis</li>
            <li>✅ Network Analysis</li>
            <li>✅ Security Analysis</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>📁 Output Files</h2>
        <ul>
            <li>JSON Report: comprehensive_report.json</li>
            <li>Text Report: comprehensive_report.txt</li>
            <li>HTML Report: comprehensive_report.html</li>
            <li>Artifacts: artifacts/ directory</li>
            <li>Logs: logs/ directory</li>
        </ul>
    </div>
</body>
</html>
        """

        with open (output_path ,'w',encoding ='utf-8')as f :
            f .write (html_content )

    def run_complete_analysis (self )->str :
        start_time =time .time ()

        try :

            set_progress_stage ("Initializing analysis",5 ,f"Analyzing {self .apk_path .name }")


            set_progress_stage ("Validating APK file",10 ,"Checking file structure and integrity")
            if not self .validate_apk ():
                return "FAILED: APK validation failed"


            set_progress_stage ("Extracting APK contents",25 ,"Extracting and analyzing APK structure")
            self .results ['artifacts']=self .run_basic_extraction ()


            set_progress_stage ("Performing static analysis",45 ,"Analyzing code structure and permissions")
            self .results ['static_analysis']=self .run_static_analysis ()


            set_progress_stage ("Analyzing network components",65 ,"Examining network usage and communications")
            self .results ['network_analysis']=self .run_network_analysis ()


            set_progress_stage ("Running security analysis",75 ,"Scanning for security issues and vulnerabilities")
            self .results ['security_analysis']=self .run_security_analysis ()


            set_progress_stage ("Scanning for malware patterns",85 ,"Running YARA signature matching")
            self .results ['yara_matches']=self .run_yara_scan ()


            set_progress_stage ("Enriching with threat intelligence",90 ,"Checking against threat databases")
            self .results ['threat_intelligence']=self .run_threat_intelligence ()

            try :
                sec =self .results .get ('security_analysis',{})
                ti =self .results .get ('threat_intelligence',{})
                if isinstance (sec ,dict )and isinstance (ti ,dict ):
                    sec ['risk_score']=max (float (sec .get ('risk_score',0 )),float (ti .get ('risk_score',0 )))
                    self .results ['security_analysis']=sec 
            except Exception :
                pass 


            self .results ['summary']={
            'analysis_duration':time .time ()-start_time ,
            'components_completed':[
            'basic_extraction',
            'static_analysis',
            'network_analysis',
            'security_analysis'
            ],
            'output_directory':str (self .output_dir ),
            'total_files_created':len (list (self .output_dir .rglob ('*')))
            }


            set_progress_stage ("Generating comprehensive reports",95 ,"Creating final analysis reports")
            self .generate_comprehensive_report ()


            update_progress (100 ,"Analysis completed successfully")

            self .log (f"Analysis completed successfully in {time .time ()-start_time :.2f} seconds")
            self .log (f"All results consolidated in: {self .output_dir }")

            return str (self .output_dir )

        except Exception as e :
            self .log (f"Analysis failed: {e }","ERROR")
            update_progress (100 ,f"Analysis failed: {str (e )}")
            return f"FAILED: {e }"

def main ():
    if len (sys .argv )!=2 :
        print ("Usage: python unified_analysis.py <apk_path>")
        sys .exit (1 )

    apk_path =sys .argv [1 ]
    analyzer =UnifiedAPKAnalyzer (apk_path )
    result =analyzer .run_complete_analysis ()

    if result .startswith ("FAILED"):
        print (f"❌ {result }")
        sys .exit (1 )
    else :
        print (f"✅ Analysis completed successfully!")
        print (f"📁 Results location: {result }")
        print (f"📊 View reports in: {result }/reports/")

if __name__ =="__main__":
    main ()
