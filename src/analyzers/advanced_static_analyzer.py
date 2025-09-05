#!/usr/bin/env python3

import os 
import sys 
import json 
import hashlib 
import zipfile 
import xml .etree .ElementTree as ET 
import re 
import subprocess 
import tempfile 
from pathlib import Path 
import argparse 
from datetime import datetime 

import logging 
import shutil 
from concurrent .futures import ThreadPoolExecutor ,as_completed 
from urllib .parse import urlparse 
import ipaddress 

class AdvancedAPKAnalyzer :
    def __init__ (self ,apk_path ,*,threads =4 ,timeout =30 ,max_strings =50000 ):
        self .apk_path =apk_path 

        self .threads =max (1 ,threads )
        self .timeout =timeout 
        self .max_strings =max (1 ,max_strings )

        self ._string_set =set ()
        self ._url_set =set ()
        self ._domain_set =set ()
        self ._ip_set =set ()
        self .analysis_results ={
        'metadata':{
        'timestamp':datetime .now ().isoformat (),
        'apk_path':apk_path ,
        'file_size':0 ,
        'file_hashes':{}
        },
        'manifest_analysis':{},
        'certificate_analysis':{},
        'code_analysis':{
        'strings':[],
        'urls':[],
        'suspicious_patterns':[],
        'crypto_indicators':[]
        },
        'resource_analysis':{},
        'native_analysis':{},
        'security_analysis':{
        'permissions':[],
        'dangerous_permissions':[],
        'components':[],
        'exported_components':[]
        },

        'network_analysis':{
        'domains':[],
        'ips':[],
        'http_urls':[],
        'https_urls':[]
        },
        'stats':{
        'total_strings':0 ,
        'unique_strings':0 
        },
        'threat_indicators':[],
        'recommendations':[]
        }

    def calculate_file_hashes (self ):
        print ("[*] Calculating file hashes...")
        if not os .path .exists (self .apk_path ):
            print (f"[!] APK file not found: {self .apk_path }")
            return 
        self .analysis_results ['metadata']['file_size']=os .path .getsize (self .apk_path )
        hash_algorithms =['md5','sha1','sha256','sha512']

        hashers ={algo :hashlib .new (algo )for algo in hash_algorithms }
        try :
            with open (self .apk_path ,'rb')as f :
                for chunk in iter (lambda :f .read (1024 *1024 ),b''):
                    for h in hashers .values ():
                        h .update (chunk )
            for algo ,h in hashers .items ():
                self .analysis_results ['metadata']['file_hashes'][algo ]=h .hexdigest ()
            print (f"    SHA256: {self .analysis_results ['metadata']['file_hashes']['sha256']}")
        except Exception as e :
            print (f"[!] Error hashing file: {e }")

    def extract_and_analyze_manifest (self ):
        print ("[*] Analyzing AndroidManifest.xml...")
        try :

            aapt =shutil .which ('aapt')or shutil .which ('aapt2')
            if not aapt :
                print ("[!] aapt/aapt2 not found. Install Android SDK build-tools")
                self ._fallback_manifest_analysis ()
                return 
            result =subprocess .run (
            [aapt ,'dump','xmltree',self .apk_path ,'AndroidManifest.xml'],
            capture_output =True ,text =True ,timeout =self .timeout 
            )
            if result .returncode ==0 :
                manifest_content =result .stdout 
                self .analysis_results ['manifest_analysis']['raw_dump']=manifest_content 
                self ._extract_manifest_info (manifest_content )
            else :
                print ("[!] aapt failed, using fallback manifest analysis")
                self ._fallback_manifest_analysis ()
        except subprocess .TimeoutExpired :
            print ("[!] aapt command timed out")
        except FileNotFoundError :
            print ("[!] aapt not found. Install Android SDK build-tools")
            self ._fallback_manifest_analysis ()

    def _extract_manifest_info (self ,manifest_content ):
        lines =manifest_content .split ('\n')
        for line in lines :

            if 'package='in line :
                package_match =re .search (r'package="([^"]+)"',line )
                if package_match :
                    self .analysis_results ['manifest_analysis']['package_name']=package_match .group (1 )


            if 'versionName='in line :
                version_match =re .search (r'versionName="([^"]+)"',line )
                if version_match :
                    self .analysis_results ['manifest_analysis']['version_name']=version_match .group (1 )

            if 'versionCode='in line :
                version_match =re .search (r'versionCode=\(0x([0-9a-f]+)\)',line )
                if version_match :
                    self .analysis_results ['manifest_analysis']['version_code']=int (version_match .group (1 ),16 )


            if 'uses-permission'in line :
                perm_match =re .search (r'name="([^"]+)"',line )
                if perm_match :
                    permission =perm_match .group (1 )
                    self .analysis_results ['security_analysis']['permissions'].append (permission )


                    if self ._is_dangerous_permission (permission ):
                        self .analysis_results ['security_analysis']['dangerous_permissions'].append (permission )


            if any (comp in line for comp in ['activity','service','receiver','provider']):
                if 'name='in line :
                    comp_match =re .search (r'name="([^"]+)"',line )
                    if comp_match :
                        exported =(
                        'exported="true"'in line or 
                        'exported=(0x1)'in line or 
                        'exported=true'in line 
                        )
                        component ={
                        'name':comp_match .group (1 ),
                        'type':self ._extract_component_type (line ),
                        'exported':exported 
                        }
                        self .analysis_results ['security_analysis']['components'].append (component )
                        if component ['exported']:
                            self .analysis_results ['security_analysis']['exported_components'].append (component )





    def _is_dangerous_permission (self ,permission ):
        dangerous_perms =[
        'READ_SMS','SEND_SMS','RECEIVE_SMS','READ_CONTACTS','WRITE_CONTACTS',
        'READ_CALL_LOG','WRITE_CALL_LOG','CALL_PHONE','READ_PHONE_STATE',
        'CAMERA','RECORD_AUDIO','ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION',
        'READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE','SYSTEM_ALERT_WINDOW',
        'WRITE_SETTINGS','INSTALL_PACKAGES','DELETE_PACKAGES'
        ]
        return any (perm in permission for perm in dangerous_perms )

    def _extract_component_type (self ,line ):
        if 'activity'in line :
            return 'activity'
        elif 'service'in line :
            return 'service'
        elif 'receiver'in line :
            return 'receiver'
        elif 'provider'in line :
            return 'provider'
        return 'unknown'

    def _fallback_manifest_analysis (self ):
        try :
            with zipfile .ZipFile (self .apk_path ,'r')as zip_file :

                if 'AndroidManifest.xml'in zip_file .namelist ():
                    manifest_data =zip_file .read ('AndroidManifest.xml')
                    self .analysis_results ['manifest_analysis']['raw_size']=len (manifest_data )
                    self .analysis_results ['manifest_analysis']['note']='Binary manifest - needs aapt for full analysis'
        except Exception as e :
            print (f"[!] Fallback manifest analysis failed: {e }")

    def analyze_certificate (self ):
        print ("[*] Analyzing signing certificate...")
        try :
            result =subprocess .run (
            ['keytool','-printcert','-jarfile',self .apk_path ],
            capture_output =True ,text =True ,timeout =self .timeout 
            )
            if result .returncode ==0 :
                cert_info =result .stdout 
                self .analysis_results ['certificate_analysis']['raw_output']=cert_info 
                self ._parse_certificate_info (cert_info )
        except subprocess .TimeoutExpired :
            print ("[!] keytool command timed out")
        except FileNotFoundError :
            print ("[!] keytool not found. Install Java JDK")

    def _parse_certificate_info (self ,cert_info ):
        lines =cert_info .split ('\n')

        for line in lines :
            line =line .strip ()
            if line .startswith ('Owner:'):
                self .analysis_results ['certificate_analysis']['owner']=line [7 :].strip ()
            elif line .startswith ('Issuer:'):
                self .analysis_results ['certificate_analysis']['issuer']=line [8 :].strip ()
            elif line .startswith ('Serial number:'):
                self .analysis_results ['certificate_analysis']['serial']=line [15 :].strip ()
            elif line .startswith ('Valid from:'):
                self .analysis_results ['certificate_analysis']['valid_from']=line [12 :].strip ()
            elif 'SHA256:'in line :
                sha256_match =re .search (r'SHA256:\s*([A-F0-9:]+)',line )
                if sha256_match :
                    self .analysis_results ['certificate_analysis']['sha256']=sha256_match .group (1 )

    def extract_strings (self ):
        print ("[*] Extracting strings...")
        self ._extract_dex_strings ()
        self ._extract_resource_strings ()
        self ._extract_native_strings ()

    def _extract_dex_strings (self ):
        try :
            with zipfile .ZipFile (self .apk_path ,'r')as zip_file :
                dex_files =[f for f in zip_file .namelist ()if f .endswith ('.dex')]
                if not dex_files :
                    return 

                def process_dex (dex_name ):
                    try :
                        dex_data =zip_file .read (dex_name )
                        with tempfile .NamedTemporaryFile ()as temp_file :
                            temp_file .write (dex_data )
                            temp_file .flush ()
                            try :
                                result =subprocess .run (
                                ['strings','-n','4',temp_file .name ],
                                capture_output =True ,text =True ,timeout =self .timeout 
                                )
                                if result .returncode ==0 :
                                    strings =result .stdout .split ('\n')
                                    self ._analyze_strings (strings ,'dex')
                                else :
                                    self ._manual_string_extraction (dex_data ,'dex')
                            except (subprocess .TimeoutExpired ,FileNotFoundError ):
                                self ._manual_string_extraction (dex_data ,'dex')
                    except Exception as e :
                        print (f"[!] Failed processing {dex_name }: {e }")

                with ThreadPoolExecutor (max_workers =self .threads )as ex :
                    futures =[ex .submit (process_dex ,d )for d in dex_files ]
                    for _ in as_completed (futures ):
                        pass 
        except Exception as e :
            print (f"[!] DEX string extraction failed: {e }")

    def _extract_resource_strings (self ):
        try :
            with zipfile .ZipFile (self .apk_path ,'r')as zip_file :
                xml_files =[f for f in zip_file .namelist ()if f .endswith ('.xml')]
                for xml_file in xml_files :
                    try :
                        xml_data =zip_file .read (xml_file )
                        if b'string'in xml_data :
                            readable_strings =re .findall (rb'[\x20-\x7E]{4,}',xml_data )
                            for s in readable_strings :
                                try :
                                    decoded =s .decode ('utf-8')

                                    self ._track_string (decoded ,'resource')
                                    self ._analyze_strings ([decoded ],'resource')
                                except UnicodeDecodeError :
                                    pass 
                    except :
                        continue 
        except Exception as e :
            print (f"[!] Resource string extraction failed: {e }")

    def _extract_native_strings (self ):
        try :
            with zipfile .ZipFile (self .apk_path ,'r')as zip_file :
                so_files =[f for f in zip_file .namelist ()if f .endswith ('.so')]
                if not so_files :
                    return 

                def process_so (so_name ):
                    try :
                        so_data =zip_file .read (so_name )
                        strings =re .findall (rb'[\x20-\x7E]{4,}',so_data )
                        for s in strings :
                            try :
                                decoded =s .decode ('utf-8')
                                self ._track_string (decoded ,'native')
                                self ._analyze_strings ([decoded ],'native')
                            except UnicodeDecodeError :
                                pass 
                    except Exception as e :
                        print (f"[!] Failed processing {so_name }: {e }")

                with ThreadPoolExecutor (max_workers =self .threads )as ex :
                    futures =[ex .submit (process_so ,s )for s in so_files ]
                    for _ in as_completed (futures ):
                        pass 
        except Exception as e :
            print (f"[!] Native string extraction failed: {e }")

    def _analyze_strings (self ,strings ,source_type ):
        url_pattern =re .compile (r'\bhttps?://[^\s"\'<>)\]]+')
        crypto_patterns =[
        r'[A-Za-z0-9+/]{32,}={0,2}',
        r'\b[a-fA-F0-9]{32,}\b',
        r'-----BEGIN [A-Z ]+-----',
        ]
        suspicious_keywords =[
        'shell','su','busybox','root','xposed','frida','debug',
        'emulator','genymotion','bluestacks','nox','memu',
        'decrypt','encrypt','crypto','cipher','aes','rsa',
        'payload','exploit','backdoor','trojan','virus',
        'c2','command','control','bot','rat',

        'api_key','apikey','password','passwd','secret','token','bearer','authorization',
        ]
        ip_v4_pattern =re .compile (r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

        for string in strings :
            if not string or not str (string ).strip ():
                continue 
            s =str (string )


            self ._track_string (s ,source_type )


            for url in url_pattern .findall (s ):
                self ._add_url (url ,source_type )


            for candidate in ip_v4_pattern .findall (s ):
                self ._maybe_add_ip (candidate )


            for pattern in crypto_patterns :
                if re .search (pattern ,s ):
                    self .analysis_results ['code_analysis']['crypto_indicators'].append ({
                    'string':s ,'pattern':pattern ,'source':source_type 
                    })
                    break 


            low =s .lower ()
            for keyword in suspicious_keywords :
                if keyword in low :
                    self .analysis_results ['code_analysis']['suspicious_patterns'].append ({
                    'string':s ,'keyword':keyword ,'source':source_type 
                    })


    def _track_string (self ,s ,source_type ):
        if self .analysis_results ['stats']['total_strings']>=self .max_strings :
            return 
        if s in self ._string_set :
            return 
        self ._string_set .add (s )
        self .analysis_results ['stats']['total_strings']+=1 
        self .analysis_results ['stats']['unique_strings']=len (self ._string_set )
        self .analysis_results ['code_analysis']['strings'].append ({
        'value':s ,'source':source_type ,'type':'general'
        })

    def _add_url (self ,url ,source_type ):
        if url in self ._url_set :
            return 
        self ._url_set .add (url )
        parsed =None 
        try :
            parsed =urlparse (url )
        except Exception :
            parsed =None 
        if parsed :
            host =parsed .hostname 
            if host :
                self ._add_domain (host )
        scheme =(parsed .scheme .lower ()if parsed and parsed .scheme else '')
        if scheme =='http':
            self .analysis_results ['network_analysis']['http_urls'].append (url )
        elif scheme =='https':
            self .analysis_results ['network_analysis']['https_urls'].append (url )
        self .analysis_results ['code_analysis']['urls'].append ({'url':url ,'source':source_type })

    def _add_domain (self ,domain ):
        if domain not in self ._domain_set :
            self ._domain_set .add (domain )
            self .analysis_results ['network_analysis']['domains'].append (domain )

    def _maybe_add_ip (self ,candidate ):
        try :
            ip =ipaddress .ip_address (candidate )
            ip_str =str (ip )
        except ValueError :
            return 
        if ip_str not in self ._ip_set :
            self ._ip_set .add (ip_str )
            self .analysis_results ['network_analysis']['ips'].append (ip_str )

    def generate_threat_assessment (self ):
        print ("[*] Generating threat assessment...")
        threat_score =0 
        threats =[]


        dangerous_count =len (self .analysis_results ['security_analysis']['dangerous_permissions'])
        if dangerous_count >0 :
            threat_score +=dangerous_count *10 
            threats .append (f"Requests {dangerous_count } dangerous permissions")


        exported_count =len (self .analysis_results ['security_analysis']['exported_components'])
        if exported_count >5 :
            threat_score +=15 
            threats .append (f"Has {exported_count } exported components")


        suspicious_count =len (self .analysis_results ['code_analysis']['suspicious_patterns'])
        if suspicious_count >0 :
            threat_score +=min (30 ,suspicious_count *2 )
            threats .append (f"Contains {suspicious_count } suspicious strings")


        crypto_count =len (self .analysis_results ['code_analysis']['crypto_indicators'])
        if crypto_count >5 :
            threat_score +=10 
            threats .append (f"Heavy cryptographic usage ({crypto_count } indicators)")


        native_count =len (self .analysis_results ['native_analysis'])
        if native_count >0 :
            threat_score +=min (20 ,native_count *5 )
            threats .append (f"Contains {native_count } native libraries")


        http_count =len (self .analysis_results ['network_analysis']['http_urls'])
        https_count =len (self .analysis_results ['network_analysis']['https_urls'])
        url_count =http_count +https_count 
        if url_count >0 :
            if http_count :
                threat_score +=min (40 ,http_count *5 )
                threats .append (f"Contains {http_count } HTTP URLs (unencrypted)")
            if https_count :
                threat_score +=min (20 ,https_count *2 )
                threats .append (f"Contains {https_count } HTTPS URLs")


        domain_count =len (self .analysis_results ['network_analysis']['domains'])
        ip_count =len (self .analysis_results ['network_analysis']['ips'])
        if ip_count :
            threat_score +=min (15 ,ip_count *3 )
            threats .append (f"Contains {ip_count } raw IP addresses")
        if domain_count >50 :
            threat_score +=5 
            threats .append ("Large number of domains embedded")


        owner =self .analysis_results .get ('certificate_analysis',{}).get ('owner','')
        if 'Android Debug'in owner :
            threat_score +=10 
            threats .append ("Signed with debug certificate")

        self .analysis_results ['threat_indicators']=threats 
        self .analysis_results ['threat_score']=min (threat_score ,100 )


        if self .analysis_results ['threat_score']>70 :
            self .analysis_results ['recommendations'].append ("HIGH RISK - Detailed dynamic analysis recommended")
            self .analysis_results ['recommendations'].append ("Monitor network traffic during execution")
            self .analysis_results ['recommendations'].append ("Run in isolated environment only")
        elif self .analysis_results ['threat_score']>40 :
            self .analysis_results ['recommendations'].append ("MEDIUM RISK - Additional analysis recommended")
            self .analysis_results ['recommendations'].append ("Monitor sensitive API calls")
        else :
            self .analysis_results ['recommendations'].append ("LOW RISK - Standard monitoring sufficient")

    def save_results (self ,output_dir ):
        os .makedirs (output_dir ,exist_ok =True )

        timestamp =datetime .now ().strftime ("%Y%m%d_%H%M%S")


        json_file =os .path .join (output_dir ,f'static_analysis_{timestamp }.json')
        with open (json_file ,'w')as f :
            json .dump (self .analysis_results ,f ,indent =2 )


        ioc_file =os .path .join (output_dir ,f'static_iocs_{timestamp }.txt')
        self ._generate_ioc_file (ioc_file )


        report_file =os .path .join (output_dir ,f'static_report_{timestamp }.txt')
        self ._generate_readable_report (report_file )

        print (f"[+] Results saved to {output_dir }")
        print (f"    JSON Report: {json_file }")
        print (f"    IOC File: {ioc_file }")
        print (f"    Readable Report: {report_file }")

    def _generate_ioc_file (self ,filename ):
        with open (filename ,'w')as f :
            f .write (f"# Static Analysis IOCs - {datetime .now ().isoformat ()}\n\n")

            f .write ("## File Hashes\n")
            for algo ,hash_val in self .analysis_results ['metadata']['file_hashes'].items ():
                f .write (f"{algo .upper ()}: {hash_val }\n")
            f .write ("\n")

            if 'package_name'in self .analysis_results ['manifest_analysis']:
                f .write ("## Package Information\n")
                f .write (f"Package: {self .analysis_results ['manifest_analysis']['package_name']}\n")
                if 'version_name'in self .analysis_results ['manifest_analysis']:
                    f .write (f"Version: {self .analysis_results ['manifest_analysis']['version_name']}\n")
                f .write ("\n")

            urls =self .analysis_results ['code_analysis']['urls']
            if urls :
                f .write ("## Network Indicators (All URLs)\n")
                for url_info in urls :
                    f .write (f"{url_info ['url']}\n")
                f .write ("\n")
            http_urls =self .analysis_results ['network_analysis']['http_urls']
            https_urls =self .analysis_results ['network_analysis']['https_urls']
            if http_urls :
                f .write ("## HTTP URLs\n")
                for u in http_urls :
                    f .write (f"{u }\n")
                f .write ("\n")
            if https_urls :
                f .write ("## HTTPS URLs\n")
                for u in https_urls :
                    f .write (f"{u }\n")
                f .write ("\n")
            domains =self .analysis_results ['network_analysis']['domains']
            ips =self .analysis_results ['network_analysis']['ips']
            if domains :
                f .write ("## Domains\n")
                for d in domains :
                    f .write (f"{d }\n")
                f .write ("\n")
            if ips :
                f .write ("## IP Addresses\n")
                for ip in ips :
                    f .write (f"{ip }\n")
                f .write ("\n")

            if 'sha256'in self .analysis_results ['certificate_analysis']:
                f .write ("## Certificate Indicators\n")
                f .write (f"Cert SHA256: {self .analysis_results ['certificate_analysis']['sha256']}\n")
                f .write ("\n")

    def _generate_readable_report (self ,filename ):
        with open (filename ,'w')as f :
            f .write ("="*60 +"\n")
            f .write ("ADVANCED APK STATIC ANALYSIS REPORT\n")
            f .write ("="*60 +"\n\n")

            f .write ("THREAT ASSESSMENT\n")
            f .write ("-"*20 +"\n")
            f .write (f"Threat Score: {self .analysis_results ['threat_score']}/100\n")
            f .write (f"Risk Level: {self ._get_risk_level (self .analysis_results ['threat_score'])}\n\n")

            if self .analysis_results ['threat_indicators']:
                f .write ("Identified Threats:\n")
                for threat in self .analysis_results ['threat_indicators']:
                    f .write (f"  • {threat }\n")
                f .write ("\n")

            if self .analysis_results ['recommendations']:
                f .write ("Recommendations:\n")
                for rec in self .analysis_results ['recommendations']:
                    f .write (f"  • {rec }\n")
                f .write ("\n")

            na =self .analysis_results ['network_analysis']
            f .write ("Network Summary\n")
            f .write ("-"*20 +"\n")
            f .write (f"HTTP URLs: {len (na ['http_urls'])}\n")
            f .write (f"HTTPS URLs: {len (na ['https_urls'])}\n")
            f .write (f"Domains: {len (na ['domains'])}\n")
            f .write (f"IP Addresses: {len (na ['ips'])}\n\n")


    def _get_risk_level (self ,score ):
        if score >=70 :
            return "HIGH"
        elif score >=40 :
            return "MEDIUM"
        elif score >=20 :
            return "LOW"
        else :
            return "MINIMAL"

    def run_full_analysis (self ,output_dir ='analysis_output'):
        print (f"[*] Starting advanced APK analysis: {self .apk_path }")

        self .calculate_file_hashes ()
        self .extract_and_analyze_manifest ()
        self .analyze_certificate ()
        self .extract_strings ()
        self .analyze_native_libraries ()
        self .generate_threat_assessment ()
        self .save_results (output_dir )

        print (f"\n[+] Analysis complete!")
        print (f"[+] Threat Score: {self .analysis_results ['threat_score']}/100")
        print (f"[+] Risk Level: {self ._get_risk_level (self .analysis_results ['threat_score'])}")

    def _manual_string_extraction (self ,data ,source_type ):
        strings =re .findall (rb'[\x20-\x7E]{4,}',data )
        for s in strings :
            try :
                decoded =s .decode ('utf-8')
                self ._track_string (decoded ,source_type )
                self ._analyze_strings ([decoded ],source_type )
            except UnicodeDecodeError :
                pass 

    def analyze_native_libraries (self ):
        print ("[*] Analyzing native libraries...")
        try :
            with zipfile .ZipFile (self .apk_path ,'r')as zip_file :
                so_files =[f for f in zip_file .namelist ()if f .endswith ('.so')]
                self .analysis_results ['native_analysis']['count']=len (so_files )
                self .analysis_results ['native_analysis']['libraries']=so_files 
                print (f"    Found {len (so_files )} native libraries")
        except Exception as e :
            print (f"[!] Native library analysis failed: {e }")

def main ():
    parser =argparse .ArgumentParser (description ='Advanced APK Static Analysis Tool')
    parser .add_argument ('apk_path',help ='Path to APK file')
    parser .add_argument ('-o','--output',default ='analysis_output',help ='Output directory for results')

    parser .add_argument ('--threads',type =int ,default =4 ,help ='Max concurrent workers for extraction')
    parser .add_argument ('--timeout',type =int ,default =30 ,help ='Subprocess timeout (seconds)')
    parser .add_argument ('--max-strings',type =int ,default =50000 ,help ='Max strings to store/analyze')
    parser .add_argument ('-v','--verbose',action ='store_true',help ='Enable verbose logging')
    args =parser .parse_args ()

    if not os .path .exists (args .apk_path ):
        print (f"[!] APK file not found: {args .apk_path }")
        sys .exit (1 )


    logging .basicConfig (
    level =(logging .DEBUG if args .verbose else logging .INFO ),
    format ='[%(levelname)s] %(message)s'
    )

    analyzer =AdvancedAPKAnalyzer (
    args .apk_path ,
    threads =args .threads ,
    timeout =args .timeout ,
    max_strings =args .max_strings 
    )
    analyzer .run_full_analysis (args .output )

if __name__ =='__main__':
    main ()
