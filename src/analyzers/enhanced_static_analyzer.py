#!/usr/bin/env python3

import sys 
from pathlib import Path 


SUITE_DIR =Path (__file__ ).resolve ().parents [1 ]
sys .path .insert (0 ,str (SUITE_DIR ))

from utils .logger import Logger 

import os 
import json 
import hashlib 
import zipfile 
import subprocess 
import re 
from datetime import datetime 
from typing import Dict ,List ,Optional ,Tuple ,Any 
import xml .etree .ElementTree as ET 
import math 
import argparse 

try :
    import lief 
    from androguard .misc import AnalyzeAPK 
    from androguard .core .analysis .analysis import ExternalMethod 
except ImportError :
    print ("Error: Androguard or LIEF not installed. Please install them using 'pip install androguard lief'")
    sys .exit (1 )

try :
    from apk_extractor import run_extractor 
except ImportError :

    import sys as _sys 
    from pathlib import Path as _Path 
    _sys .path .insert (0 ,str (_Path (__file__ ).parent ))
    from apk_extractor import run_extractor 

class EnhancedStaticAnalyzer :

    def __init__ (self ,apk_path :str ,logger :Optional [Logger ]=None ):
        self .apk_path =Path (apk_path )
        self .logger =logger if logger else Logger (log_file =Path (SUITE_DIR )/'output'/'static_analysis.log')
        if not self .apk_path .exists ():
            self .logger .error (f"APK file not found: {self .apk_path }")
            raise FileNotFoundError (f"APK file not found: {self .apk_path }")

        self .analysis_id =None 
        self .output_dir =None 


        self .a ,self .d ,self .dx =None ,None ,None 
        self .lief_apk =None 


        self .results ={
        'metadata':{
        'analyzer_version':'4.0 (APASS ARYX Beta v1)',
        'development_status':'Under Development - Beta v1',
        'timestamp':datetime .now ().isoformat (),
        'apk_path':str (self .apk_path ),
        'file_size':self .apk_path .stat ().st_size 
        },
        'file_analysis':{},
        'manifest_analysis':{},
        'certificate_analysis':{},
        'code_analysis':{},
        'native_analysis':{},
        'resource_analysis':{},
        'security_analysis':{
        'trackers':{},
        'threat_indicators':[],
        },
        'threat_score':0 ,
        'artifacts':{
        'extracted_path':'',
        'files_indexed':0 ,
        'nested_archives':0 
        }
        }

        self .analyze_file_properties ()
        self .load_analysis_tools ()

    def load_analysis_tools (self ):

        try :
            self .a ,self .d ,self .dx =AnalyzeAPK (str (self .apk_path ))
            self .logger .info ("Successfully loaded APK with Androguard.")
        except Exception as e :
            raise RuntimeError (f"CRITICAL: Failed to load APK with Androguard: {e }")


        self .lief_apk =None 
        try :

            self .lief_apk =lief .parse (str (self .apk_path ))
            if self .lief_apk :
                self .logger .info ("Successfully parsed APK with lief.parse().")
            else :

                self .logger .warning ("lief.parse() returned None; LIEF analysis will be limited.")
        except lief .bad_file as e :
            self .logger .error (f"LIEF parsing failed because the file is malformed or protected: {e }")
        except Exception as e :
            self .logger .error (f"An unexpected error occurred during LIEF parsing: {e }")

        if not self .lief_apk :
            self .logger .warning ("LIEF analysis will be unavailable for this session.")

    def analyze_file_properties (self ):
        if not self .apk_path .exists ():
            raise FileNotFoundError (f"APK file not found: {self .apk_path }")


        file_size =self .apk_path .stat ().st_size 
        self .results ['metadata']['file_size']=file_size 


        self .results ['file_analysis']=self .calculate_hashes ()


        self .results ['file_analysis']['file_type']=self .verify_file_type ()


        self .results ['file_analysis']['entropy']=self .calculate_entropy ()

    def get_risk_level (self ,score :int )->str :
        if score >=80 :
            return "CRITICAL"
        elif score >=60 :
            return "HIGH"
        elif score >=40 :
            return "MEDIUM"
        elif score >=20 :
            return "LOW"
        else :
            return "MINIMAL"

    def calculate_hashes (self )->Dict [str ,str ]:
        hashes ={}

        hash_algorithms ={
        'md5':hashlib .md5 (),
        'sha1':hashlib .sha1 (),
        'sha256':hashlib .sha256 (),
        'sha512':hashlib .sha512 ()
        }

        with open (self .apk_path ,'rb')as f :
            chunk =f .read (8192 )
            while chunk :
                for alg in hash_algorithms .values ():
                    alg .update (chunk )
                chunk =f .read (8192 )

        for name ,alg in hash_algorithms .items ():
            hashes [name ]=alg .hexdigest ()

        return hashes 

    def verify_file_type (self )->Dict [str ,Any ]:
        file_info ={
        'is_zip':False ,
        'is_apk':False ,
        'magic_bytes':'',
        'zip_structure_valid':False 
        }


        with open (self .apk_path ,'rb')as f :
            magic =f .read (4 )
            file_info ['magic_bytes']=magic .hex ()


        try :
            with zipfile .ZipFile (self .apk_path ,'r')as zf :
                file_info ['is_zip']=True 
                files =zf .namelist ()


                required_apk_files =['AndroidManifest.xml','classes.dex']
                file_info ['is_apk']=all (f in files for f in required_apk_files )
                file_info ['zip_structure_valid']=True 

        except zipfile .BadZipFile :
            file_info ['zip_structure_valid']=False 

        return file_info 

    def calculate_entropy (self )->float :
        with open (self .apk_path ,'rb')as f :
            data =f .read ()

        if not data :
            return 0.0 


        frequencies =[0 ]*256 
        for byte in data :
            frequencies [byte ]+=1 


        entropy =0.0 
        data_len =len (data )

        for freq in frequencies :
            if freq >0 :
                p =freq /data_len 
                entropy -=p *math .log2 (p )

        return entropy 

    def analyze_manifest (self )->Dict [str ,Any ]:
        if not self .a :
            return {'error':'Androguard analysis object not available'}

        manifest_analysis ={
        'package_name':self .a .get_package (),
        'app_name':self .a .get_app_name (),
        'version_name':self .a .get_version_name (),
        'version_code':self .a .get_version_code (),
        'min_sdk':self .a .get_min_sdk_version (),
        'target_sdk':self .a .get_target_sdk_version (),
        'permissions':self .a .get_permissions (),
        'dangerous_permissions':[],
        'activities':self .a .get_activities (),
        'services':self .a .get_services (),
        'receivers':self .a .get_receivers (),
        'providers':self .a .get_providers (),
        'exported_components':[],
        'intent_filters':[],
        'features':self .a .get_features (),
        'libraries':self .a .get_libraries (),
        'main_activity':self .a .get_main_activity (),
        'application_class':self .a .get_attribute_value ('application','android:name'),
        'threat_indicators':[]
        }

        try :

            manifest_analysis ['dangerous_permissions']=self .identify_dangerous_permissions (
            manifest_analysis ['permissions']
            )


            manifest_analysis ['exported_components']=self .identify_exported_components ()


            manifest_analysis ['threat_indicators']=self .identify_manifest_threats (
            manifest_analysis 
            )

        except Exception as e :
            manifest_analysis ['error']=str (e )

        return manifest_analysis 

    def identify_exported_components (self )->List [Dict [str ,str ]]:
        if not self .a :
            return []

        exported =[]
        for comp_type ,comps in {
        'activity':self .a .get_activities (),
        'service':self .a .get_services (),
        'receiver':self .a .get_receivers (),
        'provider':self .a .get_providers (),
        }.items ():
            for comp_name in comps :
                if self .a .is_exported (comp_type ,comp_name ):
                    exported .append ({'type':comp_type ,'name':comp_name })
        return exported 

    def extract_manifest_xml (self )->Optional [str ]:
        try :
            result =subprocess .run ([
            'aapt','dump','xmltree',str (self .apk_path ),'AndroidManifest.xml'
            ],capture_output =True ,text =True ,timeout =30 )

            if result .returncode ==0 :
                return result .stdout 

        except (subprocess .TimeoutExpired ,FileNotFoundError ):
            pass 

        return None 

    def parse_manifest_xml (self ,manifest_xml :str )->Dict [str ,Any ]:
        return {}

    def identify_dangerous_permissions (self ,permissions :List [str ])->List [str ]:
        dangerous_perms ={
        'SEND_SMS','READ_SMS','RECEIVE_SMS','WRITE_SMS',
        'READ_CONTACTS','WRITE_CONTACTS','GET_ACCOUNTS',
        'READ_PHONE_STATE','CALL_PHONE','READ_CALL_LOG','WRITE_CALL_LOG',
        'ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION',
        'CAMERA','RECORD_AUDIO',
        'READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE',
        'READ_CALENDAR','WRITE_CALENDAR',
        'BODY_SENSORS','ACCESS_WIFI_STATE','CHANGE_WIFI_STATE',
        'BLUETOOTH','BLUETOOTH_ADMIN',
        'NFC','TRANSMIT_IR',
        'SYSTEM_ALERT_WINDOW','WRITE_SETTINGS',
        'DEVICE_ADMIN','BIND_DEVICE_ADMIN',
        'INSTALL_PACKAGES','DELETE_PACKAGES',
        'MOUNT_UNMOUNT_FILESYSTEMS',
        'WRITE_SECURE_SETTINGS'
        }

        found_dangerous =[]
        for perm in permissions :
            perm_name =perm .split ('.')[-1 ]
            if perm_name in dangerous_perms :
                found_dangerous .append (perm )

        return found_dangerous 

    def identify_manifest_threats (self ,manifest_data :Dict )->List [Dict [str ,str ]]:
        threats =[]


        dangerous_perms =manifest_data .get ('dangerous_permissions',[])

        if any ('SMS'in perm for perm in dangerous_perms ):
            threats .append ({
            'type':'suspicious_permissions',
            'description':'SMS access permissions detected',
            'severity':'high'
            })

        if any ('CALL'in perm for perm in dangerous_perms ):
            threats .append ({
            'type':'suspicious_permissions',
            'description':'Phone call permissions detected',
            'severity':'medium'
            })


        permissions =manifest_data .get ('permissions',[])
        if any ('INSTALL_PACKAGES'in perm for perm in permissions ):
            threats .append ({
            'type':'installer_abuse',
            'description':'Can install other packages, potential for downloader/dropper behavior',
            'severity':'high',
            'confidence':0.8 
            })

        if manifest_data .get ('application_class'):
             threats .append ({
             'type':'custom_application_class',
             'description':f"Custom Application class '{manifest_data ['application_class']}' used, a common location for early malicious code execution.",
             'severity':'medium',
             'confidence':0.7 
             })

        if len (manifest_data .get ('exported_components',[]))>5 :
            threats .append ({
            'type':'excessive_exported_components',
            'description':f"High number of exported components ({len (manifest_data ['exported_components'])}) increases attack surface.",
            'severity':'medium',
            'confidence':0.6 
            })

        return threats 

    def analyze_certificate (self )->Dict [str ,Any ]:
        if not self .lief_apk or not self .lief_apk .signatures :
            return {'error':'LIEF APK object not available or no signatures found'}

        cert_analysis ={
        'certificates':[],
        'signature_version':None ,
        'is_debug':False ,
        'threat_indicators':[]
        }

        try :

            if self .lief_apk .signatures :
                signature =self .lief_apk .signatures [0 ]
                cert_analysis ['signature_version']=signature .version 
                for cert in signature .certificates :
                    cert_data ={
                    'subject':cert .subject ,
                    'issuer':cert .issuer ,
                    'serial_number':hex (cert .serial_number ),
                    'version':cert .version ,
                    'signature_algorithm':cert .signature_algorithm ,
                    'valid_from':datetime .fromtimestamp (cert .valid_from ).isoformat (),
                    'valid_to':datetime .fromtimestamp (cert .valid_to ).isoformat (),
                    'is_self_signed':cert .is_self_signed ,
                    }
                    cert_analysis ['certificates'].append (cert_data )


                    if "Android Debug"in cert .subject :
                        cert_analysis ['is_debug']=True 

                cert_analysis ['threat_indicators']=self .identify_certificate_threats (cert_analysis )
            else :
                cert_analysis ['error']='No signatures found in APK'
        except Exception as e :
            cert_analysis ['error']=str (e )

        return cert_analysis 

    def extract_certificate_info (self )->Optional [str ]:
        return None 

    def parse_certificate_info (self ,cert_info :str )->Dict [str ,Any ]:
        return {}

    def identify_certificate_threats (self ,cert_data :Dict )->List [Dict [str ,str ]]:
        threats =[]

        if cert_data .get ('is_debug'):
            threats .append ({
            'type':'debug_certificate',
            'description':'Application signed with a standard Android debug certificate.',
            'severity':'medium',
            'confidence':1.0 
            })

        for cert in cert_data .get ('certificates',[]):
            if cert .get ('is_self_signed'):
                threats .append ({
                'type':'self_signed_certificate',
                'description':f"Application uses a self-signed certificate (SN: {cert .get ('serial_number')}).",
                'severity':'low',
                'confidence':1.0 
                })


            subject =cert .get ('subject','').lower ()
            if any (keyword in subject for keyword in ['test','temp','fake','malware','example']):
                threats .append ({
                'type':'suspicious_certificate_subject',
                'description':f"Certificate subject contains suspicious keyword: '{subject }'",
                'severity':'medium',
                'confidence':0.8 
                })

        return threats 

    def analyze_code (self )->Dict [str ,Any ]:
        if not self .dx :
            return {'error':'Androguard analysis object (dx) not available'}

        code_analysis ={
        'dex_files':[d .get_name ()for d in self .d ],
        'strings':[],
        'suspicious_strings':[],
        'apis':[],
        'suspicious_apis':[],
        'native_methods':[],
        'reflection_calls':[],
        'dynamic_loading':[],
        'obfuscation_detected':False ,
        'encryption_detected':False ,
        'threat_indicators':[]
        }

        try :

            code_analysis ['strings']=self .extract_strings ()


            code_analysis ['suspicious_strings']=self .identify_suspicious_strings (
            code_analysis ['strings']
            )


            api_analysis =self .analyze_api_calls ()
            code_analysis .update (api_analysis )


            code_analysis ['obfuscation_detected']=self .detect_obfuscation ()


            code_analysis ['encryption_detected']=self .detect_encryption (code_analysis ['strings'])


            code_analysis ['threat_indicators']=self .identify_code_threats (code_analysis )

        except Exception as e :
            code_analysis ['error']=str (e )

        return code_analysis 

    def analyze_api_calls (self )->Dict [str ,Any ]:
        if not self .dx :
            return {}

        analysis ={
        'suspicious_apis':[],
        'native_methods':[],
        'reflection_calls':[],
        'dynamic_loading':[],
        }

        suspicious_api_patterns ={
        'reflection':[r'Ljava/lang/reflect/Method;->invoke'],
        'dynamic_loading':[r'Ldalvik/system/DexClassLoader;-><init>',r'Ljava/lang/System;->loadLibrary'],
        'crypto':[r'Ljavax/crypto/Cipher;->getInstance'],
        'sms':[r'Landroid/telephony/SmsManager;->sendTextMessage'],
        'command_execution':[r'Ljava/lang/Runtime;->exec'],
        'e-mail':[r'Landroid/content/Intent;->ACTION_SENDTO'],
        'networking':[r'Ljava/net/HttpURLConnection;-><init>'],
        'file_access':[r'Ljava/io/File;-><init>'],
        'system_properties':[r'Ljava/lang/System;->getProperty'],
        'device_info':[r'Landroid/telephony/TelephonyManager;->getDeviceId'],
        }

        for method in self .dx .get_methods ():
            if method .is_external ():
                api_call =f"{method .get_class_name ()}->{method .get_name ()}"

                for category ,patterns in suspicious_api_patterns .items ():
                    for pattern in patterns :
                        if re .search (pattern ,api_call ):
                            analysis ['suspicious_apis'].append ({
                            'api':api_call ,
                            'category':category 
                            })

            if method .is_native ():
                analysis ['native_methods'].append (f"{method .get_class_name ()}->{method .get_name ()}")


        analysis ['reflection_calls']=[api ['api']for api in analysis ['suspicious_apis']if api ['category']=='reflection']
        analysis ['dynamic_loading']=[api ['api']for api in analysis ['suspicious_apis']if api ['category']=='dynamic_loading']

        return analysis 

    def analyze_native_code (self )->Dict [str ,Any ]:
        if not self .lief_apk :
            return {'error':'LIEF APK object not available'}

        native_analysis ={
        'libraries':[],
        'suspicious_imports':[],
        'threat_indicators':[],
        }

        suspicious_functions ={

        '__system_property_get','popen','system','exec','android_log_print',

        'open','read','write','unlink','remove',

        'socket','connect','send','recv','gethostbyname',

        'dlopen','dlsym'
        }

        try :
            for lib in self .lief_apk .libraries :
                lib_info ={'name':lib .name ,'imports':[],'exports':[]}
                if lib .has_imported_functions :
                    for func in lib .imported_functions :
                        lib_info ['imports'].append (func .name )
                        if func .name in suspicious_functions :
                            native_analysis ['suspicious_imports'].append ({
                            'library':lib .name ,
                            'function':func .name 
                            })
                if lib .has_exported_functions :
                     for func in lib .exported_functions :
                        lib_info ['exports'].append (func .name )
                native_analysis ['libraries'].append (lib_info )
        except Exception as e :
            native_analysis ['error']=str (e )

        if native_analysis ['suspicious_imports']:
            native_analysis ['threat_indicators'].append ({
            'type':'suspicious_native_imports',
            'description':'Native libraries import suspicious functions.',
            'severity':'high',
            'confidence':0.9 
            })

        return native_analysis 

    def extract_strings (self )->List [str ]:
        if not self .dx :
            return []

        strings =list (self .dx .get_strings ())


        unique_strings =list (set (strings ))
        filtered_strings =[s for s in unique_strings if len (s )>=4 and len (s )<=1000 ]

        return filtered_strings [:2000 ]

    def extract_dex_strings (self ,dex_data :bytes )->List [str ]:
        return []

    def identify_suspicious_strings (self ,strings :List [str ])->List [Dict [str ,str ]]:
        suspicious =[]


        patterns ={
        'url':r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^/s]*)?',
        'ip_address':r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'email':r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'filepath':r'(/[\w\.-]+)+',
        'base64':r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
        }

        suspicious_keywords ={
        'shell_commands':[
        'su','chmod','/system/bin/sh','busybox','mount','pm install','/data/local/tmp'
        ],
        'crypto_keywords':[
        'AES','DES','RSA','MD5','SHA','encrypt','decrypt','cipher','keystore','certificate'
        ],
        'exploitation':['metasploit','meterpreter','cobaltstrike'],
        'malware_families':['adups','gingermaster','droidkungfu'],
        }

        for s in strings :
            for category ,pattern in patterns .items ():
                matches =re .findall (pattern ,s )
                for match in matches :

                    if category =='ip_address'and (match .startswith ('0.')or match .startswith ('127.')):
                        continue 
                    suspicious .append ({'string':match ,'category':category ,'pattern':pattern })

            for category ,keywords in suspicious_keywords .items ():
                for keyword in keywords :
                    if keyword in s .lower ():
                        suspicious .append ({'string':s ,'category':category ,'keyword':keyword })

        return suspicious [:200 ]

    def detect_obfuscation (self )->bool :
        if not self .dx :
            return False 

        try :


            class_names =[c .get_name ()for c in self .dx .get_classes ()]
            method_names =[m .get_name ()for m in self .dx .get_methods ()]

            names =class_names +method_names 
            if not names :
                return False 

            short_names =sum (1 for n in names if len (n )<3 )
            non_ascii_names =sum (1 for n in names if not n .isascii ())

            short_ratio =short_names /len (names )
            non_ascii_ratio =non_ascii_names /len (names )

            return short_ratio >0.4 or non_ascii_ratio >0.1 
        except Exception :
            return False 

    def looks_random (self ,string :str )->bool :
        return False 

    def detect_encryption (self ,strings :List [str ])->bool :

        if self .results .get ('file_analysis',{}).get ('entropy',0 )>7.5 :
            return True 


        crypto_strings =[s for s in strings if 'encrypt'in s or 'decrypt'in s or 'cipher'in s ]
        if len (crypto_strings )>2 :
            return True 


        if self .results .get ('code_analysis',{}).get ('suspicious_apis'):
            for api in self .results ['code_analysis']['suspicious_apis']:
                if api ['category']=='crypto':
                    return True 

        return False 

    def identify_code_threats (self ,code_data :Dict )->List [Dict [str ,str ]]:
        threats =[]

        if code_data .get ('obfuscation_detected'):
            threats .append ({
            'type':'obfuscation',
            'description':'Code obfuscation detected, hindering analysis.',
            'severity':'medium',
            'confidence':0.8 
            })

        if code_data .get ('encryption_detected'):
            threats .append ({
            'type':'encryption',
            'description':'Use of encryption detected, may hide malicious payloads or data.',
            'severity':'high',
            'confidence':0.7 
            })

        if code_data .get ('reflection_calls'):
            threats .append ({
            'type':'reflection',
            'description':f"Uses reflection ({len (code_data ['reflection_calls'])} calls), which can be used to hide malicious behavior.",
            'severity':'high',
            'confidence':0.9 
            })

        if code_data .get ('dynamic_loading'):
            threats .append ({
            'type':'dynamic_loading',
            'description':f"Uses dynamic code loading ({len (code_data ['dynamic_loading'])} calls), potential for loading malicious code at runtime.",
            'severity':'high',
            'confidence':0.9 
            })

        suspicious_strings =code_data .get ('suspicious_strings',[])
        if len (suspicious_strings )>10 :
            threats .append ({
            'type':'suspicious_strings',
            'description':f'Multiple suspicious strings detected ({len (suspicious_strings )}), including potential C2 endpoints or commands.',
            'severity':'medium',
            'confidence':0.7 
            })

        return threats 

    def calculate_threat_score (self )->int :
        score =0 
        weights ={
        'entropy':2 ,
        'dangerous_perm':3 ,
        'debug_cert':10 ,
        'self_signed_cert':5 ,
        'obfuscation':15 ,
        'encryption':10 ,
        'reflection':20 ,
        'dynamic_loading':25 ,
        'suspicious_strings':1 ,
        'suspicious_native':20 ,
        'installer_abuse':25 ,
        'exported_component':2 ,
        }


        if self .results .get ('file_analysis',{}).get ('entropy',0 )>7.5 :
            score +=weights ['entropy']


        manifest =self .results .get ('manifest_analysis',{})
        score +=min (len (manifest .get ('dangerous_permissions',[]))*weights ['dangerous_perm'],30 )
        score +=min (len (manifest .get ('exported_components',[]))*weights ['exported_component'],10 )
        if any (t ['type']=='installer_abuse'for t in manifest .get ('threat_indicators',[])):
            score +=weights ['installer_abuse']


        cert =self .results .get ('certificate_analysis',{})
        if cert .get ('is_debug'):
            score +=weights ['debug_cert']
        if any (c .get ('is_self_signed')for c in cert .get ('certificates',[])):
            score +=weights ['self_signed_cert']


        code =self .results .get ('code_analysis',{})
        if code .get ('obfuscation_detected'):
            score +=weights ['obfuscation']
        if code .get ('encryption_detected'):
            score +=weights ['encryption']
        if code .get ('reflection_calls'):
            score +=weights ['reflection']
        if code .get ('dynamic_loading'):
            score +=weights ['dynamic_loading']
        score +=min (len (code .get ('suspicious_strings',[]))*weights ['suspicious_strings'],15 )


        native =self .results .get ('native_analysis',{})
        if native .get ('suspicious_imports'):
            score +=weights ['suspicious_native']

        return min (score ,100 )

    def run_analysis (self ,output_dir :str ,analysis_id :str )->Dict [str ,Any ]:
        self .output_dir =Path (output_dir )
        self .analysis_id =analysis_id 

        try :
            self .logger .info (f"[*] Starting enhanced static analysis: {self .apk_path .name }")


            self .logger .info (f"[*] File hashes calculated")


            artifacts_dir =self .output_dir /'artifacts'
            artifacts_dir .mkdir (parents =True ,exist_ok =True )
            self .logger .info (f"[*] Extracting APK contents to {artifacts_dir } ...")
            try :
                extract_result =run_extractor (str (self .apk_path ),str (artifacts_dir ))
                self .results ['artifacts']['extracted_path']=str (artifacts_dir )
                self .results ['artifacts']['files_indexed']=extract_result .get ('files_extracted',0 )
                self .results ['artifacts']['nested_archives']=extract_result .get ('nested_archives_extracted',0 )
                self .logger .info (f"[+] Extraction complete: {self .results ['artifacts']['files_indexed']} files, {self .results ['artifacts']['nested_archives']} nested archives")
            except Exception as e :
                self .logger .error (f"[-] Extraction failed: {e }")


            self .logger .info (f"[*] Analyzing AndroidManifest.xml...")
            self .results ['manifest_analysis']=self .analyze_manifest ()


            self .logger .info (f"[*] Analyzing signing certificate...")
            self .results ['certificate_analysis']=self .analyze_certificate ()


            self .logger .info (f"[*] Analyzing application code...")
            self .results ['code_analysis']=self .analyze_code ()


            self .logger .info (f"[*] Analyzing native code...")
            self .results ['native_analysis']=self .analyze_native_code ()


            self .logger .info (f"[*] Calculating threat score...")
            self .results ['threat_score']=self .calculate_threat_score ()


            self .save_results ()

            self .logger .info (f"[+] Static analysis completed")
            self .logger .info (f"[+] Threat Score: {self .results ['threat_score']}/100")

            return self .results 

        except Exception as e :
            self .logger .error (f"[-] Static analysis failed: {e }",exc_info =True )
            raise 

    def save_results (self ):
        self .output_dir .mkdir (parents =True ,exist_ok =True )

        timestamp =datetime .now ().strftime ("%Y%m%d_%H%M%S")


        json_file =self .output_dir /f"static_analysis_{timestamp }.json"
        with open (json_file ,'w')as f :
            json .dump (self .results ,f ,indent =2 ,default =str )


        text_file =self .output_dir /f"static_report_{timestamp }.txt"
        with open (text_file ,'w')as f :
            f .write (self .generate_text_report ())


        ioc_file =self .output_dir /f"static_iocs_{timestamp }.txt"
        with open (ioc_file ,'w')as f :
            f .write (self .generate_iocs ())

        self .logger .info (f"[+] Results saved to {self .output_dir }")

    def generate_text_report (self )->str :
        report =[]
        report .append ("="*60 )
        report .append ("ENHANCED STATIC ANALYSIS REPORT")
        report .append ("="*60 )
        report .append ("")


        metadata =self .results ['metadata']
        report .append ("== METADATA ==")
        report .append (f"  File Name: {Path (metadata ['apk_path']).name }")
        report .append (f"  File Size: {metadata ['file_size']:,} bytes")
        report .append (f"  Analysis Time: {metadata ['timestamp']}")
        report .append ("")


        threat_score =self .results ['threat_score']
        risk_level =self .get_risk_level (threat_score )
        report .append ("== THREAT ASSESSMENT ==")
        report .append (f"  Threat Score: {threat_score }/100")
        report .append (f"  Risk Level: {risk_level }")
        report .append ("")


        report .append ("== KEY FINDINGS ==")
        all_threats =[]
        for section in ['manifest_analysis','certificate_analysis','code_analysis','native_analysis']:
            all_threats .extend (self .results .get (section ,{}).get ('threat_indicators',[]))

        if all_threats :
            for threat in sorted (all_threats ,key =lambda x :x .get ('severity','low')):
                report .append (f"  - [{threat .get ('severity','N/A').upper ()}] {threat .get ('description','No description')}")
        else :
            report .append ("  - No significant threats identified.")
        report .append ("")


        file_analysis =self .results .get ('file_analysis',{})
        report .append ("== FILE ANALYSIS ==")
        report .append (f"  MD5: {file_analysis .get ('md5','N/A')}")
        report .append (f"  SHA1: {file_analysis .get ('sha1','N/A')}")
        report .append (f"  SHA256: {file_analysis .get ('sha256','N/A')}")
        report .append (f"  Entropy: {file_analysis .get ('entropy',0 ):.2f} (High > 7.5 suggests packing/encryption)")
        report .append ("")


        manifest =self .results .get ('manifest_analysis',{})
        if manifest :
            report .append ("== MANIFEST ANALYSIS ==")
            report .append (f"  Package: {manifest .get ('package_name','N/A')}")
            report .append (f"  Version: {manifest .get ('version_name','N/A')} (Code: {manifest .get ('version_code','N/A')})")
            report .append (f"  SDK: Min={manifest .get ('min_sdk','N/A')}, Target={manifest .get ('target_sdk','N/A')}")

            dangerous_perms =manifest .get ('dangerous_permissions',[])
            if dangerous_perms :
                report .append (f"  Dangerous Permissions ({len (dangerous_perms )}):")
                for perm in dangerous_perms [:5 ]:
                    report .append (f"    - {perm .split ('.')[-1 ]}")
                if len (dangerous_perms )>5 :
                    report .append (f"    ... and {len (dangerous_perms )-5 } more.")

            exported =manifest .get ('exported_components',[])
            if exported :
                report .append (f"  Exported Components ({len (exported )}):")
                for comp in exported [:3 ]:
                    report .append (f"    - {comp ['type']}: {comp ['name']}")
                if len (exported )>3 :
                    report .append (f"    ... and {len (exported )-3 } more.")
            report .append ("")


        cert_analysis =self .results .get ('certificate_analysis',{})
        if cert_analysis .get ('certificates'):
            cert =cert_analysis ['certificates'][0 ]
            report .append ("== CERTIFICATE ANALYSIS ==")
            report .append (f"  Signature Version: {cert_analysis .get ('signature_version','N/A')}")
            report .append (f"  Debug Certificate: {cert_analysis .get ('is_debug',False )}")
            report .append (f"  Subject: {cert .get ('subject','N/A')}")
            report .append (f"  Issuer: {cert .get ('issuer','N/A')}")
            report .append (f"  Self-Signed: {cert .get ('is_self_signed',False )}")
            report .append (f"  Validity: {cert .get ('valid_from','N/A')} to {cert .get ('valid_to','N/A')}")
            report .append ("")


        code =self .results .get ('code_analysis',{})
        if code :
            report .append ("== CODE ANALYSIS ==")
            report .append (f"  Obfuscation Detected: {code .get ('obfuscation_detected',False )}")
            report .append (f"  Encryption Detected: {code .get ('encryption_detected',False )}")
            if code .get ('reflection_calls'):
                report .append (f"  Reflection Calls: {len (code .get ('reflection_calls',[]))}")
            if code .get ('dynamic_loading'):
                report .append (f"  Dynamic Loading Calls: {len (code .get ('dynamic_loading',[]))}")
            report .append ("")


        native =self .results .get ('native_analysis',{})
        if native .get ('libraries'):
            report .append ("== NATIVE ANALYSIS ==")
            report .append (f"  Libraries Found: {len (native .get ('libraries',[]))}")
            suspicious_imports =native .get ('suspicious_imports',[])
            if suspicious_imports :
                report .append (f"  Suspicious Imports ({len (suspicious_imports )}):")
                for imp in suspicious_imports [:5 ]:
                    report .append (f"    - {imp ['function']} in {imp ['library']}")
                if len (suspicious_imports )>5 :
                    report .append (f"    ... and {len (suspicious_imports )-5 } more.")
            report .append ("")


        artifacts =self .results .get ('artifacts',{})
        if artifacts .get ('extracted_path'):
            report .append ("== ARTIFACTS ==")
            report .append (f"  Extracted Path: {artifacts .get ('extracted_path')}")
            report .append (f"  Files Indexed: {artifacts .get ('files_indexed',0 )}")
            report .append (f"  Nested Archives: {artifacts .get ('nested_archives',0 )}")
            report .append ("")


        report .append ("== RECOMMENDATIONS ==")
        recommendations =self .generate_recommendations (threat_score )
        for rec in recommendations :
            report .append (f"  • {rec }")

        return "\n".join (report )

    def generate_iocs (self )->str :
        iocs =[]
        iocs .append (f"# Static Analysis IOCs - {datetime .now ().isoformat ()}")
        iocs .append ("")


        file_analysis =self .results .get ('file_analysis',{})
        iocs .append ("## File Hashes")
        for hash_type in ['md5','sha1','sha256']:
            if hash_type in file_analysis :
                iocs .append (f"{hash_type .upper ()}: {file_analysis [hash_type ]}")
        iocs .append ("")


        manifest =self .results .get ('manifest_analysis',{})
        if manifest .get ('package_name'):
            iocs .append ("## Package Information")
            iocs .append (f"Package: {manifest ['package_name']}")
            if manifest .get ('version_name'):
                iocs .append (f"Version: {manifest ['version_name']}")
            iocs .append ("")


        cert =self .results .get ('certificate_analysis',{})
        if cert .get ('subject'):
            iocs .append ("## Certificate Information")
            iocs .append (f"Subject: {cert ['subject']}")
            if cert .get ('serial_number'):
                iocs .append (f"Serial: {cert ['serial_number']}")
            iocs .append ("")

        return "\n".join (iocs )

    def generate_recommendations (self ,score :int )->List [str ]:
        if score >=80 :
            return [
            "CRITICAL RISK - Immediate investigation required",
            "Quarantine application and analyze in isolated environment",
            "Report to security team immediately"
            ]
        elif score >=60 :
            return [
            "HIGH RISK - Enhanced monitoring recommended",
            "Review dangerous permissions and behavior",
            "Consider blocking application"
            ]
        elif score >=40 :
            return [
            "MEDIUM RISK - Monitor application behavior",
            "Review granted permissions",
            "Regular security scans recommended"
            ]
        elif score >=20 :
            return [
            "LOW RISK - Standard monitoring sufficient",
            "Periodic security reviews recommended"
            ]
        else :
            return [
            "MINIMAL RISK - Standard monitoring sufficient"
            ]


def main ():
    parser =argparse .ArgumentParser (description ="Enhanced Static Analyzer v4.0")
    parser .add_argument ("apk_path",help ="Path to the APK file.")
    parser .add_argument ("-o","--output-dir",default ="analysis_output",help ="Path to save the analysis output files.")
    args =parser .parse_args ()


    logger_config_json =os .getenv ('LOGGER_CONFIG')
    if logger_config_json :
        logger_config =json .loads (logger_config_json )
        logger =Logger .from_dict (logger_config )
    else :
        logger =Logger ()

    try :
        analyzer =EnhancedStaticAnalyzer (args .apk_path ,logger =logger )

        output_dir =Path (args .output_dir )
        analysis_id =f"{Path (args .apk_path ).stem }_{datetime .now ().strftime ('%Y%m%d%H%M%S')}"

        results =analyzer .run_analysis (output_dir =str (output_dir ),analysis_id =analysis_id )

        logger .info (f"Static analysis results saved to {output_dir }")


        print ("\n"+analyzer .generate_text_report ())

        return 0 
    except Exception as e :
        logger .error (f"Static analysis failed: {e }",exc_info =True )
        return 1 


if __name__ =="__main__":
    sys .exit (main ())
