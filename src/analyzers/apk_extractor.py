#!/usr/bin/env python3

from __future__ import annotations 

import argparse 
import json 
import logging 
import multiprocessing 
import os 
import re 
import shutil 
import subprocess 
import sys 
import tempfile 
import time 
import zipfile 
from concurrent .futures import ProcessPoolExecutor ,as_completed 
from dataclasses import dataclass ,asdict ,field 
from hashlib import sha256 
from pathlib import Path 
from typing import Dict ,List ,Optional ,Tuple ,Set ,Any ,Union 

try :
    from tqdm import tqdm 
    HAS_TQDM =True 
except ImportError :
    HAS_TQDM =False 


logging .basicConfig (
level =logging .INFO ,
format ='%(asctime)s - %(levelname)s - %(message)s',
datefmt ='%Y-%m-%d %H:%M:%S'
)
logger =logging .getLogger ('apk-extractor')


def _safe_join (base :Path ,*paths :str )->Path :
    target =(base /Path (*paths )).resolve ()
    base_resolved =base .resolve ()
    if not str (target ).startswith (str (base_resolved )):
        raise ValueError ("Attempted path traversal in archive")
    return target 


def _entropy (data :bytes )->float :
    if not data :
        return 0.0 
    freq =[0 ]*256 
    for b in data :
        freq [b ]+=1 
    total =len (data )
    import math 
    ent =0.0 
    for f in freq :
        if f :
            p =f /total 
            ent -=p *math .log2 (p )
    return ent 


def _guess_type (name :str ,data :bytes )->str :
    n =name .lower ()
    if n .endswith ('.dex')or data .startswith (b'dex\n'):
        return 'dex'
    if data [:2 ]==b'PK':
        if n .endswith ('.apk'):
            return 'apk'
        if n .endswith ('.jar'):
            return 'jar'
        return 'zip'
    if data .startswith (b"\x7fELF"):
        return 'elf'
    if n .endswith ('.arsc'):
        return 'arsc'
    if n .endswith ('.xml'):
        return 'xml'
    if data .startswith (b'SQLite format 3\x00'):
        return 'sqlite'
    if n .endswith ('.so'):
        return 'native_lib'
    if n .endswith ('.png')or n .endswith ('.jpg')or n .endswith ('.jpeg')or n .endswith ('.gif'):
        return 'image'
    if n .endswith ('.html')or n .endswith ('.htm'):
        return 'html'
    if n .endswith ('.js'):
        return 'javascript'
    if n .endswith ('.css'):
        return 'css'
    if n .endswith ('.json'):
        return 'json'
    if n .endswith ('.txt'):
        return 'text'
    return 'binary'


@dataclass 
class ExtractedFile :
    path :str 
    size :int 
    sha256 :str 
    entropy :float 
    ftype :str 
    nested_extracted :bool =False 
    interesting :bool =False 
    analysis :Dict [str ,Any ]=field (default_factory =dict )


class ApkExtractor :
    def __init__ (self ,apk_path :str ,dest_root :str ,max_depth :int =3 ,
    parallel :bool =True ,max_workers :Optional [int ]=None ):
        self .apk_path =Path (apk_path )
        self .dest_root =Path (dest_root )
        self .max_depth =max_depth 
        self .parallel =parallel 
        self .max_workers =max_workers or min (32 ,os .cpu_count ()*2 )
        self .index :List [ExtractedFile ]=[]
        self .meta :Dict ={
        'apk':self .apk_path .name ,
        'apk_size':os .path .getsize (self .apk_path )if self .apk_path .exists ()else 0 ,
        'extraction_time':0 ,
        'decoded':{},
        'cert':{},
        'permissions':[],
        'components':{
        'activities':[],
        'services':[],
        'receivers':[],
        'providers':[]
        },
        'security':{
        'debuggable':False ,
        'backup_allowed':False ,
        'min_sdk':None ,
        'target_sdk':None 
        },
        'errors':[]
        }
        self .interesting_patterns =[
        re .compile (r'password|secret|token|key|credential',re .I ),
        re .compile (r'firebase|api[_-]?key|auth',re .I ),
        re .compile (r'\.so$|\.elf$'),
        re .compile (r'\.sqlite$|\.db$')
        ]

    def extract_all (self )->Tuple [List [ExtractedFile ],Dict ]:
        start_time =time .time ()
        out_dir =self .dest_root 
        out_dir .mkdir (parents =True ,exist_ok =True )

        logger .info (f"Starting extraction of {self .apk_path .name } to {out_dir }")

        try :
            with zipfile .ZipFile (self .apk_path ,'r')as zf :
                total_files =len ([f for f in zf .infolist ()if not f .is_dir ()])
                logger .info (f"Found {total_files } files in APK")


                extracted_count =0 
                pbar =tqdm (total =total_files ,desc ="Extracting files",unit ="file")if HAS_TQDM else None 
                for info in zf .infolist ():

                    if info .is_dir ():
                        continue 

                    extracted_count +=1 
                    if extracted_count %100 ==0 :
                        logger .info (f"Extracted {extracted_count }/{total_files } files")

                    try :
                        data =zf .read (info .filename )
                    except Exception as e :
                        self .meta ['errors'].append (f"read {info .filename }: {e }")
                        if pbar :
                            pbar .update (1 )
                        continue 

                    rel_path =Path (info .filename )
                    dest =_safe_join (out_dir ,rel_path .as_posix ())
                    dest .parent .mkdir (parents =True ,exist_ok =True )
                    try :
                        dest .write_bytes (data )
                    except Exception as e :
                        self .meta ['errors'].append (f"write {rel_path }: {e }")
                        if pbar :
                            pbar .update (1 )
                        continue 


                    is_interesting =False 
                    for pattern in self .interesting_patterns :
                        if pattern .search (rel_path .as_posix ())or (
                        len (data )<1024 *1024 and 
                        _guess_type (rel_path .name ,data )in ['text','xml','json']and 
                        pattern .search (data .decode ('utf-8','ignore'))):
                            is_interesting =True 
                            break 

                    ftype =_guess_type (rel_path .name ,data )
                    ef =ExtractedFile (
                    path =str (rel_path ),
                    size =len (data ),
                    sha256 =sha256 (data ).hexdigest (),
                    entropy =_entropy (data ),
                    ftype =ftype ,
                    interesting =is_interesting 
                    )


                    if ftype =='native_lib':
                        ef .analysis ['architecture']=self ._analyze_native_lib (dest )
                    elif ftype in ['binary','elf','dex']:
                        ef .analysis ['strings']=self ._extract_strings (data )

                    self .index .append (ef )

                    if pbar :
                        pbar .update (1 )

                if pbar :
                    pbar .close ()


                nested_archives =[(info .filename ,zf .read (info .filename ))
                for info in zf .infolist ()
                if not info .is_dir ()and 
                (_guess_type (info .filename ,zf .read (info .filename )[:10 ])in {'zip','jar','apk'}or 
                Path (info .filename ).suffix .lower ()in {'.zip','.jar','.apk'})]

                logger .info (f"Found {len (nested_archives )} nested archives to extract")

                if self .parallel and nested_archives :
                    self ._extract_nested_parallel (nested_archives ,out_dir )
                else :
                    for filename ,data in nested_archives :
                        rel_path =Path (filename )
                        nested_dir =out_dir /'_nested'/rel_path .with_suffix ('').name 
                        try :
                            self ._unpack_zip_bytes (data ,nested_dir ,depth =1 )

                            for ef in self .index :
                                if ef .path ==str (rel_path ):
                                    ef .nested_extracted =True 
                                    break 
                        except Exception as e :
                            self .meta ['errors'].append (f"nested {rel_path }: {e }")


            logger .info ("Extracting APK metadata and certificate information")
            self ._decode_with_aapt (out_dir )
            self ._extract_cert_info ()
            self ._extract_permissions_and_components ()
            self ._analyze_security_settings ()

        except zipfile .BadZipFile as e :
            logger .error (f"Bad zip file: {e }")
            self .meta ['errors'].append (f"bad zip: {e }")
        except Exception as e :
            logger .error (f"Extraction error: {e }")
            self .meta ['errors'].append (f"extraction: {e }")


        file_types ={}
        for ef in self .index :
            file_types [ef .ftype ]=file_types .get (ef .ftype ,0 )+1 

        self .meta ['file_stats']={
        'total_files':len (self .index ),
        'nested_archives':sum (1 for x in self .index if x .nested_extracted ),
        'interesting_files':sum (1 for x in self .index if x .interesting ),
        'file_types':file_types 
        }


        self .meta ['extraction_time']=round (time .time ()-start_time ,2 )


        logger .info ("Writing extraction index and metadata")
        (out_dir /'extraction_index.json').write_text (
        json .dumps ([asdict (x )for x in self .index ],indent =2 )
        )
        (out_dir /'extraction_meta.json').write_text (
        json .dumps (self .meta ,indent =2 )
        )

        logger .info (f"Extraction completed in {self .meta ['extraction_time']} seconds")
        return self .index ,self .meta 

    def _extract_nested_parallel (self ,nested_archives :List [Tuple [str ,bytes ]],out_dir :Path ):
        logger .info (f"Extracting {len (nested_archives )} nested archives in parallel with {self .max_workers } workers")

        with ProcessPoolExecutor (max_workers =self .max_workers )as executor :
            futures ={}

            for filename ,data in nested_archives :
                rel_path =Path (filename )
                nested_dir =out_dir /'_nested'/rel_path .with_suffix ('').name 
                nested_dir .mkdir (parents =True ,exist_ok =True )


                temp_file =tempfile .NamedTemporaryFile (delete =False )
                temp_file .write (data )
                temp_file .close ()

                future =executor .submit (
                self ._unpack_zip_file ,
                temp_file .name ,
                str (nested_dir ),
                1 ,
                self .max_depth 
                )
                futures [future ]=(temp_file .name ,str (rel_path ))

            completed =0 
            for future in as_completed (futures ):
                temp_file ,rel_path =futures [future ]
                try :
                    future .result ()

                    for ef in self .index :
                        if ef .path ==rel_path :
                            ef .nested_extracted =True 
                            break 
                except Exception as e :
                    self .meta ['errors'].append (f"nested {rel_path }: {e }")
                finally :

                    try :
                        os .unlink (temp_file )
                    except :
                        pass 

                completed +=1 
                if completed %10 ==0 or completed ==len (futures ):
                    logger .info (f"Extracted {completed }/{len (futures )} nested archives")

    @staticmethod 
    def _unpack_zip_file (zip_file :str ,dest_dir :str ,depth :int ,max_depth :int )->None :
        if depth >max_depth :
            return 

        dest =Path (dest_dir )
        dest .mkdir (parents =True ,exist_ok =True )

        try :
            with zipfile .ZipFile (zip_file ,'r')as nested :
                for ninfo in nested .infolist ():
                    if ninfo .is_dir ():
                        continue 
                    ndata =nested .read (ninfo .filename )
                    nrel =Path (ninfo .filename )

                    npath =Path (dest_dir )/nrel 
                    if not str (npath .resolve ()).startswith (str (Path (dest_dir ).resolve ())):
                        continue 

                    npath .parent .mkdir (parents =True ,exist_ok =True )
                    npath .write_bytes (ndata )


                    if nrel .suffix .lower ()in {'.zip','.jar','.apk'}or ndata [:2 ]==b'PK':
                        if depth +1 <=max_depth :
                            subdir =dest /'_nested'/nrel .with_suffix ('').name 


                            temp_file =tempfile .NamedTemporaryFile (delete =False )
                            temp_file .write (ndata )
                            temp_file .close ()

                            try :
                                ApkExtractor ._unpack_zip_file (temp_file .name ,str (subdir ),depth +1 ,max_depth )
                            finally :
                                try :
                                    os .unlink (temp_file .name )
                                except :
                                    pass 
        except Exception as e :
            raise Exception (f"Failed to unpack {zip_file }: {e }")

    def _unpack_zip_bytes (self ,data :bytes ,dest :Path ,depth :int ):

        if depth >self .max_depth :
            return 
        dest .mkdir (parents =True ,exist_ok =True )
        try :
            from io import BytesIO 
            with zipfile .ZipFile (BytesIO (data ),'r')as nested :
                for ninfo in nested .infolist ():
                    if ninfo .is_dir ():
                        continue 
                    ndata =nested .read (ninfo .filename )
                    nrel =Path (ninfo .filename )
                    npath =_safe_join (dest ,nrel .as_posix ())
                    npath .parent .mkdir (parents =True ,exist_ok =True )
                    npath .write_bytes (ndata )

                    if nrel .suffix .lower ()in {'.zip','.jar','.apk'}or ndata [:2 ]==b'PK':
                        subdir =dest /'_nested'/nrel .with_suffix ('').name 
                        self ._unpack_zip_bytes (ndata ,subdir ,depth +1 )
        except Exception as e :
            raise e 

    def _decode_with_aapt (self ,out_dir :Path ):


        try :
            logger .info ("Decoding AndroidManifest.xml")
            r =subprocess .run (['aapt','dump','xmltree',str (self .apk_path ),'AndroidManifest.xml'],
            capture_output =True ,text =True ,timeout =30 )
            if r .returncode ==0 :
                (out_dir /'AndroidManifest.decoded.xml').write_text (r .stdout )
                self .meta ['decoded']['manifest']=True 
            else :
                self .meta ['decoded']['manifest']=False 
                logger .warning (f"Failed to decode AndroidManifest.xml: {r .stderr }")
        except Exception as e :
            self .meta ['decoded']['manifest']=False 
            self .meta ['errors'].append (f"aapt xmltree: {e }")
            logger .error (f"Error decoding manifest: {e }")


        try :
            logger .info ("Extracting app badging information")
            r =subprocess .run (['aapt','dump','badging',str (self .apk_path )],
            capture_output =True ,text =True ,timeout =30 )
            if r .returncode ==0 :
                (out_dir /'badging.txt').write_text (r .stdout )
                self .meta ['decoded']['badging']=True 


                pkg_match =re .search (r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'",r .stdout )
                if pkg_match :
                    self .meta ['package_name']=pkg_match .group (1 )
                    self .meta ['version_code']=pkg_match .group (2 )
                    self .meta ['version_name']=pkg_match .group (3 )

                sdk_match =re .search (r"sdkVersion:'(\d+)'",r .stdout )
                if sdk_match :
                    self .meta ['security']['min_sdk']=int (sdk_match .group (1 ))

                target_sdk_match =re .search (r"targetSdkVersion:'(\d+)'",r .stdout )
                if target_sdk_match :
                    self .meta ['security']['target_sdk']=int (target_sdk_match .group (1 ))
            else :
                self .meta ['decoded']['badging']=False 
                logger .warning (f"Failed to extract badging: {r .stderr }")
        except Exception as e :
            self .meta ['decoded']['badging']=False 
            self .meta ['errors'].append (f"aapt badging: {e }")
            logger .error (f"Error extracting badging: {e }")


        try :
            logger .info ("Extracting resources")
            r =subprocess .run (['aapt','dump','resources',str (self .apk_path )],
            capture_output =True ,text =True ,timeout =60 )
            if r .returncode ==0 :
                (out_dir /'resources.txt').write_text (r .stdout )
                self .meta ['decoded']['resources']=True 
            else :
                self .meta ['decoded']['resources']=False 
                logger .warning (f"Failed to extract resources: {r .stderr }")
        except Exception as e :
            self .meta ['decoded']['resources']=False 
            self .meta ['errors'].append (f"aapt resources: {e }")
            logger .error (f"Error extracting resources: {e }")

    def _extract_cert_info (self ):
        try :
            logger .info ("Extracting certificate information")
            r =subprocess .run (['keytool','-printcert','-jarfile',str (self .apk_path )],
            capture_output =True ,text =True ,timeout =30 )
            if r .returncode ==0 :
                self .meta ['cert']['raw']=r .stdout 


                owner_match =re .search (r"Owner: (.*?)(?:\n|$)",r .stdout )
                if owner_match :
                    self .meta ['cert']['owner']=owner_match .group (1 ).strip ()

                issuer_match =re .search (r"Issuer: (.*?)(?:\n|$)",r .stdout )
                if issuer_match :
                    self .meta ['cert']['issuer']=issuer_match .group (1 ).strip ()

                serial_match =re .search (r"Serial number: (.*?)(?:\n|$)",r .stdout )
                if serial_match :
                    self .meta ['cert']['serial']=serial_match .group (1 ).strip ()

                valid_from_match =re .search (r"Valid from: (.*?) until: (.*?)(?:\n|$)",r .stdout )
                if valid_from_match :
                    self .meta ['cert']['valid_from']=valid_from_match .group (1 ).strip ()
                    self .meta ['cert']['valid_until']=valid_from_match .group (2 ).strip ()


                if self .meta .get ('cert',{}).get ('owner')==self .meta .get ('cert',{}).get ('issuer'):
                    self .meta ['cert']['self_signed']=True 
                else :
                    self .meta ['cert']['self_signed']=False 
            else :
                self .meta ['cert']['error']=r .stderr .strip ()
                logger .warning (f"Failed to extract certificate: {r .stderr }")
        except Exception as e :
            self .meta ['cert']['error']=str (e )
            logger .error (f"Error extracting certificate: {e }")

    def _extract_permissions_and_components (self ):
        try :
            logger .info ("Extracting permissions and app components")
            manifest_path =self .dest_root /'AndroidManifest.decoded.xml'
            if not manifest_path .exists ():
                logger .warning ("Decoded manifest not found, skipping permission extraction")
                return 

            manifest_content =manifest_path .read_text ()


            perm_matches =re .findall (r'uses-permission.*?name="([^"]+)"',manifest_content )
            if perm_matches :
                self .meta ['permissions']=list (set (perm_matches ))


            activities =re .findall (r'activity.*?name="([^"]+)"',manifest_content )
            services =re .findall (r'service.*?name="([^"]+)"',manifest_content )
            receivers =re .findall (r'receiver.*?name="([^"]+)"',manifest_content )
            providers =re .findall (r'provider.*?name="([^"]+)"',manifest_content )

            self .meta ['components']['activities']=activities 
            self .meta ['components']['services']=services 
            self .meta ['components']['receivers']=receivers 
            self .meta ['components']['providers']=providers 


            exported_activities =re .findall (r'activity.*?exported="true".*?name="([^"]+)"',manifest_content )
            exported_services =re .findall (r'service.*?exported="true".*?name="([^"]+)"',manifest_content )
            exported_receivers =re .findall (r'receiver.*?exported="true".*?name="([^"]+)"',manifest_content )
            exported_providers =re .findall (r'provider.*?exported="true".*?name="([^"]+)"',manifest_content )

            self .meta ['security']['exported_components']={
            'activities':exported_activities ,
            'services':exported_services ,
            'receivers':exported_receivers ,
            'providers':exported_providers ,
            'count':len (exported_activities )+len (exported_services )+
            len (exported_receivers )+len (exported_providers )
            }

        except Exception as e :
            logger .error (f"Error extracting permissions and components: {e }")
            self .meta ['errors'].append (f"permissions extraction: {e }")

    def _analyze_security_settings (self ):
        try :
            logger .info ("Analyzing security settings")
            manifest_path =self .dest_root /'AndroidManifest.decoded.xml'
            if not manifest_path .exists ():
                logger .warning ("Decoded manifest not found, skipping security analysis")
                return 

            manifest_content =manifest_path .read_text ()


            debuggable_match =re .search (r'android:debuggable="true"',manifest_content )
            self .meta ['security']['debuggable']=bool (debuggable_match )


            backup_match =re .search (r'android:allowBackup="true"',manifest_content )
            self .meta ['security']['backup_allowed']=bool (backup_match )


            deeplink_filters =re .findall (r'<data android:scheme="(.*?)"',manifest_content )
            self .meta ['security']['deeplinks']=deeplink_filters if deeplink_filters else []


            network_security_config =re .search (r'networkSecurityConfig="([^"]+)"',manifest_content )
            self .meta ['security']['network_security_config']=bool (network_security_config )


            cleartext_traffic =re .search (r'usesCleartextTraffic="true"',manifest_content )
            self .meta ['security']['uses_cleartext_traffic']=bool (cleartext_traffic )

        except Exception as e :
            logger .error (f"Error analyzing security settings: {e }")
            self .meta ['errors'].append (f"security analysis: {e }")

    def _analyze_native_lib (self ,lib_path :Path )->Dict [str ,Any ]:
        result ={}
        try :

            r =subprocess .run (['file',str (lib_path )],
            capture_output =True ,text =True ,timeout =10 )
            if r .returncode ==0 :
                stdout =r .stdout .lower ()
                if 'arm'in stdout :
                    if '64-bit'in stdout :
                        result ['arch']='arm64-v8a'
                    else :
                        result ['arch']='armeabi-v7a'
                elif 'x86-64'in stdout :
                    result ['arch']='x86_64'
                elif 'intel 80386'in stdout :
                    result ['arch']='x86'
                elif 'mips'in stdout :
                    result ['arch']='mips'if '64'not in stdout else 'mips64'
                elif 'risc-v'in stdout :
                    result ['arch']='riscv'
                else :
                    result ['arch']='unknown'


                result ['is_pie']='shared object'in stdout 


                result ['is_stripped']='stripped'in stdout 


                result ['has_debug']='debug'in stdout or 'not stripped'in stdout 
        except subprocess .TimeoutExpired :
            result ['error']='timeout'
        except Exception as e :
            result ['error']=str (e )

        return result 

    def _extract_strings (self ,data :bytes )->List [str ]:
        strings =[]
        try :

            current =b''
            for b in data :
                if 32 <=b <=126 :
                    current +=bytes ([b ])
                else :
                    if len (current )>=4 :
                        strings .append (current .decode ('ascii','ignore'))
                    current =b''
            if len (current )>=4 :
                strings .append (current .decode ('ascii','ignore'))
        except Exception as e :
            logger .warning (f"Error extracting strings: {e }")
        return strings [:100 ]


def run_extractor (apk_path :str ,dest_root :str ,**kwargs )->Dict :
    extractor =ApkExtractor (apk_path ,dest_root ,**kwargs )
    index ,meta =extractor .extract_all ()
    return {
    'files_extracted':len (index ),
    'nested_archives_extracted':sum (1 for x in index if x .nested_extracted ),
    'interesting_files':sum (1 for x in index if x .interesting ),
    'extraction_time':meta ['extraction_time'],
    'meta':meta ,
    }


def parse_args ():
    parser =argparse .ArgumentParser (description ='Aggressive APK Extractor v2.0')
    parser .add_argument ('apk_path',help ='Path to APK file')
    parser .add_argument ('dest_dir',help ='Destination directory for extraction')
    parser .add_argument ('--max-depth',type =int ,default =3 ,
    help ='Maximum recursion depth for nested archives (default: 3)')
    parser .add_argument ('--no-parallel',action ='store_true',
    help ='Disable parallel extraction of nested archives')
    parser .add_argument ('--workers',type =int ,default =None ,
    help ='Number of worker processes for parallel extraction')
    parser .add_argument ('--verbose','-v',action ='store_true',
    help ='Enable verbose logging')
    return parser .parse_args ()


if __name__ =='__main__':
    args =parse_args ()

    if args .verbose :
        logger .setLevel (logging .DEBUG )

    logger .info (f"APK Extractor v2.0 starting on {args .apk_path }")

    result =run_extractor (
    args .apk_path ,
    args .dest_dir ,
    max_depth =args .max_depth ,
    parallel =not args .no_parallel ,
    max_workers =args .workers 
    )

    print (json .dumps (result ,indent =2 ))

    logger .info (f"Extraction complete. Extracted {result ['files_extracted']} files "
    f"({result ['nested_archives_extracted']} nested archives) "
    f"in {result ['extraction_time']} seconds.")

    if result ['interesting_files']>0 :
        logger .info (f"Found {result ['interesting_files']} potentially interesting files.")
        logger .info (f"Found {result ['interesting_files']} potentially interesting files.")
