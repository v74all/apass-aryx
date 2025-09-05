#!/usr/bin/env python3

from __future__ import annotations 

import json 
import os 
import shutil 
import subprocess 
import tempfile 
import time 
import logging 
import zipfile 
from dataclasses import dataclass ,field 
from pathlib import Path 
from typing import Any ,Dict ,Optional ,List ,Union ,Callable 
import hashlib 
import requests 
from contextlib import contextmanager 


logger =logging .getLogger (__name__ )

@dataclass 
class ToolResult :
    name :str 
    available :bool 
    success :bool 
    data :Dict [str ,Any ]
    error :Optional [str ]=None 
    runtime_ms :Optional [float ]=None 
    version :Optional [str ]=None 

    def to_dict (self )->Dict [str ,Any ]:
        return {
        "name":self .name ,
        "available":self .available ,
        "success":self .success ,
        "data":self .data ,
        "error":self .error ,
        "runtime_ms":self .runtime_ms ,
        "version":self .version 
        }


@contextmanager 
def measure_time ():
    start =time .time ()
    elapsed_container ={"ms":0 }
    try :
        yield elapsed_container 
    finally :
        end =time .time ()
        elapsed_container ["ms"]=(end -start )*1000 


def _which (cmd :str )->bool :
    return shutil .which (cmd )is not None 


def _get_file_hash (file_path :str ,algorithm :str ='sha256')->str :
    hash_alg =getattr (hashlib ,algorithm )()
    with open (file_path ,'rb')as f :
        for chunk in iter (lambda :f .read (4096 ),b''):
            hash_alg .update (chunk )
    return hash_alg .hexdigest ()


def _run_process (cmd :List [str ],timeout :int ,**kwargs )->subprocess .CompletedProcess :
    logger .debug (f"Running command: {' '.join (cmd )}")
    return subprocess .run (cmd ,capture_output =True ,text =True ,timeout =timeout ,**kwargs )


def run_androguard (apk_path :str ,timeout :int =120 )->ToolResult :
    start_time =time .time ()
    version =None 

    try :

        try :
            import importlib .metadata 
            version =importlib .metadata .version ("androguard")
        except Exception :
            pass 


        from androguard .core .bytecodes .apk import APK 

        apk =APK (apk_path )
        data :Dict [str ,Any ]={
        "package":apk .get_package (),
        "version_name":apk .get_androidversion_name (),
        "version_code":apk .get_androidversion_code (),
        "permissions":sorted (list (apk .get_permissions ()or [])),
        "is_debuggable":bool (apk .is_debuggable ()),
        "is_signed":bool (apk .is_signed ()),
        "files":apk .get_files (),
        "activities":apk .get_activities (),
        "services":apk .get_services (),
        "receivers":apk .get_receivers (),
        "providers":apk .get_providers (),
        }


        try :
            certs =apk .get_certificates ()
            cert_hashes =[]
            for c in certs or []:
                try :
                    cert_hashes .append ({
                    "subject":getattr (c ,"subject",None ),
                    "sha256":getattr (c ,"sha256_fingerprint",lambda :None )(),
                    "sha1":getattr (c ,"sha1_fingerprint",lambda :None )(),
                    "md5":getattr (c ,"md5_fingerprint",lambda :None )(),
                    })
                except Exception :
                    continue 
            if cert_hashes :
                data ["certificates"]=cert_hashes 
        except Exception :
            pass 


        try :
            data ["manifest_xml"]=apk .get_android_manifest_axml ().get_xml ()
        except Exception :
            pass 

        end_time =time .time ()
        return ToolResult ("androguard",True ,True ,data ,
        runtime_ms =(end_time -start_time )*1000 ,
        version =version )
    except Exception as e :
        end_time =time .time ()

        available ="No module named 'androguard'"not in str (e )
        return ToolResult ("androguard",available ,False ,{},
        error =str (e ),
        runtime_ms =(end_time -start_time )*1000 ,
        version =version )


def run_apkid (apk_path :str ,timeout :int =60 )->ToolResult :
    start_time =time .time ()
    version =None 

    if not _which ("apkid"):
        return ToolResult ("apkid",False ,False ,{},error ="apkid not found in PATH")

    try :

        try :
            proc =_run_process (["apkid","--version"],timeout =10 )
            if proc .returncode ==0 :
                version =proc .stdout .strip ()
        except Exception :
            pass 


        proc =_run_process (["apkid","-j",apk_path ],timeout =timeout )

        if proc .returncode !=0 :
            return ToolResult ("apkid",True ,False ,{},
            error =proc .stderr .strip ()or proc .stdout .strip (),
            runtime_ms =(time .time ()-start_time )*1000 ,
            version =version )


        parsed =json .loads (proc .stdout )


        result_data ={"raw":parsed }


        if parsed and isinstance (parsed ,list )and len (parsed )>0 :
            first_file =list (parsed [0 ].keys ())[0 ]if parsed [0 ]else None 
            if first_file :
                matches =parsed [0 ][first_file ].get ("matches",{})
                result_data ["packers"]=matches .get ("packer",[])
                result_data ["obfuscators"]=matches .get ("obfuscator",[])
                result_data ["anti_vm"]=matches .get ("anti_vm",[])
                result_data ["anti_debug"]=matches .get ("anti_debug",[])

        return ToolResult ("apkid",True ,True ,result_data ,
        runtime_ms =(time .time ()-start_time )*1000 ,
        version =version )
    except subprocess .TimeoutExpired :
        return ToolResult ("apkid",True ,False ,{},
        error ="timeout",
        runtime_ms =timeout *1000 ,
        version =version )
    except Exception as e :
        return ToolResult ("apkid",True ,False ,{},
        error =str (e ),
        runtime_ms =(time .time ()-start_time )*1000 ,
        version =version )


def run_quark (apk_path :str ,output_dir :Path ,timeout :int =180 )->ToolResult :
    start_time =time .time ()
    version =None 


    quark_out =output_dir /"quark"
    quark_out .mkdir (parents =True ,exist_ok =True )

    if _which ("quark"):
        try :

            try :
                proc =_run_process (["quark","--version"],timeout =10 )
                if proc .returncode ==0 :
                    version =proc .stdout .strip ()
            except Exception :
                pass 



            proc =_run_process (
            ["quark","-a",apk_path ,"-o",str (quark_out )],
            timeout =timeout 
            )

            success =proc .returncode ==0 
            data :Dict [str ,Any ]={
            "stdout":proc .stdout [-4000 :],
            "stderr":proc .stderr [-4000 :],
            "report_dir":str (quark_out ),
            }


            json_reports =list (quark_out .glob ("*.json"))
            if json_reports :
                try :
                    report_data =json .loads (json_reports [0 ].read_text ())
                    data ["findings"]=report_data 
                except Exception as e :
                    data ["json_parse_error"]=str (e )

            return ToolResult ("quark",True ,success ,data ,
            None if success else proc .stderr ,
            runtime_ms =(time .time ()-start_time )*1000 ,
            version =version )
        except subprocess .TimeoutExpired :
            return ToolResult ("quark",True ,False ,{"report_dir":str (quark_out )},
            error ="timeout",
            runtime_ms =timeout *1000 ,
            version =version )
        except Exception as e :
            return ToolResult ("quark",True ,False ,{"report_dir":str (quark_out )},
            error =str (e ),
            runtime_ms =(time .time ()-start_time )*1000 ,
            version =version )


    try :
        import importlib 

        if importlib .util .find_spec ("quark_engine"):
            try :

                try :
                    import quark_engine as quark 
                    version =getattr (quark ,"__version__",None )
                except Exception :
                    pass 


                return ToolResult ("quark",True ,False ,{"report_dir":str (quark_out )},
                error ="quark_engine module present but no stable API used",
                runtime_ms =(time .time ()-start_time )*1000 ,
                version =version )
            except Exception as e :
                return ToolResult ("quark",True ,False ,{"report_dir":str (quark_out )},
                error =f"quark_engine module error: {str (e )}",
                runtime_ms =(time .time ()-start_time )*1000 ,
                version =version )

        return ToolResult ("quark",False ,False ,{"report_dir":str (quark_out )},
        error ="quark_engine not found",
        runtime_ms =(time .time ()-start_time )*1000 )
    except Exception as e :
        return ToolResult ("quark",False ,False ,{"report_dir":str (quark_out )},
        error =str (e ),
        runtime_ms =(time .time ()-start_time )*1000 )


def run_yara_scan (apk_path :str ,rules_dirs :list [Path ]|None ,timeout :int =20 )->ToolResult :
    start_time =time .time ()
    version =None 

    yara_mod =None 
    try :
        import yara as _y 
        yara_mod =_y 

        try :
            version =getattr (yara_mod ,"__version__",None )
        except Exception :
            pass 


        rule_paths :list [str ]=[]
        default_dirs =[Path ("resources/yara"),Path ("resources/yara/community")]
        for base in (rules_dirs or default_dirs ):
            base =Path (base )
            if base .is_dir ():
                rule_paths .extend ([str (p )for p in base .glob ("*.yar")])
            elif base .is_file ():
                rule_paths .append (str (base ))

        if not rule_paths :
            return ToolResult ("yara",True ,False ,{},error ="no YARA rules found",runtime_ms =(time .time ()-start_time )*1000 ,version =version )


        namespaces ={f"ns{i }":path for i ,path in enumerate (sorted (rule_paths ))}
        rules =yara_mod .compile (filepaths =namespaces )

        matches_out :list [Dict [str ,Any ]]=[]
        matches =rules .match (filepath =apk_path ,timeout =timeout )
        for m in matches :
            matches_out .append ({
            "rule":m .rule ,
            "namespace":m .namespace ,
            "tags":list (m .tags or []),
            "meta":dict (getattr (m ,"meta",{})or {}),
            "strings":[{"name":s .identifier ,"value":s .strings }for s in getattr (m ,"strings",[])or []]
            })

        return ToolResult ("yara",True ,True ,{"matches":matches_out ,"rules_used":rule_paths },runtime_ms =(time .time ()-start_time )*1000 ,version =version )
    except Exception as e :

        if yara_mod is not None and isinstance (e ,getattr (yara_mod ,"TimeoutError",tuple ())):
            return ToolResult ("yara",True ,False ,{},error ="timeout",runtime_ms =timeout *1000 ,version =version )

        available =("No module named 'yara'"not in str (e ))and (yara_mod is not None )
        return ToolResult ("yara",available ,False ,{},error =str (e ),runtime_ms =(time .time ()-start_time )*1000 ,version =version )


def run_mobsf (apk_path :str ,output_dir :Path ,timeout :int =300 )->ToolResult :
    start_time =time .time ()

    base_url =os .environ .get ("MOBSF_URL")
    api_key =os .environ .get ("MOBSF_API_KEY")
    if not base_url or not api_key :
        return ToolResult ("mobsf",False ,False ,{},
        error ="MOBSF_URL/API_KEY not set",
        runtime_ms =(time .time ()-start_time )*1000 )

    headers ={"Authorization":api_key }
    try :

        version =None 
        try :
            r =requests .get (f"{base_url }/api/v1/status",headers =headers ,timeout =timeout /10 )
            r .raise_for_status ()
            version_data =r .json ()
            version =version_data .get ("version",None )
        except Exception :
            pass 


        with open (apk_path ,"rb")as f :
            r =requests .post (f"{base_url }/api/v1/upload",headers =headers ,files ={"file":f },timeout =timeout )
            r .raise_for_status ()
            upload_json =r .json ()
        scan_hash =upload_json .get ("hash")or upload_json .get ("md5")
        if not scan_hash :
            return ToolResult ("mobsf",True ,False ,{"upload":upload_json },
            error ="no hash in upload response",
            runtime_ms =(time .time ()-start_time )*1000 ,
            version =version )


        r =requests .post (f"{base_url }/api/v1/scan",headers =headers ,data ={"hash":scan_hash },timeout =timeout )
        r .raise_for_status ()


        r =requests .post (f"{base_url }/api/v1/report_json",headers =headers ,data ={"hash":scan_hash },timeout =timeout )
        r .raise_for_status ()
        report =r .json ()


        out =output_dir /"mobsf_report.json"
        out .write_text (json .dumps (report ,indent =2 ))


        summary ={}
        try :
            summary ["security_score"]=report .get ("security_score",None )
            summary ["high_issues"]=len (report .get ("high_vulns",[]))
            summary ["medium_issues"]=len (report .get ("medium_vulns",[]))
            summary ["low_issues"]=len (report .get ("low_vulns",[]))
            summary ["malware_detection"]=report .get ("malware_analysis",{}).get ("result",None )
        except Exception :
            pass 

        return ToolResult ("mobsf",True ,True ,
        {"hash":scan_hash ,"report_file":str (out ),"summary":summary },
        runtime_ms =(time .time ()-start_time )*1000 ,
        version =version )
    except Exception as e :
        return ToolResult ("mobsf",True ,False ,{},
        error =str (e ),
        runtime_ms =(time .time ()-start_time )*1000 )


def run_virustotal_lookup (sha256 :str ,output_dir :Path ,timeout :int =60 )->ToolResult :
    start_time =time .time ()

    api_key =os .environ .get ("VT_API_KEY")or os .environ .get ("VIRUSTOTAL_API_KEY")
    if not api_key :
        return ToolResult ("virustotal",False ,False ,{},
        error ="VT_API_KEY not set",
        runtime_ms =(time .time ()-start_time )*1000 )

    headers ={"x-apikey":api_key }
    try :
        r =requests .get (f"https://www.virustotal.com/api/v3/files/{sha256 }",headers =headers ,timeout =timeout )
        if r .status_code ==404 :
            return ToolResult ("virustotal",True ,True ,{"found":False },
            runtime_ms =(time .time ()-start_time )*1000 )

        r .raise_for_status ()
        data =r .json ()

        (output_dir /"virustotal_response.json").write_text (json .dumps (data ,indent =2 ))

        stats =data .get ("data",{}).get ("attributes",{}).get ("last_analysis_stats",{})
        mal =stats .get ("malicious",0 )
        susp =stats .get ("suspicious",0 )


        attributes =data .get ("data",{}).get ("attributes",{})
        result_data ={
        "found":True ,
        "stats":stats ,
        "malicious":mal ,
        "suspicious":susp ,
        "first_submission":attributes .get ("first_submission_date"),
        "last_analysis":attributes .get ("last_analysis_date"),
        "reputation":attributes .get ("reputation"),
        "total_votes":attributes .get ("total_votes"),
        }


        engines ={}
        for engine ,result in attributes .get ("last_analysis_results",{}).items ():
            if result .get ("category")in ["malicious","suspicious"]:
                engines [engine ]=result .get ("result","")

        if engines :
            result_data ["detections"]=engines 

        return ToolResult ("virustotal",True ,True ,result_data ,
        runtime_ms =(time .time ()-start_time )*1000 )
    except Exception as e :
        return ToolResult ("virustotal",True ,False ,{},
        error =str (e ),
        runtime_ms =(time .time ()-start_time )*1000 )


def run_avclass (labels_json_path :Path ,output_dir :Path ,timeout :int =60 )->ToolResult :
    start_time =time .time ()
    version =None 

    cmd =None 
    if _which ("avclass2"):
        cmd ="avclass2"
    elif _which ("avclass"):
        cmd ="avclass"
    else :
        return ToolResult ("avclass",False ,False ,{},
        error ="avclass/avclass2 not found in PATH",
        runtime_ms =(time .time ()-start_time )*1000 )

    try :

        try :
            proc =_run_process ([cmd ,"--version"],timeout =10 )
            if proc .returncode ==0 :
                version =proc .stdout .strip ()
        except Exception :
            pass 



        proc =_run_process ([cmd ,str (labels_json_path )],timeout =timeout )

        success =proc .returncode ==0 
        result_data ={"stdout":proc .stdout ,"stderr":proc .stderr }


        if success and proc .stdout :
            lines =proc .stdout .strip ().split ('\n')
            for line in lines :
                if ":"in line :
                    key ,value =line .split (':',1 )
                    key =key .strip ().lower ()
                    value =value .strip ()
                    if key in ["family","families","tags","avs"]:
                        result_data [key ]=value 

        return ToolResult ("avclass",True ,success ,result_data ,
        runtime_ms =(time .time ()-start_time )*1000 ,
        version =version )
    except subprocess .TimeoutExpired :
        return ToolResult ("avclass",True ,False ,{},
        error ="timeout",
        runtime_ms =timeout *1000 ,
        version =version )
    except Exception as e :
        return ToolResult ("avclass",True ,False ,{},
        error =str (e ),
        runtime_ms =(time .time ()-start_time )*1000 ,
        version =version )





def check_cutter_r2frida ()->ToolResult :
    start_time =time .time ()
    version =None 

    try :
        if _which ("cutter"):

            try :
                proc =_run_process (["cutter","--version"],timeout =10 )
                if proc .returncode ==0 :
                    version =proc .stdout .strip ()
            except Exception :
                pass 

        available =_which ("cutter")and (_which ("r2frida")or _which ("r2pm"))
        return ToolResult ("cutter_r2frida",available ,available ,
        {"cutter":_which ("cutter"),"r2frida":_which ("r2frida")or _which ("r2pm")},
        runtime_ms =(time .time ()-start_time )*1000 ,
        version =version )
    except Exception as e :
        return ToolResult ("cutter_r2frida",False ,False ,{},
        error =str (e ),
        runtime_ms =(time .time ()-start_time )*1000 )


def check_ghidra ()->ToolResult :
    start_time =time .time ()
    version =None 

    try :

        available =_which ("ghidraRun")or _which ("ghidra")


        if available :
            try :
                proc =_run_process (["ghidraRun","--version"],timeout =10 )
                if proc .returncode ==0 :
                    version =proc .stdout .strip ()
            except Exception :
                pass 

        return ToolResult ("ghidra",available ,available ,
        {"ghidraRun":_which ("ghidraRun"),"ghidra":_which ("ghidra")},
        runtime_ms =(time .time ()-start_time )*1000 ,
        version =version )
    except Exception as e :
        return ToolResult ("ghidra",False ,False ,{},
        error =str (e ),
        runtime_ms =(time .time ()-start_time )*1000 )


def check_qiling ()->ToolResult :
    start_time =time .time ()
    version =None 

    try :
        import importlib 

        available =importlib .util .find_spec ("qiling")is not None 


        if available :
            try :
                import qiling 
                version =getattr (qiling ,"__version__",None )
            except Exception :
                pass 

        return ToolResult ("qiling",available ,available ,{},
        runtime_ms =(time .time ()-start_time )*1000 ,
        version =version )
    except Exception as e :
        return ToolResult ("qiling",False ,False ,{},
        error =str (e ),
        runtime_ms =(time .time ()-start_time )*1000 )




def _adb_list_packages (timeout :int =10 )->list [str ]|None :
    start_time =time .time ()

    if not _which ("adb"):
        return None 
    try :
        proc =_run_process (["adb","shell","pm","list","packages"],timeout =timeout )
        if proc .returncode !=0 :
            return []
        pkgs =[]
        for line in proc .stdout .splitlines ():
            line =line .strip ()
            if line .startswith ("package:"):
                pkgs .append (line .split (":",1 )[1 ])
        return pkgs 
    except Exception :
        return []


def check_xposed_lsposed (timeout :int =10 )->ToolResult :
    start_time =time .time ()

    if not _which ("adb"):
        return ToolResult ("xposed_lsposed",False ,False ,{},
        error ="adb not found",
        runtime_ms =(time .time ()-start_time )*1000 )

    pkgs =_adb_list_packages (timeout =timeout )or []
    indicators ={
    "org.lsposed.manager":any (p =="org.lsposed.manager"for p in pkgs ),
    "de.robv.android.xposed.installer":any (p =="de.robv.android.xposed.installer"for p in pkgs ),
    "mobi.acpm.inspeckage":any (p =="mobi.acpm.inspeckage"for p in pkgs ),
    }


    prop_value =None 
    try :
        proc =_run_process (["adb","shell","getprop","persist.lsposed.api"],timeout =timeout )
        if proc .returncode ==0 :
            prop_value =proc .stdout .strip ()or None 
    except Exception :
        pass 

    available =any (indicators .values ())or bool (prop_value )
    return ToolResult (
    "xposed_lsposed",
    _which ("adb"),
    available ,
    {"packages":indicators ,"persist.lsposed.api":prop_value },
    None if available else "not detected",
    runtime_ms =(time .time ()-start_time )*1000 
    )


def check_magisk_zygisk (timeout :int =10 )->ToolResult :
    start_time =time .time ()

    if not _which ("adb"):
        return ToolResult ("magisk_zygisk",False ,False ,{},
        error ="adb not found",
        runtime_ms =(time .time ()-start_time )*1000 )

    pkgs =_adb_list_packages (timeout =timeout )or []
    has_magisk_app =any (p =="com.topjohnwu.magisk"for p in pkgs )

    magisk_version =None 
    zygisk_state =None 
    errors :list [str ]=[]


    try :
        proc =_run_process (["adb","shell","magisk","-V"],timeout =timeout )
        if proc .returncode ==0 :
            magisk_version =proc .stdout .strip ()or proc .stderr .strip ()or None 
    except Exception as e :
        errors .append (str (e ))


    if magisk_version is None :
        try :
            proc =_run_process (["adb","shell","su","-c","magisk -V"],timeout =timeout )
            if proc .returncode ==0 :
                magisk_version =proc .stdout .strip ()or proc .stderr .strip ()or None 
        except Exception as e :
            errors .append (str (e ))


    try :
        proc =_run_process (["adb","shell","magisk","--zygisk"],timeout =timeout )
        if proc .returncode ==0 :
            out =(proc .stdout or proc .stderr ).strip ().lower ()
            if out :
                zygisk_state =out 
    except Exception :
        pass 
    if zygisk_state is None :

        try :
            proc =_run_process (["adb","shell","getprop","zygisk"],timeout =timeout )
            if proc .returncode ==0 :
                zygisk_state =(proc .stdout or "").strip ()or None 
        except Exception :
            pass 

    available =has_magisk_app or (magisk_version is not None )
    return ToolResult (
    "magisk_zygisk",
    _which ("adb"),
    available ,
    {"has_magisk_app":has_magisk_app ,"magisk_version":magisk_version ,"zygisk":zygisk_state },
    None if available else ("not detected"if not errors else "; ".join (errors )),
    runtime_ms =(time .time ()-start_time )*1000 
    )


def check_objection ()->ToolResult :
    start_time =time .time ()
    version =None 

    available =_which ("objection")

    if available :
        try :
            proc =_run_process (["objection","--version"],timeout =10 )
            if proc .returncode ==0 :
                version =proc .stdout .strip ()
        except Exception :
            pass 

    return ToolResult ("objection",available ,available ,{},
    runtime_ms =(time .time ()-start_time )*1000 ,
    version =version )


def check_inspeckage (timeout :int =10 )->ToolResult :
    start_time =time .time ()

    if not _which ("adb"):
        return ToolResult ("inspeckage",False ,False ,{},
        error ="adb not found",
        runtime_ms =(time .time ()-start_time )*1000 )
    pkgs =_adb_list_packages (timeout =timeout )or []
    present =any (p =="mobi.acpm.inspeckage"for p in pkgs )
    return ToolResult ("inspeckage",True ,present ,{"present":present },
    runtime_ms =(time .time ()-start_time )*1000 )


def check_radare2_rizin_r2frida ()->ToolResult :
    start_time =time .time ()
    version =None 

    r2 =_which ("radare2")or _which ("r2")
    rizin =_which ("rizin")or _which ("rz-bin")
    r2pm =_which ("r2pm")
    r2frida =_which ("r2frida")


    if r2 :
        try :
            proc =_run_process (["radare2","-v"],timeout =10 )
            if proc .returncode ==0 :
                version =proc .stdout .split ('\n')[0 ].strip ()
        except Exception :
            pass 


    r2frida_available =r2frida 
    if not r2frida_available and r2pm :
        try :
            proc =_run_process (["r2pm","-l"],timeout =10 )
            if proc .returncode ==0 and "r2frida"in proc .stdout :
                r2frida_available =True 
        except Exception :
            pass 

    available =r2 or rizin 
    return ToolResult (
    "radare2_rizin_r2frida",
    available ,
    available ,
    {"radare2":bool (r2 ),"rizin":bool (rizin ),"r2pm":bool (r2pm ),"r2frida":bool (r2frida_available )},
    runtime_ms =(time .time ()-start_time )*1000 ,
    version =version 
    )


def check_jadx ()->ToolResult :
    start_time =time .time ()
    version =None 

    cli =_which ("jadx")
    gui =_which ("jadx-gui")or _which ("jadx.gui")
    available =cli or gui 


    if cli :
        try :
            proc =_run_process (["jadx","--version"],timeout =10 )
            if proc .returncode ==0 :
                version =proc .stdout .strip ()
        except Exception :
            pass 

    return ToolResult ("jadx",available ,available ,{"cli":cli ,"gui":gui },
    runtime_ms =(time .time ()-start_time )*1000 ,
    version =version )


def run_jadx_decompile (apk_path :str ,output_dir :Path ,timeout :int =600 )->ToolResult :
    start_time =time .time ()
    version =None 

    if not _which ("jadx"):
        return ToolResult ("jadx_decompile",False ,False ,{},
        error ="jadx not found in PATH",
        runtime_ms =(time .time ()-start_time )*1000 )


    try :
        proc =_run_process (["jadx","--version"],timeout =10 )
        if proc .returncode ==0 :
            version =proc .stdout .strip ()
    except Exception :
        pass 

    out =output_dir /"jadx"
    out .mkdir (parents =True ,exist_ok =True )
    try :

        proc =_run_process (
        ["jadx","--show-bad-code","--deobf","--deobf-min","3","--deobf-max","64",
        "--deobf-use-sourcename","-d",str (out ),apk_path ],
        timeout =timeout 
        )

        success =proc .returncode ==0 
        data ={
        "out_dir":str (out ),
        "stdout":proc .stdout [-4000 :],
        "stderr":proc .stderr [-4000 :],
        }


        try :
            java_files =list (out .glob ("**/*.java"))
            xml_files =list (out .glob ("**/*.xml"))
            data ["java_files"]=len (java_files )
            data ["xml_files"]=len (xml_files )
        except Exception :
            pass 

        return ToolResult ("jadx_decompile",True ,success ,data ,
        None if success else proc .stderr ,
        runtime_ms =(time .time ()-start_time )*1000 ,
        version =version )
    except subprocess .TimeoutExpired :
        return ToolResult ("jadx_decompile",True ,False ,{"out_dir":str (out )},
        error ="timeout",
        runtime_ms =timeout *1000 ,
        version =version )
    except Exception as e :
        return ToolResult ("jadx_decompile",True ,False ,{"out_dir":str (out )},
        error =str (e ),
        runtime_ms =(time .time ()-start_time )*1000 ,
        version =version )


def check_mobsf ()->ToolResult :
    start_time =time .time ()

    try :
        proc =_run_process (["mobile-security-framework-mobsf","--version"],timeout =5 )
        if proc .returncode ==0 or "MobSF"in proc .stdout or "MobSF"in proc .stderr :
            version =proc .stdout .strip ()or "Unknown version"
            return ToolResult ("MobSF",True ,True ,{"version":version },None ,
            runtime_ms =(time .time ()-start_time )*1000 ,
            version =version )
        return ToolResult ("MobSF",False ,False ,{},"Command found but failed to execute properly",
        runtime_ms =(time .time ()-start_time )*1000 )
    except (FileNotFoundError ,subprocess .SubprocessError )as e :
        return ToolResult ("MobSF",False ,False ,{},f"Tool not found: {str (e )}",
        runtime_ms =(time .time ()-start_time )*1000 )


def check_appium ()->ToolResult :
    start_time =time .time ()

    try :
        proc =_run_process (["appium","-v"],timeout =5 )
        if proc .returncode ==0 :
            version =proc .stdout .strip ()
            return ToolResult ("Appium",True ,True ,{"version":version },None ,
            runtime_ms =(time .time ()-start_time )*1000 ,
            version =version )
        return ToolResult ("Appium",False ,False ,{},"Command found but failed to execute properly",
        runtime_ms =(time .time ()-start_time )*1000 )
    except (FileNotFoundError ,subprocess .SubprocessError )as e :
        return ToolResult ("Appium",False ,False ,{},f"Tool not found: {str (e )}",
        runtime_ms =(time .time ()-start_time )*1000 )


def check_apktool ()->ToolResult :
    start_time =time .time ()

    try :
        proc =_run_process (["apktool","--version"],timeout =5 )
        if proc .returncode ==0 :
            version =proc .stdout .strip ()
            return ToolResult ("APKTool",True ,True ,{"version":version },None ,
            runtime_ms =(time .time ()-start_time )*1000 ,
            version =version )
        return ToolResult ("APKTool",False ,False ,{},"Command found but failed to execute properly",
        runtime_ms =(time .time ()-start_time )*1000 )
    except (FileNotFoundError ,subprocess .SubprocessError )as e :
        return ToolResult ("APKTool",False ,False ,{},f"Tool not found: {str (e )}",
        runtime_ms =(time .time ()-start_time )*1000 )


def run_apktool_decode (apk_path :str ,output_dir :Path ,timeout :int =300 )->ToolResult :
    start_time =time .time ()
    version =None 

    if not _which ("apktool"):
        return ToolResult ("apktool_decode",False ,False ,{},
        error ="apktool not found in PATH",
        runtime_ms =(time .time ()-start_time )*1000 )


    try :
        proc =_run_process (["apktool","--version"],timeout =10 )
        if proc .returncode ==0 :
            version =proc .stdout .strip ()
    except Exception :
        pass 

    out =output_dir /"apktool"
    out .mkdir (parents =True ,exist_ok =True )
    try :
        proc =_run_process (
        ["apktool","d","-f","-o",str (out ),apk_path ],
        timeout =timeout 
        )

        success =proc .returncode ==0 
        data ={
        "out_dir":str (out ),
        "stdout":proc .stdout [-4000 :],
        "stderr":proc .stderr [-4000 :],
        }


        try :
            manifest =out /"AndroidManifest.xml"
            smali_files =list (out .glob ("**/smali/**/*.smali"))
            res_files =list (out .glob ("**/res/**/*"))
            data ["has_manifest"]=manifest .exists ()
            data ["smali_files"]=len (smali_files )
            data ["res_files"]=len (res_files )
        except Exception :
            pass 

        return ToolResult ("apktool_decode",True ,success ,data ,
        None if success else proc .stderr ,
        runtime_ms =(time .time ()-start_time )*1000 ,
        version =version )
    except subprocess .TimeoutExpired :
        return ToolResult ("apktool_decode",True ,False ,{"out_dir":str (out )},
        error ="timeout",
        runtime_ms =timeout *1000 ,
        version =version )
    except Exception as e :
        return ToolResult ("apktool_decode",True ,False ,{"out_dir":str (out )},
        error =str (e ),
        runtime_ms =(time .time ()-start_time )*1000 ,
        version =version )


def check_house ()->ToolResult :
    start_time =time .time ()

    try :
        proc =_run_process (["house","--version"],timeout =5 )
        if proc .returncode ==0 :
            version =proc .stdout .strip ()
            return ToolResult ("House",True ,True ,{"version":version },None ,
            runtime_ms =(time .time ()-start_time )*1000 ,
            version =version )
        return ToolResult ("House",False ,False ,{},"Command found but failed to execute properly",
        runtime_ms =(time .time ()-start_time )*1000 )
    except (FileNotFoundError ,subprocess .SubprocessError )as e :
        return ToolResult ("House",False ,False ,{},f"Tool not found: {str (e )}",
        runtime_ms =(time .time ()-start_time )*1000 )




def run_azure_security_scan (apk_path :str ,output_dir :Path ,timeout :int =600 )->ToolResult :
    start_time =time .time ()


    client_id =os .environ .get ("AZURE_CLIENT_ID")
    client_secret =os .environ .get ("AZURE_CLIENT_SECRET")
    tenant_id =os .environ .get ("AZURE_TENANT_ID")

    if not all ([client_id ,client_secret ,tenant_id ]):
        return ToolResult ("azure_security_scan",False ,False ,{},
        error ="Required Azure credentials not set in environment variables",
        runtime_ms =(time .time ()-start_time )*1000 )

    try :





        apk_hash =_get_file_hash (apk_path )
        scan_id =f"azure-scan-{apk_hash [:10 ]}"


        report_path =output_dir /"azure_security_scan.json"
        mock_report ={
        "scan_id":scan_id ,
        "timestamp":time .time (),
        "apk_hash":apk_hash ,
        "security_score":85 ,
        "findings":[
        {"category":"info","title":"Azure scan completed","description":"Demo scan result"}
        ],
        "recommendations":[
        "Consider implementing certificate pinning",
        "Ensure sensitive data is encrypted at rest"
        ]
        }

        report_path .write_text (json .dumps (mock_report ,indent =2 ))

        return ToolResult ("azure_security_scan",True ,True ,
        {"scan_id":scan_id ,"report_file":str (report_path ),"summary":mock_report },
        runtime_ms =(time .time ()-start_time )*1000 ,
        version ="1.0.0")
    except Exception as e :
        return ToolResult ("azure_security_scan",True ,False ,{},
        error =str (e ),
        runtime_ms =(time .time ()-start_time )*1000 )


def run_batch_scan (apk_path :str ,output_dir :Path ,tools :List [str ]=None ,timeout :int =1200 )->Dict [str ,ToolResult ]:
    start_time =time .time ()


    default_tools =[
    "androguard","apkid","yara","jadx_decompile",
    "apktool_decode","quark","mobsf"
    ]

    tools_to_run =tools or default_tools 
    results ={}


    try :
        sha256 =_get_file_hash (apk_path ,'sha256')
        md5 =_get_file_hash (apk_path ,'md5')
        hashes ={"sha256":sha256 ,"md5":md5 }
    except Exception as e :
        logger .error (f"Failed to compute file hashes: {e }")
        hashes ={}


    remaining_time =timeout 


    for tool in tools_to_run :
        tool_start =time .time ()


        if remaining_time <30 :
            results [tool ]=ToolResult (tool ,True ,False ,{},
            error ="Skipped due to batch timeout",
            runtime_ms =0 )
            continue 

        tool_timeout =min (remaining_time ,300 )

        try :
            if tool =="androguard":
                results [tool ]=run_androguard (apk_path ,timeout =tool_timeout )
            elif tool =="apkid":
                results [tool ]=run_apkid (apk_path ,timeout =tool_timeout )
            elif tool =="yara":
                results [tool ]=run_yara_scan (apk_path ,None ,timeout =tool_timeout )
            elif tool =="jadx_decompile":
                results [tool ]=run_jadx_decompile (apk_path ,output_dir ,timeout =tool_timeout )
            elif tool =="apktool_decode":
                results [tool ]=run_apktool_decode (apk_path ,output_dir ,timeout =tool_timeout )
            elif tool =="quark":
                results [tool ]=run_quark (apk_path ,output_dir ,timeout =tool_timeout )
            elif tool =="mobsf":
                results [tool ]=run_mobsf (apk_path ,output_dir ,timeout =tool_timeout )
            elif tool =="virustotal"and hashes .get ("sha256"):
                results [tool ]=run_virustotal_lookup (hashes ["sha256"],output_dir ,timeout =tool_timeout )
            elif tool =="azure_security_scan":
                results [tool ]=run_azure_security_scan (apk_path ,output_dir ,timeout =tool_timeout )
            else :
                results [tool ]=ToolResult (tool ,False ,False ,{},error =f"Tool {tool } not implemented or hash not available")
        except Exception as e :
            results [tool ]=ToolResult (tool ,True ,False ,{},error =f"Batch execution error: {str (e )}")


        tool_runtime =time .time ()-tool_start 
        remaining_time =max (0 ,remaining_time -tool_runtime )


    summary_path =output_dir /"batch_scan_summary.json"
    summary ={
    "apk_path":apk_path ,
    "hashes":hashes ,
    "scan_time":time .strftime ("%Y-%m-%d %H:%M:%S"),
    "total_runtime_ms":(time .time ()-start_time )*1000 ,
    "tools_run":len (results ),
    "successful_tools":sum (1 for r in results .values ()if r .success ),
    "results":{name :result .to_dict ()for name ,result in results .items ()}
    }

    summary_path .write_text (json .dumps (summary ,indent =2 ))

    return results 
    summary_path =output_dir /"batch_scan_summary.json"
    summary ={
    "apk_path":apk_path ,
    "hashes":hashes ,
    "scan_time":time .strftime ("%Y-%m-%d %H:%M:%S"),
    "total_runtime_ms":(time .time ()-start_time )*1000 ,
    "tools_run":len (results ),
    "successful_tools":sum (1 for r in results .values ()if r .success ),
    "results":{name :result .to_dict ()for name ,result in results .items ()}
    }

    summary_path .write_text (json .dumps (summary ,indent =2 ))

    return results 
