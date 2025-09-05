#!/usr/bin/env python3
from __future__ import annotations 

import argparse 
import json 
import sys 
import platform 
from datetime import datetime 
from pathlib import Path 
from typing import Any ,Dict ,List ,Optional 

try :
    from colorama import init ,Fore ,Style 
    COLORAMA_AVAILABLE =True 
except ImportError :
    COLORAMA_AVAILABLE =False 

    class DummyFore :
        GREEN =RED =YELLOW =BLUE =RESET =""
    class DummyStyle :
        BRIGHT =RESET_ALL =""
    Fore =DummyFore ()
    Style =DummyStyle ()

try :
    from .tool_integrations import (
    check_xposed_lsposed ,
    check_magisk_zygisk ,
    check_objection ,
    check_inspeckage ,
    check_radare2_rizin_r2frida ,
    check_jadx ,
    check_mobsf ,
    check_appium ,
    check_apktool ,
    check_house ,
    ToolResult ,
    )
except Exception :

    import sys as _sys 
    from pathlib import Path as _Path 
    _sys .path .insert (0 ,str (_Path (__file__ ).resolve ().parents [1 ]))
    try :
        from analyzers .tool_integrations import (
        check_xposed_lsposed ,
        check_magisk_zygisk ,
        check_objection ,
        check_inspeckage ,
        check_radare2_rizin_r2frida ,
        check_jadx ,
        ToolResult ,
        )

        try :
            from analyzers .tool_integrations import check_mobsf 
        except ImportError :
            def check_mobsf ()->ToolResult :
                return ToolResult ("MobSF",False ,False ,{},"Tool check not implemented")

        try :
            from analyzers .tool_integrations import check_appium 
        except ImportError :
            def check_appium ()->ToolResult :
                return ToolResult ("Appium",False ,False ,{},"Tool check not implemented")

        try :
            from analyzers .tool_integrations import check_apktool 
        except ImportError :
            def check_apktool ()->ToolResult :
                return ToolResult ("APKTool",False ,False ,{},"Tool check not implemented")

        try :
            from analyzers .tool_integrations import check_house 
        except ImportError :
            def check_house ()->ToolResult :
                return ToolResult ("House",False ,False ,{},"Tool check not implemented")
    except Exception as e :
        raise SystemExit (f"Failed to import tool_integrations: {e }")


def _tr (tool :ToolResult )->Dict [str ,Any ]:
    return {
    "name":tool .name ,
    "available":tool .available ,
    "success":tool .success ,
    "data":tool .data ,
    "error":tool .error ,
    }


def get_system_info ()->Dict [str ,Any ]:
    return {
    "platform":platform .platform (),
    "python_version":platform .python_version (),
    "timestamp":datetime .now ().isoformat (),
    "system":platform .system (),
    "architecture":platform .machine (),
    }


def print_tool_status (tool :ToolResult ,verbose :bool =False )->None :
    if tool .success :
        status =f"{Fore .GREEN }YES{Style .RESET_ALL }"
    elif tool .available :
        status =f"{Fore .YELLOW }MAYBE{Style .RESET_ALL }"
    else :
        status =f"{Fore .RED }NO{Style .RESET_ALL }"

    print (f"- {Style .BRIGHT }{tool .name }{Style .RESET_ALL }: {status }")

    if tool .error :
        print (f"  {Fore .RED }error:{Style .RESET_ALL } {tool .error }")

    if tool .data and verbose :

        for key ,value in tool .data .items ():
            print (f"  {Fore .BLUE }{key }{Style .RESET_ALL }: {value }")
    elif tool .data :

        compact_keys =", ".join (sorted (tool .data .keys ()))
        print (f"  {Fore .BLUE }data:{Style .RESET_ALL } {compact_keys }")


def get_tool_recommendations (checks :List [ToolResult ])->List [str ]:
    recommendations =[]


    if not any (c .success for c in checks if c .name in ["JADX","APKTool"]):
        recommendations .append ("Install JADX or APKTool for basic APK decompilation")


    if not any (c .success for c in checks if c .name in ["Objection","Radare2 / Rizin / r2frida","House"]):
        recommendations .append ("Install Frida/Objection for runtime analysis and instrumentation")


    if not any (c .success for c in checks if c .name in ["Magisk/Zygisk","Xposed/LSPosed"]):
        recommendations .append ("Consider a rooted device with Magisk or Xposed for advanced analysis")


    if not any (c .success for c in checks ):
        recommendations .append ("Your environment lacks mobile security tools. Consider setting up a dedicated Android analysis environment")

    return recommendations 


def print_summary (checks :List [ToolResult ])->None :
    total =len (checks )
    available =sum (1 for c in checks if c .success )
    partial =sum (1 for c in checks if c .available and not c .success )

    print (f"\n{Style .BRIGHT }Environment Summary:{Style .RESET_ALL }")
    print (f"- Tools checked: {total }")
    print (f"- Available: {Fore .GREEN }{available }{Style .RESET_ALL }")
    print (f"- Partially available: {Fore .YELLOW }{partial }{Style .RESET_ALL }")
    print (f"- Missing: {Fore .RED }{total -available -partial }{Style .RESET_ALL }")


    if available /total >=0.7 :
        print (f"\n{Fore .GREEN }Environment readiness: GOOD{Style .RESET_ALL }")
    elif available /total >=0.4 :
        print (f"\n{Fore .YELLOW }Environment readiness: PARTIAL{Style .RESET_ALL }")
    else :
        print (f"\n{Fore .RED }Environment readiness: INSUFFICIENT{Style .RESET_ALL }")


def main ()->int :
    p =argparse .ArgumentParser (description ="Detect mobile reversing toolchain availability")
    p .add_argument ("--json",action ="store_true",help ="Print JSON output")
    p .add_argument ("--out",type =Path ,help ="Save JSON summary to this path")
    p .add_argument ("--verbose","-v",action ="store_true",help ="Show detailed output")
    p .add_argument ("--no-color",action ="store_true",help ="Disable colorized output")
    p .add_argument ("--recommendations",action ="store_true",help ="Show tool recommendations")
    args =p .parse_args ()


    if COLORAMA_AVAILABLE and not args .no_color :
        init ()


    checks =[
    check_xposed_lsposed (),
    check_magisk_zygisk (),
    check_objection (),
    check_inspeckage (),
    check_radare2_rizin_r2frida (),
    check_jadx (),
    check_mobsf (),
    check_appium (),
    check_apktool (),
    check_house (),
    ]


    summary ={c .name :_tr (c )for c in checks }


    metadata ={
    "system_info":get_system_info (),
    "summary":{
    "total_tools":len (checks ),
    "available_tools":sum (1 for c in checks if c .success ),
    "partial_tools":sum (1 for c in checks if c .available and not c .success ),
    "missing_tools":sum (1 for c in checks if not c .available ),
    }
    }

    full_data ={
    "metadata":metadata ,
    "tools":summary ,
    }

    if args .recommendations :
        full_data ["recommendations"]=get_tool_recommendations (checks )


    if args .out :
        args .out .parent .mkdir (parents =True ,exist_ok =True )
        args .out .write_text (json .dumps (full_data ,indent =2 ))


    if args .json :
        print (json .dumps (full_data ,indent =2 ))
    else :

        print (f"{Style .BRIGHT }System Information:{Style .RESET_ALL }")
        print (f"- Platform: {platform .platform ()}")
        print (f"- Python: {platform .python_version ()}")
        print ()


        print (f"{Style .BRIGHT }Tool Availability:{Style .RESET_ALL }")
        for c in checks :
            print_tool_status (c ,args .verbose )


        print_summary (checks )


        if args .recommendations :
            print (f"\n{Style .BRIGHT }Recommendations:{Style .RESET_ALL }")
            recommendations =get_tool_recommendations (checks )
            if recommendations :
                for i ,rec in enumerate (recommendations ,1 ):
                    print (f"{i }. {rec }")
            else :
                print ("Your environment appears to be well-equipped for mobile app analysis.")

    return 0 


if __name__ =="__main__":
    raise SystemExit (main ())
