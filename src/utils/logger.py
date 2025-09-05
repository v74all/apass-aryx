#!/usr/bin/env python3

import logging 
import sys 
from datetime import datetime 
from pathlib import Path 
from typing import Optional ,Union ,Dict ,Any 

try :
    from colorama import Fore ,Style ,init 
    init (autoreset =True )
    COLORAMA_AVAILABLE =True 
except ImportError :

    class DummyColor :
        RED =""
        GREEN =""
        YELLOW =""
        BLUE =""
        MAGENTA =""
        CYAN =""
        WHITE =""
        RESET =""

    class DummyStyle :
        BRIGHT =""
        DIM =""
        RESET_ALL =""

    Fore =DummyColor ()
    Style =DummyStyle ()
    COLORAMA_AVAILABLE =False 


class Logger :

    def __init__ (self ,name :str ="apass-aryx",log_file :Optional [str ]=None ,level :str ="INFO"):
        self .name =name 
        self .level =getattr (logging ,level .upper (),logging .INFO )
        self .log_file =log_file 


        self .logger =logging .getLogger (name )
        self .logger .setLevel (self .level )


        self .logger .handlers .clear ()


        console_handler =logging .StreamHandler (sys .stdout )
        console_handler .setLevel (self .level )
        console_formatter =ColoredFormatter ()
        console_handler .setFormatter (console_formatter )
        self .logger .addHandler (console_handler )


        if log_file :
            try :
                file_handler =logging .FileHandler (log_file )
                file_handler .setLevel (self .level )
                file_formatter =logging .Formatter (
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                file_handler .setFormatter (file_formatter )
                self .logger .addHandler (file_handler )
            except Exception as e :
                self .logger .warning (f"Could not create file handler: {e }")

    def debug (self ,message :str ,**kwargs ):
        self ._log (logging .DEBUG ,message ,**kwargs )

    def info (self ,message :str ,**kwargs ):
        self ._log (logging .INFO ,message ,**kwargs )

    def warning (self ,message :str ,**kwargs ):
        self ._log (logging .WARNING ,message ,**kwargs )

    def error (self ,message :str ,**kwargs ):
        self ._log (logging .ERROR ,message ,**kwargs )

    def critical (self ,message :str ,**kwargs ):
        self ._log (logging .CRITICAL ,message ,**kwargs )

    def success (self ,message :str ,**kwargs ):
        self ._log (logging .INFO ,f"✅ {message }",level_name ="SUCCESS",**kwargs )

    def fail (self ,message :str ,**kwargs ):
        self ._log (logging .ERROR ,f"❌ {message }",level_name ="FAIL",**kwargs )

    def security (self ,message :str ,**kwargs ):
        self ._log (logging .WARNING ,f"🔒 {message }",level_name ="SECURITY",**kwargs )

    def analysis (self ,message :str ,**kwargs ):
        self ._log (logging .INFO ,f"🔍 {message }",level_name ="ANALYSIS",**kwargs )

    def network (self ,message :str ,**kwargs ):
        self ._log (logging .INFO ,f"🌐 {message }",level_name ="NETWORK",**kwargs )

    def _log (self ,level :int ,message :str ,level_name :Optional [str ]=None ,**kwargs ):
        if kwargs :

            metadata_str =" | ".join (f"{k }={v }"for k ,v in kwargs .items ())
            message =f"{message } | {metadata_str }"


        if level_name :
            record =self .logger .makeRecord (
            self .logger .name ,level ,__file__ ,0 ,message ,(),None 
            )
            record .levelname =level_name 
            self .logger .handle (record )
        else :
            self .logger .log (level ,message )


class ColoredFormatter (logging .Formatter ):

    COLORS ={
    'DEBUG':Fore .CYAN ,
    'INFO':Fore .WHITE ,
    'WARNING':Fore .YELLOW ,
    'ERROR':Fore .RED ,
    'CRITICAL':Fore .MAGENTA ,
    'SUCCESS':Fore .GREEN ,
    'FAIL':Fore .RED ,
    'SECURITY':Fore .YELLOW ,
    'ANALYSIS':Fore .BLUE ,
    'NETWORK':Fore .CYAN ,
    }

    def format (self ,record ):

        color =self .COLORS .get (record .levelname ,Fore .WHITE )


        timestamp =datetime .fromtimestamp (record .created ).strftime ('%H:%M:%S')


        if COLORAMA_AVAILABLE :
            formatted =f"{Fore .WHITE }[{timestamp }] {color }{record .levelname :<8}{Style .RESET_ALL } {record .getMessage ()}"
        else :
            formatted =f"[{timestamp }] {record .levelname :<8} {record .getMessage ()}"

        return formatted 



_global_logger =None 

def get_logger (name :str ="apass-aryx",log_file :Optional [str ]=None ,level :str ="INFO")->Logger :
    global _global_logger 
    if _global_logger is None :
        _global_logger =Logger (name ,log_file ,level )
    return _global_logger 


def setup_logging (log_file :Optional [str ]=None ,level :str ="INFO"):
    global _global_logger 
    _global_logger =Logger ("apass-aryx",log_file ,level )
    return _global_logger 



def debug (message :str ,**kwargs ):
    get_logger ().debug (message ,**kwargs )

def info (message :str ,**kwargs ):
    get_logger ().info (message ,**kwargs )

def warning (message :str ,**kwargs ):
    get_logger ().warning (message ,**kwargs )

def error (message :str ,**kwargs ):
    get_logger ().error (message ,**kwargs )

def critical (message :str ,**kwargs ):
    get_logger ().critical (message ,**kwargs )

def success (message :str ,**kwargs ):
    get_logger ().success (message ,**kwargs )

def fail (message :str ,**kwargs ):
    get_logger ().fail (message ,**kwargs )

def security (message :str ,**kwargs ):
    get_logger ().security (message ,**kwargs )

def analysis (message :str ,**kwargs ):
    get_logger ().analysis (message ,**kwargs )

def network (message :str ,**kwargs ):
    get_logger ().network (message ,**kwargs )
