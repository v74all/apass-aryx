#!/usr/bin/env python3
from __future__ import annotations 

import argparse 
import contextlib 
import http .server 
import os 
from pathlib import Path 
import sys 
import threading 
import time 
import webbrowser 
from typing import Union 

from .analysis_dashboard_impl import AnalysisDashboard 


def generate_dashboard (workspace_root :Union [str ,os .PathLike [str ]]=".")->Path :
    dashboard =AnalysisDashboard (str (workspace_root ))
    return dashboard .save_dashboard ()


class _QuietHTTPRequestHandler (http .server .SimpleHTTPRequestHandler ):
    def log_message (self ,format :str ,*args )->None :

        pass 


def serve_dashboard (
file_path :Path ,
*,
host :str ="127.0.0.1",
port :int =8080 ,
open_browser :bool =True ,
auto_port :bool =False ,
retries :int =25 ,
verbose :bool =False ,
)->None :
    file_path =file_path .resolve ()
    serve_dir =file_path .parent 
    index_name =file_path .name 


    base_handler =http .server .SimpleHTTPRequestHandler if verbose else _QuietHTTPRequestHandler 

    class _Handler (base_handler ):
        def __init__ (self ,*args ,**kwargs ):
            super ().__init__ (*args ,directory =str (serve_dir ),**kwargs )


    HTTPServer =getattr (http .server ,"ThreadingHTTPServer",http .server .HTTPServer )

    bound =False 
    attempt =0 
    last_error :Exception |None =None 
    while not bound and (attempt <=max (0 ,retries )if auto_port else attempt ==0 ):
        try :
            with HTTPServer ((host ,port ),_Handler )as httpd :
                bound =True 
                url =f"http://{host }:{httpd .server_address [1 ]}/{index_name }"
                print (f"Serving dashboard at: {url }")
                if open_browser :

                    threading .Thread (
                    target =lambda :(time .sleep (0.2 ),webbrowser .open_new_tab (url )),
                    daemon =True ,
                    ).start ()
                try :
                    httpd .serve_forever ()
                except KeyboardInterrupt :
                    print ("\nShutting down server...")
                finally :
                    with contextlib .suppress (Exception ):
                        httpd .server_close ()
        except OSError as exc :
            last_error =exc 
            if auto_port :

                if port ==0 :
                    break 
                attempt +=1 
                port +=1 
                continue 
            break 

    if not bound and last_error :

        raise RuntimeError (f"Failed to start server on {host }:{port } after {attempt } attempts: {last_error }")


def launch_dashboard (port :int =8080 )->None :
    output =generate_dashboard (Path (__file__ ).resolve ().parents [2 ])
    print (f"✓ Dashboard generated: {output }")
    serve_dashboard (output ,host ="127.0.0.1",port =port ,open_browser =True ,auto_port =False ,verbose =False )


def _parse_args (argv :list [str ])->argparse .Namespace :
    p =argparse .ArgumentParser (description ="APK Analysis Dashboard Launcher")
    p .add_argument ("--workspace",default =Path (__file__ ).resolve ().parents [2 ],help ="Workspace root (default: repo root)")
    p .add_argument ("--host",default ="127.0.0.1",help ="Host/IP to bind (default: 127.0.0.1)")
    p .add_argument ("--port",type =int ,default =8080 ,help ="Port to serve on (0 for ephemeral)")
    p .add_argument ("--no-open",action ="store_true",help ="Do not open a browser automatically")
    p .add_argument ("--serve",action ="store_true",help ="Serve the generated dashboard over HTTP")
    p .add_argument ("--auto-port",action ="store_true",help ="If port is busy, try the next ports until one works")
    p .add_argument ("--retries",type =int ,default =25 ,help ="Max additional ports to try when --auto-port is set")
    p .add_argument ("--verbose",action ="store_true",help ="Verbose HTTP request logging")
    return p .parse_args (argv )


def main (argv :list [str ]|None =None )->None :
    ns =_parse_args (argv or sys .argv [1 :])
    workspace =Path (str (ns .workspace )).resolve ()


    out_path =generate_dashboard (workspace )
    print (f"✓ Dashboard generated: {out_path }")


    latest_path =out_path .parent /"latest_dashboard.html"
    if latest_path .exists ()or latest_path .is_symlink ():
        latest_path .unlink ()
    latest_path .symlink_to (out_path .name )

    print (f"✓ Latest dashboard: {latest_path }")
    print (f"📄 File URL: file://{out_path }")

    if ns .serve :
        serve_dashboard (
        out_path ,
        host =ns .host ,
        port =ns .port ,
        open_browser =not ns .no_open ,
        auto_port =ns .auto_port ,
        retries =ns .retries ,
        verbose =ns .verbose ,
        )
    else :
        if not ns .no_open :
            webbrowser .open_new_tab (f"file://{out_path }")


if __name__ =="__main__":
    main ()
