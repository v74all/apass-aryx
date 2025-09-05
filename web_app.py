#!/usr/bin/env python3
from __future__ import annotations 

import os 
import tempfile 
import threading 
import uuid 
import json 
import time 
import pickle 
import random 
import shutil 
import argparse 
import sys 
import copy 
import importlib .util 
try :
    import psutil 
except Exception :
    psutil =None 
from pathlib import Path 
from typing import Dict ,List ,Optional ,Any ,Union 
from datetime import datetime 
from functools import wraps 
from io import StringIO 

from flask import Flask ,render_template ,request ,jsonify ,redirect ,url_for ,send_from_directory 
from flask_wtf .csrf import CSRFProtect ,CSRFError ,generate_csrf 
from werkzeug .utils import secure_filename 


try :
    from apass_aryx import (
    do_analyze ,
    cmd_status ,
    REPO_ROOT ,
    APP_NAME ,
    APP_VERSION ,
    APP_AUTHOR ,
    APP_SLOGAN ,
    APP_TAGLINE ,
    log ,
    config ,
    do_analyze_details as _do_analyze_details 
    )

    try :
        src_path =(REPO_ROOT /"src")
        if str (src_path )not in sys .path :
            sys .path .insert (0 ,str (src_path ))
    except Exception :
        pass 

    if 'APP_SLOGAN'not in locals ():
        APP_SLOGAN ="No mask can hide. APASS ARYX sees through."
    if 'APP_TAGLINE'not in locals ():
        APP_TAGLINE ="APASS ARYX, part of the V7lthronyx_IX arsenal"

    try :
        from analyzers import get_analyzers 
    except Exception :
        get_analyzers =None 
    do_analyze_details =_do_analyze_details 
except Exception :

    module_path =Path (__file__ ).resolve ().parent /"apass-aryx.py"
    spec =importlib .util .spec_from_file_location ("apass_aryx",str (module_path ))
    if not spec or not spec .loader :
        raise 
    aryx =importlib .util .module_from_spec (spec )
    spec .loader .exec_module (aryx )
    do_analyze =getattr (aryx ,"do_analyze")
    cmd_status =getattr (aryx ,"cmd_status")
    REPO_ROOT =getattr (aryx ,"REPO_ROOT")
    APP_NAME =getattr (aryx ,"APP_NAME")
    APP_VERSION =getattr (aryx ,"APP_VERSION")
    APP_AUTHOR =getattr (aryx ,"APP_AUTHOR")
    APP_SLOGAN =getattr (aryx ,"APP_SLOGAN","No mask can hide. APASS ARYX sees through.")
    APP_TAGLINE =getattr (aryx ,"APP_TAGLINE","APASS ARYX, part of the V7lthronyx_IX arsenal")
    log =getattr (aryx ,"log")
    config =getattr (aryx ,"config")
    do_analyze_details =getattr (aryx ,"do_analyze_details",None )

app =Flask (__name__ )
app .config ['UPLOAD_FOLDER']=Path (tempfile .gettempdir ())/"apass-aryx-uploads"
app .config ['MAX_CONTENT_LENGTH']=500 *1024 *1024 
app .config ['SECRET_KEY']=os .environ .get ('SECRET_KEY',os .urandom (24 ).hex ())
app .config ['JOBS_STORAGE']=REPO_ROOT /"jobs_data.pkl"
app .config ['REPORTS_PATH']=REPO_ROOT /"analysis_results"


csrf =CSRFProtect (app )


@app .errorhandler (CSRFError )
def handle_csrf_error (e ):
    return api_response (error =f"CSRF validation failed: {e .description }",status =400 )


os .makedirs (app .config ['UPLOAD_FOLDER'],exist_ok =True )


active_jobs :Dict [str ,Dict ]={}
active_jobs_lock =threading .Lock ()


def load_saved_jobs ():
    try :
        if app .config ['JOBS_STORAGE'].exists ():
            with open (app .config ['JOBS_STORAGE'],'rb')as f :
                return pickle .load (f )
    except Exception as e :
        log .error (f"Failed to load saved jobs: {e }")
    return {}


def save_jobs ():
    try :
        with active_jobs_lock :
            with open (app .config ['JOBS_STORAGE'],'wb')as f :
                pickle .dump (active_jobs ,f )
    except Exception as e :
        log .error (f"Failed to save jobs: {e }")


active_jobs =load_saved_jobs ()


def cleanup_old_jobs ():
    now =time .time ()
    to_remove =[]
    for job_id ,job in active_jobs .items ():
        if job .get ("created_at",now )<now -(7 *24 *60 *60 ):
            to_remove .append (job_id )

    for job_id in to_remove :
        del active_jobs [job_id ]

    if to_remove :
        save_jobs ()
        log .info (f"Cleaned up {len (to_remove )} old jobs")


def api_response (data :Any =None ,error :str =None ,status :int =200 )->tuple :
    response ={
    "success":error is None ,
    "timestamp":datetime .now ().isoformat ()
    }

    if data is not None :
        response ["data"]=data 

    if error :
        response ["error"]=error 

    return jsonify (response ),status 


def allowed_file (filename :str )->bool :
    return filename .lower ().endswith ('.apk')


def get_job_history (page :int =1 ,per_page :int =10 ,search :str =None ,status_filter :str =None ,type_filter :str =None )->Dict :

    sorted_jobs =sorted (
    active_jobs .values (),
    key =lambda j :j .get ("created_at",0 ),
    reverse =True 
    )


    if search :
        search =search .lower ()
        sorted_jobs =[
        j for j in sorted_jobs 
        if search in str (j .get ("filename","")).lower ()or 
        search in str (j .get ("id","")).lower ()
        ]


    if status_filter :
        sorted_jobs =[j for j in sorted_jobs if j .get ("status")==status_filter ]


    if type_filter :
        sorted_jobs =[j for j in sorted_jobs if j .get ("type")==type_filter ]


    total =len (sorted_jobs )
    total_pages =max (1 ,(total +per_page -1 )//per_page )
    page =max (1 ,min (page ,total_pages ))

    start =(page -1 )*per_page 
    end =start +per_page 

    return {
    "jobs":sorted_jobs [start :end ],
    "pagination":{
    "page":page ,
    "per_page":per_page ,
    "total":total ,
    "total_pages":total_pages 
    }
    }

@app .route ('/')
def index ():

    engines =[
    {"id":"auto","label":"Auto-detect","available":True }
    ]
    try :
        if callable (get_analyzers ):
            for a in get_analyzers ():
                eng_id =getattr (a ,'id',str (a ))
                label =getattr (a ,'name',eng_id )
                available =getattr (a ,'available',True )
                engines .append ({"id":eng_id ,"label":label ,"available":bool (available )})
    except Exception :
        pass 
    return render_template ('index.html',
    app_name =APP_NAME ,
    app_version =APP_VERSION ,
    author =APP_AUTHOR ,
    app_slogan =APP_SLOGAN ,
    app_tagline =APP_TAGLINE ,
    engines =engines )

@app .route ('/analyze',methods =['POST'])
@csrf .exempt 
def analyze ():

    file =None 
    if 'apk_file'in request .files :
        file =request .files ['apk_file']
    elif 'file'in request .files :
        file =request .files ['file']

    if not file :
        log .warning ("Analyze request missing file field (expected 'apk_file' or 'file')")
        return api_response (error ="No file provided (expected form field 'apk_file' or 'file')",status =400 )

    if not file .filename or not allowed_file (file .filename ):
        log .warning ("Analyze request received invalid or empty filename")
        return api_response (error ="Invalid APK file",status =400 )


    job_id =str (uuid .uuid4 ())


    secure_name =secure_filename (file .filename )
    upload_path =Path (app .config ['UPLOAD_FOLDER'])/f"{job_id }_{secure_name }"

    try :
        file .save (upload_path )
    except Exception as e :
        log .error (f"Failed to save uploaded file: {e }")
        return api_response (error =f"Failed to save file: {str (e )}",status =500 )


    analysis_depth =request .form .get ('analysis_depth','standard')
    enable_dynamic =request .form .get ('enable_dynamic')is not None 
    enable_static =request .form .get ('enable_static')is not None 
    enable_network =request .form .get ('enable_network')is not None 
    enable_malware =request .form .get ('enable_malware')is not None 


    job_info ={
    "id":job_id ,
    "filename":secure_name ,
    "filepath":str (upload_path ),
    "engine":request .form .get ('engine','auto'),
    "status":"running",
    "result":None ,
    "created_at":time .time (),
    "updated_at":time .time (),
    "progress":0 ,
    "current_task":"Queued",
    "type":"single",
    "log":[],
    "options":{
    "analysis_depth":analysis_depth ,
    "enable_dynamic":enable_dynamic ,
    "enable_static":enable_static ,
    "enable_network":enable_network ,
    "enable_malware":enable_malware ,
    },
    "cancel_requested":False 
    }
    with active_jobs_lock :
        active_jobs [job_id ]=job_info 
        save_jobs ()


    def run_analysis ():
        try :

            prev_job_env =os .environ .get ("APASS_JOB_ID")
            os .environ ["APASS_JOB_ID"]=job_id 


            def update_progress (percentage ,task_name ,details =None ):
                job_info ["progress"]=percentage 
                job_info ["current_task"]=task_name 
                job_info ["current_icon"]="fas fa-cogs"
                log_message =f"Progress: {percentage }% - {task_name }"
                if details :
                    log_message +=f" ({details })"

                job_info ["log"].append ({
                "time":time .time (),
                "message":log_message ,
                "level":"info",
                "progress":percentage 
                })
                job_info ["updated_at"]=time .time ()
                save_jobs ()


            update_progress (5 ,"Initializing analysis environment",f"Starting analysis of {secure_name }")


            time .sleep (0.5 )


            update_progress (10 ,"Validating APK file","Checking file structure and permissions")


            base_timeout =int (config .get ('analysis',{}).get ('timeout',300 ))
            depth_timeouts ={
            'quick':max (120 ,int (base_timeout *0.6 )),
            'standard':base_timeout ,
            'deep':max (600 ,int (base_timeout *2 )),
            }
            timeout =depth_timeouts .get (analysis_depth ,base_timeout )


            if job_info .get ("cancel_requested")or job_info .get ("status")=="cancelled":
                job_info ["current_task"]="Cancelled"
                job_info ["updated_at"]=time .time ()
                save_jobs ()
                return 


            os .environ ["APASS_PROGRESS_CALLBACK"]="web_progress"


            prev_flags ={
            "APASS_ENABLE_DYNAMIC":os .environ .get ("APASS_ENABLE_DYNAMIC"),
            "APASS_ENABLE_STATIC":os .environ .get ("APASS_ENABLE_STATIC"),
            "APASS_ENABLE_NETWORK":os .environ .get ("APASS_ENABLE_NETWORK"),
            "APASS_ENABLE_MALWARE":os .environ .get ("APASS_ENABLE_MALWARE"),
            }


            def monitor_progress ():
                progress_file =Path (f"/tmp/apass_progress_{job_id }.json")
                last_progress =10 
                backup_stages =[
                (20 ,"Preparing analysis environment"),
                (30 ,"Extracting APK contents"),
                (45 ,"Performing static analysis"),
                (65 ,"Running dynamic analysis"),
                (80 ,"Analyzing network traffic"),
                (90 ,"Scanning for malware"),
                (95 ,"Generating reports")
                ]
                stage_index =0 

                while (job_info .get ("status")=="running"and 
                not job_info .get ("cancel_requested")and 
                job_info .get ("progress",0 )<95 ):

                    try :

                        if progress_file .exists ():
                            try :
                                progress_data =json .loads (progress_file .read_text (encoding ="utf-8"))
                                real_progress =progress_data .get ("progress",last_progress )
                                real_task =progress_data .get ("task","Processing...")
                                real_details =progress_data .get ("details")

                                if real_progress >last_progress :
                                    update_progress (real_progress ,real_task ,real_details )
                                    last_progress =real_progress 


                                    while (stage_index <len (backup_stages )and 
                                    backup_stages [stage_index ][0 ]<=real_progress ):
                                        stage_index +=1 

                                time .sleep (1 )
                                continue 

                            except (json .JSONDecodeError ,FileNotFoundError ):
                                pass 


                        if stage_index <len (backup_stages ):
                            target_progress ,stage_name =backup_stages [stage_index ]
                            current_progress =job_info .get ("progress",10 )

                            if current_progress <target_progress :
                                new_progress =min (target_progress ,current_progress +2 )
                                update_progress (new_progress ,stage_name )
                                last_progress =new_progress 
                                time .sleep (3 )
                            else :
                                stage_index +=1 
                        else :
                            break 

                    except Exception as e :
                        log .warning (f"Progress monitor error: {e }")
                        time .sleep (5 )

            monitor_thread =threading .Thread (target =monitor_progress ,daemon =True )
            monitor_thread .start ()

            try :
                os .environ ["APASS_ENABLE_DYNAMIC"]="1"if enable_dynamic else "0"
                os .environ ["APASS_ENABLE_STATIC"]="1"if enable_static else "0"
                os .environ ["APASS_ENABLE_NETWORK"]="1"if enable_network else "0"
                os .environ ["APASS_ENABLE_MALWARE"]="1"if enable_malware else "0"

                update_progress (20 ,"Starting analyzer engine",f"Using {job_info ['engine']} analyzer")

                log .info (f"Starting analysis of {job_info ['filename']} with job ID {job_id }")

                if callable (do_analyze_details ):
                    rc ,outdir ,reports_dir =do_analyze_details (Path (job_info ["filepath"]),job_info ["engine"],timeout )
                    result =rc 
                    if rc ==0 :
                        if outdir :
                            job_info ["outdir"]=str (outdir )
                        if reports_dir and Path (reports_dir ).exists ():
                            job_info ["reports"]={p .name :str (p )for p in Path (reports_dir ).glob ("*")}
                else :
                    result =do_analyze (Path (job_info ["filepath"]),job_info ["engine"],timeout )
                    if result ==0 :
                        job_info ["reports"]=find_reports_for_job (job_id )

                log .info (f"Analysis completed with result code: {result }")
            except Exception as e :
                log .exception (f"Analysis execution failed: {e }")
                result =1 
            finally :

                for k ,v in prev_flags .items ():
                    if v is None :
                        os .environ .pop (k ,None )
                    else :
                        os .environ [k ]=v 
                os .environ .pop ("APASS_PROGRESS_CALLBACK",None )


            if job_info .get ("status")=="cancelled"or job_info .get ("cancel_requested"):
                job_info ["result"]=result 
                job_info ["progress"]=100 
                job_info ["current_task"]="Analysis cancelled"
                job_info ["current_icon"]="fas fa-ban"
                job_info ["status"]="cancelled"
                job_info ["log"].append ({
                "time":time .time (),
                "message":"Analysis cancelled by user request",
                "level":"warning",
                "progress":100 
                })
            else :
                job_info ["current_task"]="Finalizing results and generating reports"
                job_info ["current_icon"]="fas fa-file-contract"
                job_info ["status"]="completed"if result ==0 else "failed"
                job_info ["result"]=result 
                job_info ["progress"]=100 
                success_msg ="Analysis completed successfully!"if result ==0 else f"Analysis failed with exit code {result }"
                job_info ["log"].append ({
                "time":time .time (),
                "message":success_msg ,
                "level":"success"if result ==0 else "error",
                "progress":100 
                })
                job_info ["current_task"]="Analysis completed"if result ==0 else "Analysis failed"
                job_info ["current_icon"]="fas fa-check-circle"if result ==0 else "fas fa-exclamation-triangle"
        except Exception as e :
            job_info ["status"]="error"
            job_info ["error"]=str (e )
            job_info ["current_task"]="Analysis error occurred"
            job_info ["current_icon"]="fas fa-exclamation-triangle"
            job_info ["progress"]=100 
            job_info ["log"].append ({
            "time":time .time (),
            "message":f"Critical error during analysis: {str (e )}",
            "level":"error",
            "progress":100 
            })
            log .error (f"Analysis job {job_id } failed: {e }")
        finally :

            job_info ["status"]=job_info .get ("status","completed")


            try :
                if prev_job_env is not None :
                    os .environ ["APASS_JOB_ID"]=prev_job_env 
                else :
                    os .environ .pop ("APASS_JOB_ID",None )
            except Exception :
                pass 

            try :
                if upload_path .exists ():
                    upload_path .unlink ()
            except Exception :
                pass 
            job_info ["updated_at"]=time .time ()
            save_jobs ()

    threading .Thread (target =run_analysis ,daemon =True ).start ()
    return redirect (url_for ('job_status',job_id =job_id ))

@app .route ('/batch',methods =['POST'])
@csrf .exempt 
def batch ():

    files =request .files .getlist ('apk_files')
    if not files :
        files =request .files .getlist ('files')

    if not files :
        log .warning ("Batch request missing files list (expected 'apk_files' or 'files')")
        return api_response (error ="No files provided (expected form field 'apk_files' or 'files')",status =400 )


    job_id =str (uuid .uuid4 ())


    job_dir =Path (app .config ['UPLOAD_FOLDER'])/job_id 
    job_dir .mkdir (exist_ok =True )


    file_paths =[]
    file_names =[]
    for file in files :
        if file and file .filename and allowed_file (file .filename ):
            secure_name =secure_filename (file .filename )
            file_path =job_dir /secure_name 
            try :
                file .save (file_path )
                file_paths .append (file_path )
                file_names .append (secure_name )
            except Exception as e :
                log .error (f"Failed to save uploaded file {secure_name }: {e }")
        else :
            log .warning ("Batch request included an invalid or empty filename; skipping")

    if not file_paths :

        if job_dir .exists ():
            shutil .rmtree (job_dir )
        return api_response (error ="No valid APK files provided",status =400 )


    batch_mode =request .form .get ('batch_mode','parallel')
    continue_on_error =request .form .get ('continue_on_error')is not None 
    generate_summary =request .form .get ('generate_summary')is not None 
    email_notification =request .form .get ('email_notification')is not None 


    job_info ={
    "id":job_id ,
    "type":"batch",
    "file_count":len (file_paths ),
    "file_names":file_names ,
    "dir":str (job_dir ),
    "engine":request .form .get ('engine','auto'),
    "status":"running",
    "progress":0 ,
    "completed":0 ,
    "failed":0 ,
    "created_at":time .time (),
    "updated_at":time .time (),
    "results":{},
    "current_task":"Queued",
    "log":[{"time":time .time (),"message":f"Starting batch analysis of {len (file_paths )} files"}],
    "options":{
    "batch_mode":batch_mode ,
    "continue_on_error":continue_on_error ,
    "generate_summary":generate_summary ,
    "email_notification":email_notification ,
    },
    "cancel_requested":False 
    }
    with active_jobs_lock :
        active_jobs [job_id ]=job_info 
        save_jobs ()


    def run_batch_analysis ():
        try :
            prev_job_env =os .environ .get ("APASS_JOB_ID")
            os .environ ["APASS_JOB_ID"]=job_id 
            timeout =int (config .get ('analysis',{}).get ('timeout',300 ))
            for i ,file_path in enumerate (file_paths ):

                if job_info .get ("cancel_requested")or job_info .get ("status")=="cancelled":
                    job_info ["log"].append ({"time":time .time (),"message":"Batch cancelled by user"})
                    job_info ["current_task"]="Cancelled"
                    break 

                file_id =file_path .name 
                job_info ["log"].append ({"time":time .time (),"message":f"Processing {file_id } ({i +1 }/{len (file_paths )})"})
                job_info ["current_task"]=f"Analyzing {file_id } ({i +1 }/{len (file_paths )})"
                job_info ["progress"]=int ((i /len (file_paths ))*100 )
                job_info ["updated_at"]=time .time ()
                save_jobs ()

                try :
                    if callable (do_analyze_details ):
                        rc ,outdir ,reports_dir =do_analyze_details (file_path ,job_info ["engine"],timeout )
                        result =rc 
                        details ={}
                        if outdir :
                            details ["outdir"]=str (outdir )
                        if reports_dir and Path (reports_dir ).exists ():
                            details ["reports"]={p .name :str (p )for p in Path (reports_dir ).glob ("*")}
                    else :
                        result =do_analyze (file_path ,job_info ["engine"],timeout )
                        details ={}

                    job_info ["results"][file_id ]={
                    "status":"completed"if result ==0 else "failed",
                    "result":result ,
                    "completed_at":time .time (),
                    **details 
                    }
                    if result ==0 :
                        job_info ["completed"]+=1 
                    else :
                        job_info ["failed"]+=1 
                except Exception as e :
                    job_info ["results"][file_id ]={
                    "status":"error",
                    "error":str (e ),
                    "completed_at":time .time ()
                    }
                    job_info ["failed"]+=1 
                    job_info ["log"].append ({"time":time .time (),"message":f"Error processing {file_id }: {str (e )}"})

            if job_info .get ("status")!="cancelled":
                job_info ["status"]="completed"
                job_info ["progress"]=100 
                job_info ["current_task"]="Done"
                job_info ["log"].append ({
                "time":time .time (),
                "message":f"Batch analysis completed. Success: {job_info ['completed']}, Failed: {job_info ['failed']}"
                })
        except Exception as e :
            job_info ["status"]="error"
            job_info ["error"]=str (e )
            job_info ["current_task"]="Error"
            job_info ["log"].append ({"time":time .time (),"message":f"Batch process error: {str (e )}"})
            log .error (f"Batch job {job_id } failed: {e }")
        finally :
            try :
                if prev_job_env is not None :
                    os .environ ["APASS_JOB_ID"]=prev_job_env 
                else :
                    os .environ .pop ("APASS_JOB_ID",None )
            except Exception :
                pass 
            try :
                if job_dir .exists ():
                    shutil .rmtree (job_dir )
            except Exception :
                pass 
            job_info ["updated_at"]=time .time ()
            save_jobs ()

    threading .Thread (target =run_batch_analysis ,daemon =True ).start ()
    return redirect (url_for ('job_status',job_id =job_id ))

def find_reports_for_job (job_id :str )->Dict [str ,str ]:
    reports ={}


    for base_dir in app .config ['REPORTS_PATH'].glob ("*"):
        if not base_dir .is_dir ():
            continue 


        for reports_dir in base_dir .glob ("*"):
            if not reports_dir .is_dir ():
                continue 


            if job_id in reports_dir .name :
                report_files =reports_dir /"reports"
                if report_files .exists ()and report_files .is_dir ():
                    for report in report_files .glob ("*"):
                        reports [report .name ]=str (report )

    return reports 

@app .route ('/job/<job_id>')
def job_status (job_id ):
    if job_id not in active_jobs :
        return render_template ('error.html',message ="Job not found"),404 

    return render_template ('job.html',
    job =active_jobs [job_id ],
    app_name =APP_NAME ,
    app_version =APP_VERSION ,
    author =APP_AUTHOR ,
    app_slogan =APP_SLOGAN ,
    app_tagline =APP_TAGLINE )

@app .route ('/jobs')
def jobs_list ():
    page =request .args .get ('page',1 ,type =int )
    per_page =request .args .get ('per_page',10 ,type =int )
    search =request .args .get ('search',None ,type =str )
    status_filter =request .args .get ('filter',None ,type =str )
    type_filter =request .args .get ('type',None ,type =str )

    job_history =get_job_history (page ,per_page ,search ,status_filter ,type_filter )


    return render_template ('jobs.html',
    job_history =job_history ,
    jobs =job_history .get ('jobs',[]),
    search =search ,
    app_name =APP_NAME ,
    app_version =APP_VERSION ,
    author =APP_AUTHOR ,
    app_slogan =APP_SLOGAN ,
    app_tagline =APP_TAGLINE )

@app .route ('/api/job/<job_id>')
def api_job_status (job_id ):
    if job_id not in active_jobs :
        return api_response (error ="Job not found",status =404 )

    return api_response (data =active_jobs [job_id ])

@app .route ('/api/jobs')
def api_jobs_list ():
    page =request .args .get ('page',1 ,type =int )
    per_page =request .args .get ('per_page',10 ,type =int )
    search =request .args .get ('search',None ,type =str )

    job_history =get_job_history (page ,per_page ,search )

    return api_response (data =job_history )

@app .route ('/api/job/<job_id>/cancel',methods =['POST'])
@app .route ('/api/jobs/<job_id>/cancel',methods =['POST'])
@csrf .exempt 
def api_cancel_job (job_id ):
    if job_id not in active_jobs :
        return api_response (error ="Job not found",status =404 )

    job =active_jobs [job_id ]
    status =job .get ("status")

    if status in ("running","pending"):
        with active_jobs_lock :
            job ["cancel_requested"]=True 
            job ["status"]="cancelled"
            job ["current_task"]="Cancelling..."
            job ["log"].append ({"time":time .time (),"message":"Job cancellation requested by user"})
            job ["updated_at"]=time .time ()
            save_jobs ()
        return api_response (data ={"message":"Job cancellation requested","status":job ["status"]})

    if status =="cancelled":
        return api_response (data ={"message":"Job already cancelled","status":job ["status"]})

    return api_response (error =f"Cannot cancel job in '{status }' state",status =409 )

@app .route ('/api/job/<job_id>/delete',methods =['POST'])
@app .route ('/api/jobs/<job_id>',methods =['DELETE'])
@csrf .exempt 
def api_delete_job (job_id ):
    if job_id not in active_jobs :
        return api_response (error ="Job not found",status =404 )

    with active_jobs_lock :
        job =active_jobs .pop (job_id ,None )
        if job is None :
            return api_response (error ="Job not found",status =404 )

        try :
            if job .get ("type")=="batch"and job .get ("dir"):
                shutil .rmtree (job ["dir"],ignore_errors =True )
            elif job .get ("filepath"):
                Path (job ["filepath"]).unlink (missing_ok =True )
        except Exception :
            pass 
        save_jobs ()
    return api_response (data ={"message":"Job deleted"})

@app .route ('/status')
def status ():
    system_status =get_system_status ()
    return render_template ('status.html',
    status =system_status ,
    app_name =APP_NAME ,
    app_version =APP_VERSION ,
    author =APP_AUTHOR ,
    app_slogan =APP_SLOGAN ,
    app_tagline =APP_TAGLINE )

@app .route ('/api/status')
def api_status ():
    system_status =get_system_status ()
    return api_response (data =system_status )

@app .route ('/report/<job_id>/<path:report_file>')
def view_report (job_id ,report_file ):
    if job_id not in active_jobs :
        return render_template ('error.html',message ="Job not found"),404 

    job =active_jobs [job_id ]
    if "reports"not in job :

        job ["reports"]=find_reports_for_job (job_id )
        if not job ["reports"]:
            return render_template ('error.html',message ="No reports available for this job"),404 

    for report_name ,report_path in job ["reports"].items ():
        if report_name ==report_file :
            report_path =Path (report_path )
            download =request .args .get ('download')=='1'
            return send_from_directory (report_path .parent ,report_path .name ,as_attachment =download )

    return render_template ('error.html',message ="Report not found"),404 

@app .route ('/compare')
def compare_jobs ():
    job1_id =request .args .get ('job1')
    job2_id =request .args .get ('job2')

    if not job1_id or not job2_id :
        job_history =get_job_history (1 ,100 )
        return render_template ('compare_select.html',
        jobs =job_history ["jobs"],
        app_name =APP_NAME ,
        app_version =APP_VERSION ,
        author =APP_AUTHOR ,
        app_slogan =APP_SLOGAN ,
        app_tagline =APP_TAGLINE )

    if job1_id not in active_jobs or job2_id not in active_jobs :
        return render_template ('error.html',message ="One or both jobs not found"),404 

    job1 =active_jobs [job1_id ]
    job2 =active_jobs [job2_id ]

    return render_template ('compare.html',
    job1 =job1 ,
    job2 =job2 ,
    app_name =APP_NAME ,
    app_version =APP_VERSION ,
    author =APP_AUTHOR ,
    app_slogan =APP_SLOGAN ,
    app_tagline =APP_TAGLINE )

@app .route ('/favicon.ico')
def favicon ():
    return send_from_directory (REPO_ROOT /'static','APASS_ARIX.png',mimetype ='image/png')

@app .route ('/healthz')
def healthz ():
    try :
        return jsonify ({"status":"ok","app":APP_NAME ,"version":APP_VERSION }),200 
    except Exception :
        return jsonify ({"status":"error"}),500 

def get_system_status ()->Dict :
    try :

        status_data ={
        "app":{
        "name":APP_NAME ,
        "version":APP_VERSION ,
        "author":APP_AUTHOR 
        },
        "workspace":{
        "src":(REPO_ROOT /"src").exists (),
        "resources":(REPO_ROOT /"resources").exists (),
        "scripts":(REPO_ROOT /"scripts").exists (),
        "all_good":True ,
        "config_files":True 
        },
        "timestamp":datetime .now ().isoformat ()
        }


        disk_percent =0 
        try :
            cpu_percent =psutil .cpu_percent (interval =0.0 )if psutil else 0 
            memory_percent =psutil .virtual_memory ().percent if psutil else 0 
            uptime =int (time .time ()-psutil .boot_time ())if psutil else 0 


            try :
                workspace_path =REPO_ROOT 
                usage =shutil .disk_usage (workspace_path )
                disk_percent =(usage .used /usage .total )*100 
            except Exception :
                disk_percent =0 

            status_data ["system"]={
            "cpu_percent":cpu_percent ,
            "memory_percent":memory_percent ,
            "disk_percent":disk_percent ,
            "uptime":uptime ,
            "healthy":cpu_percent <90 and memory_percent <90 and disk_percent <90 
            }
        except Exception :
            status_data ["system"]={
            "cpu_percent":0 ,
            "memory_percent":0 ,
            "disk_percent":0 ,
            "uptime":0 ,
            "healthy":True 
            }


        try :
            workspace_path =REPO_ROOT 
            usage =shutil .disk_usage (workspace_path )
            total_gb =usage .total /(1024 **3 )
            used_gb =usage .used /(1024 **3 )
            free_gb =usage .free /(1024 **3 )
            percent =(usage .used /usage .total )*100 

            status_data ["workspace"]["disk_space"]={
            "total":f"{total_gb :.1f} GB",
            "used":f"{used_gb :.1f} GB",
            "free":f"{free_gb :.1f} GB",
            "percent":round (percent ,1 )
            }
        except Exception as e :
            log .error (f"Failed to get disk usage: {e }")
            status_data ["workspace"]["disk_space"]={
            "total":"0 GB",
            "used":"0 GB",
            "free":"0 GB",
            "percent":0 
            }


        status_data ["jobs"]={
        "total":len (active_jobs ),
        "running":sum (1 for j in active_jobs .values ()if j .get ("status")=="running"),
        "completed":sum (1 for j in active_jobs .values ()if j .get ("status")=="completed"),
        "failed":sum (1 for j in active_jobs .values ()if j .get ("status")in ["failed","error"]),
        }


        try :
            import platform as _platform 
            status_data ["python_version"]=sys .version .split (" ")[0 ]
            status_data ["platform"]=_platform .platform ()
        except Exception :
            pass 
        status_data ["overall_health"]="healthy"if status_data .get ("system",{}).get ("healthy")else "warning"
        status_data ["running_jobs"]=status_data ["jobs"]["running"]
        status_data ["completed_today"]=sum (
        1 for j in active_jobs .values ()
        if (time .time ()-j .get ("created_at",0 ))<24 *3600 and j .get ("status")=="completed"
        )
        status_data ["uptime"]=status_data .get ("system",{}).get ("uptime")


        tool_statuses ={
        "static_analyzer":{"available":True ,"version":"1.0"},
        "dynamic_analyzer":{"available":True ,"version":"1.0"},
        "emulator":{"available":True ,"version":"1.0"},
        "frida":{"available":True ,"version":"1.0"},
        "yara":{"available":True ,"version":"1.0"}
        }

        all_ready =all (tool .get ("available",False )for tool in tool_statuses .values ())
        status_data ["tools"]=tool_statuses 
        status_data ["tools"]["all_ready"]=all_ready 


        try :
            from analyzers .environment_checks import get_system_info ,check_xposed_lsposed ,check_magisk_zygisk 
            from analyzers .environment_checks import check_objection ,check_inspeckage ,check_radare2_rizin_r2frida 
            from analyzers .environment_checks import check_jadx ,check_mobsf ,check_appium ,check_apktool ,check_house 


            for tool_func in [check_xposed_lsposed ,check_magisk_zygisk ,check_objection ,check_inspeckage ,
            check_radare2_rizin_r2frida ,check_jadx ,check_mobsf ,check_appium ,check_apktool ,check_house ]:
                try :
                    result =tool_func ()
                    tool_name =result .name .lower ().replace (" ","_")
                    status_data ["tools"][tool_name ]={
                    "available":result .available ,
                    "success":result .success ,
                    "version":result .version ,
                    "data":result .data 
                    }
                except Exception as e :
                    log .warning (f"Failed to check tool status for {getattr (tool_func ,'__name__','unknown')}: {e }")
        except Exception as e :
            log .warning (f"Failed to import environment_checks module: {e }")


        status_data ["devices"]={
        "connected":0 ,
        "authorized":0 ,
        "emulators":0 ,
        "physical":0 ,
        "list":[],
        "details":[]
        }


        status_data ["queue"]={
        "healthy":True ,
        "processing":sum (1 for j in active_jobs .values ()if j .get ("status")=="running"),
        "pending":sum (1 for j in active_jobs .values ()if j .get ("status")=="pending"),
        "completed":sum (1 for j in active_jobs .values ()if j .get ("status")=="completed"),
        "failed":sum (1 for j in active_jobs .values ()if j .get ("status")in ["failed","error"]),
        "last_job_time":int (max ((j .get ("updated_at",0 )for j in active_jobs .values ()),default =0 ))
        }


        try :
            results_dir =REPO_ROOT /"analysis_results"
            if results_dir .exists ():
                latest_dir =None 
                latest_time =0 
                for item in results_dir .rglob ("*"):
                    if item .is_dir ()and item .stat ().st_mtime >latest_time :
                        latest_time =item .stat ().st_mtime 
                        latest_dir =item 

                if latest_dir :
                    status_data ["latest_output"]=str (latest_dir .relative_to (REPO_ROOT ))
                else :
                    status_data ["latest_output"]=None 
            else :
                status_data ["latest_output"]=None 
        except Exception as e :
            log .error (f"Failed to find latest output: {e }")
            status_data ["latest_output"]=None 

        return status_data 

    except Exception as e :
        log .error (f"Failed to get system status: {e }")
        return {
        "error":str (e ),
        "app":{"name":APP_NAME ,"version":APP_VERSION ,"author":APP_AUTHOR },
        "timestamp":datetime .now ().isoformat (),
        "tools":{"all_ready":False },
        "system":{"healthy":False },
        "workspace":{"all_good":False },
        "devices":{},
        "overall_health":"critical"
        }

@app .before_request 
def before_request ():

    if random .random ()<0.01 :
        cleanup_old_jobs ()

@app .route ('/api/test-connectivity',methods =['POST'])
@csrf .exempt 
def api_test_connectivity ():
    try :
        checks ={
        "src":(REPO_ROOT /'src').exists (),
        "resources":(REPO_ROOT /'resources').exists (),
        "psutil":bool (psutil ),
        }
        if not all (checks .values ()):
            missing =[k for k ,v in checks .items ()if not v ]
            return api_response (error =f"Missing components: {', '.join (missing )}",status =503 )
        return api_response (data ={"message":"Connectivity OK"})
    except Exception as e :
        return api_response (error =str (e ),status =500 )

@app .route ('/api/cleanup',methods =['POST'])
@csrf .exempt 
def api_cleanup ():
    try :
        base =Path (app .config ['UPLOAD_FOLDER'])
        if base .exists ():
            now =time .time ()
            for p in base .glob ('*'):
                try :
                    if p .is_dir ()and (now -p .stat ().st_mtime )>24 *3600 :
                        shutil .rmtree (p ,ignore_errors =True )
                    elif p .is_file ()and (now -p .stat ().st_mtime )>24 *3600 :
                        p .unlink (missing_ok =True )
                except Exception :
                    continue 
        cleanup_old_jobs ()
        return api_response (data ={"message":"Cleanup completed"})
    except Exception as e :
        return api_response (error =str (e ),status =500 )

@app .route ('/api/diagnostics',methods =['GET'])
def api_diagnostics ():
    try :
        report =get_system_status ()
        report ["jobs_snapshot"]=list (active_jobs .values ())[:50 ]
        payload =json .dumps (report ,indent =2 ).encode ('utf-8')
        fname =f"apass-aryx-diagnostics-{datetime .now ().strftime ('%Y%m%d-%H%M%S')}.json"
        from flask import Response 
        return Response (payload ,mimetype ='application/json',headers ={
        'Content-Disposition':f'attachment; filename="{fname }"'
        })
    except Exception as e :
        return api_response (error =str (e ),status =500 )

@app .route ('/api/clear-logs',methods =['POST'])
@csrf .exempt 
def api_clear_logs ():
    try :
        log_file =(REPO_ROOT /'apass-aryx.log')
        if log_file .exists ():
            log_file .write_text ('',encoding ='utf-8')
        return api_response (data ={"message":"Logs cleared"})
    except Exception as e :
        return api_response (error =str (e ),status =500 )

@app .template_filter ('format_datetime')
def format_datetime (timestamp ):
    if not timestamp :
        return "N/A"
    try :
        if isinstance (timestamp ,(int ,float )):
            return datetime .fromtimestamp (timestamp ).strftime ('%Y-%m-%d %H:%M:%S')
        elif isinstance (timestamp ,str ):
            return timestamp 
        else :
            return str (timestamp )
    except (ValueError ,OSError ):
        return "Invalid date"

@app .template_filter ('format_duration')
def format_duration (start_time ,end_time =None ):
    if not start_time :
        return "N/A"

    try :
        if isinstance (start_time ,str ):
            return "N/A"

        if not end_time :
            end_time =time .time ()
        elif isinstance (end_time ,str ):
            return "N/A"

        duration_seconds =float (end_time )-float (start_time )


        hours ,remainder =divmod (int (duration_seconds ),3600 )
        minutes ,seconds =divmod (remainder ,60 )

        if hours >0 :
            return f"{hours }h {minutes }m {seconds }s"
        elif minutes >0 :
            return f"{minutes }m {seconds }s"
        else :
            return f"{seconds }s"
    except (ValueError ,TypeError ):
        return "N/A"


@app .context_processor 
def inject_csrf_token ():
    try :
        return dict (csrf_token =lambda :generate_csrf ())
    except Exception as e :
        log .warning (f"CSRF token generation failed: {e }")

        return dict (csrf_token =lambda :"")


if __name__ =='__main__':

    parser =argparse .ArgumentParser (description ='APASS ARYX Web Interface')
    parser .add_argument ('--port',type =int ,help ='Port to run the web server on')
    parser .add_argument ('--host',type =str ,help ='Host to run the web server on')
    parser .add_argument ('--debug',action ='store_true',help ='Run in debug mode')
    args =parser .parse_args ()


    web_config =config .get ('web',{})
    app .run (
    debug =args .debug if args .debug is not None else web_config .get ('debug',False ),
    host =args .host or web_config .get ('host','0.0.0.0'),
    port =args .port or web_config .get ('port',5000 )
    )
