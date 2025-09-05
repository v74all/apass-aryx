#!/usr/bin/env python3

import os 
import time 
import json 
import logging 
from typing import Optional ,Callable ,Dict ,Any 
from pathlib import Path 


class ProgressTracker :

    def __init__ (self ,job_id :Optional [str ]=None ):
        self .job_id =job_id or os .environ .get ("APASS_JOB_ID")
        self .callback_type =os .environ .get ("APASS_PROGRESS_CALLBACK")
        self .current_progress =0 
        self .current_task ="Initializing"
        self .start_time =time .time ()
        self .logger =logging .getLogger ("apass-aryx.progress")


        if self .job_id :
            self .progress_file =Path (f"/tmp/apass_progress_{self .job_id }.json")
        else :
            self .progress_file =None 

    def update (self ,percentage :int ,task :str ,details :Optional [str ]=None ):
        self .current_progress =min (100 ,max (0 ,percentage ))
        self .current_task =task 


        log_msg =f"Progress: {self .current_progress }% - {task }"
        if details :
            log_msg +=f" ({details })"
        self .logger .info (log_msg )


        if self .progress_file :
            try :
                progress_data ={
                "progress":self .current_progress ,
                "task":task ,
                "details":details ,
                "timestamp":time .time (),
                "job_id":self .job_id 
                }
                self .progress_file .write_text (json .dumps (progress_data ),encoding ="utf-8")
            except Exception as e :
                self .logger .warning (f"Failed to write progress file: {e }")

    def step (self ,task :str ,details :Optional [str ]=None ):
        increment =5 
        new_progress =min (95 ,self .current_progress +increment )
        self .update (new_progress ,task ,details )

    def set_stage (self ,stage_name :str ,percentage :int ,details :Optional [str ]=None ):
        self .update (percentage ,stage_name ,details )

    def complete (self ,task :str ="Analysis completed"):
        self .update (100 ,task )


        if self .progress_file and self .progress_file .exists ():
            try :
                self .progress_file .unlink ()
            except Exception :
                pass 

    def error (self ,task :str ="Analysis failed"):
        self .update (100 ,task )


        if self .progress_file and self .progress_file .exists ():
            try :
                self .progress_file .unlink ()
            except Exception :
                pass 



_global_tracker :Optional [ProgressTracker ]=None 


def get_progress_tracker ()->ProgressTracker :
    global _global_tracker 
    if _global_tracker is None :
        _global_tracker =ProgressTracker ()
    return _global_tracker 


def update_progress (percentage :int ,task :str ,details :Optional [str ]=None ):
    tracker =get_progress_tracker ()
    tracker .update (percentage ,task ,details )


def step_progress (task :str ,details :Optional [str ]=None ):
    tracker =get_progress_tracker ()
    tracker .step (task ,details )


def set_progress_stage (stage_name :str ,percentage :int ,details :Optional [str ]=None ):
    tracker =get_progress_tracker ()
    tracker .set_stage (stage_name ,percentage ,details )


def complete_progress (task :str ="Analysis completed"):
    tracker =get_progress_tracker ()
    tracker .complete (task )


def error_progress (task :str ="Analysis failed"):
    tracker =get_progress_tracker ()
    tracker .error (task )
