#!/usr/bin/env python3

import json 
import csv 
import html 
from pathlib import Path 
from datetime import datetime 
from typing import Dict ,List ,Optional ,Any ,Union 
from dataclasses import dataclass ,asdict 
import base64 

try :
    from jinja2 import Template ,Environment ,FileSystemLoader 
    JINJA2_AVAILABLE =True 
except ImportError :
    JINJA2_AVAILABLE =False 

try :
    from .logger import get_logger 
except ImportError :

    import logging 
    def get_logger ():
        return logging .getLogger (__name__ )


@dataclass 
class ReportMetadata :
    analysis_id :str 
    timestamp :str 
    analyzer_version :str 
    target_file :str 
    analysis_duration :float 
    analysis_type :str 


class ReportGenerator :

    def __init__ (self ,output_dir :Optional [Path ]=None ,template_dir :Optional [Path ]=None ,logger =None ):

        self .logger =logger or get_logger ()
        self .output_dir =output_dir or Path .cwd ()/"reports"
        self .template_dir =template_dir 
        self .output_dir .mkdir (parents =True ,exist_ok =True )


        self .jinja_env =None 
        if JINJA2_AVAILABLE and template_dir and template_dir .exists ():
            self .jinja_env =Environment (loader =FileSystemLoader (str (template_dir )))

    def generate_json_report (self ,data :Dict [str ,Any ],filename :str ="analysis_report.json")->Path :
        self .logger .info (f"Generating JSON report: {filename }")

        try :
            output_path =self .output_dir /filename 


            report_data ={
            "metadata":{
            "generated_at":datetime .now ().isoformat (),
            "generator":"APASS ARYX Report Generator",
            "format":"json",
            "version":"1.0"
            },
            "data":data 
            }

            with open (output_path ,'w',encoding ='utf-8')as f :
                json .dump (report_data ,f ,indent =2 ,ensure_ascii =False ,default =str )

            self .logger .success (f"JSON report generated: {output_path }")
            return output_path 

        except Exception as e :
            self .logger .error (f"Error generating JSON report: {e }")
            raise 

    def generate_html_report (self ,data :Dict [str ,Any ],filename :str ="analysis_report.html",
    template_name :Optional [str ]=None )->Path :
        self .logger .info (f"Generating HTML report: {filename }")

        try :
            output_path =self .output_dir /filename 

            if self .jinja_env and template_name :

                template =self .jinja_env .get_template (template_name )
                html_content =template .render (data =data ,metadata ={
                "generated_at":datetime .now ().strftime ("%Y-%m-%d %H:%M:%S"),
                "generator":"APASS ARYX"
                })
            else :

                html_content =self ._generate_basic_html (data )

            with open (output_path ,'w',encoding ='utf-8')as f :
                f .write (html_content )

            self .logger .success (f"HTML report generated: {output_path }")
            return output_path 

        except Exception as e :
            self .logger .error (f"Error generating HTML report: {e }")
            raise 

    def generate_csv_report (self ,data :Dict [str ,Any ],filename :str ="analysis_report.csv")->Path :
        self .logger .info (f"Generating CSV report: {filename }")

        try :
            output_path =self .output_dir /filename 


            flattened_data =self ._flatten_dict (data )

            with open (output_path ,'w',newline ='',encoding ='utf-8')as f :
                if flattened_data :
                    writer =csv .DictWriter (f ,fieldnames =flattened_data [0 ].keys ())
                    writer .writeheader ()
                    writer .writerows (flattened_data )
                else :

                    writer =csv .writer (f )
                    writer .writerow (['Key','Value'])
                    for key ,value in data .items ():
                        writer .writerow ([key ,str (value )])

            self .logger .success (f"CSV report generated: {output_path }")
            return output_path 

        except Exception as e :
            self .logger .error (f"Error generating CSV report: {e }")
            raise 

    def generate_markdown_report (self ,data :Dict [str ,Any ],filename :str ="analysis_report.md")->Path :
        self .logger .info (f"Generating Markdown report: {filename }")

        try :
            output_path =self .output_dir /filename 

            markdown_content =self ._generate_markdown (data )

            with open (output_path ,'w',encoding ='utf-8')as f :
                f .write (markdown_content )

            self .logger .success (f"Markdown report generated: {output_path }")
            return output_path 

        except Exception as e :
            self .logger .error (f"Error generating Markdown report: {e }")
            raise 

    def generate_executive_summary (self ,data :Dict [str ,Any ],filename :str ="executive_summary.txt")->Path :
        self .logger .info (f"Generating executive summary: {filename }")

        try :
            output_path =self .output_dir /filename 

            summary_content =self ._generate_executive_summary (data )

            with open (output_path ,'w',encoding ='utf-8')as f :
                f .write (summary_content )

            self .logger .success (f"Executive summary generated: {output_path }")
            return output_path 

        except Exception as e :
            self .logger .error (f"Error generating executive summary: {e }")
            raise 

    def generate_comprehensive_report (self ,data :Dict [str ,Any ],base_filename :str ="analysis_report")->Dict [str ,Path ]:
        self .logger .info ("Generating comprehensive reports...")

        reports ={}
        timestamp =datetime .now ().strftime ("%Y%m%d_%H%M%S")

        try :

            json_filename =f"{base_filename }_{timestamp }.json"
            reports ['json']=self .generate_json_report (data ,json_filename )


            html_filename =f"{base_filename }_{timestamp }.html"
            reports ['html']=self .generate_html_report (data ,html_filename )


            md_filename =f"{base_filename }_{timestamp }.md"
            reports ['markdown']=self .generate_markdown_report (data ,md_filename )


            summary_filename =f"executive_summary_{timestamp }.txt"
            reports ['summary']=self .generate_executive_summary (data ,summary_filename )


            if self ._has_tabular_data (data ):
                csv_filename =f"{base_filename }_{timestamp }.csv"
                reports ['csv']=self .generate_csv_report (data ,csv_filename )

            self .logger .success (f"Generated {len (reports )} report formats")
            return reports 

        except Exception as e :
            self .logger .error (f"Error generating comprehensive reports: {e }")
            raise 

    def _generate_basic_html (self ,data :Dict [str ,Any ])->str :
        html ="""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APASS ARYX Analysis Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        h3 { color: #7f8c8d; }
        .metadata { background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; }
        .highlight { background: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 10px 0; }
        .success { background: #d4edda; border-left-color: #28a745; }
        .danger { background: #f8d7da; border-left-color: #dc3545; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .code { background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; overflow-x: auto; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8em; color: white; }
        .badge-success { background-color: #28a745; }
        .badge-warning { background-color: #ffc107; color: #212529; }
        .badge-danger { background-color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 APASS ARYX Analysis Report</h1>
        <div class="metadata">
            <strong>Generated:</strong> {timestamp}<br>
            <strong>Generator:</strong> APASS ARYX Malware Analysis Suite
        </div>
        {content}
    </div>
</body>
</html>
        """.strip ()

        content =self ._dict_to_html (data )
        return html .format (
        timestamp =datetime .now ().strftime ("%Y-%m-%d %H:%M:%S"),
        content =content 
        )

    def _dict_to_html (self ,data :Dict [str ,Any ],level :int =2 )->str :
        html_parts =[]

        for key ,value in data .items ():
            if isinstance (value ,dict ):
                html_parts .append (f"<h{level }>{self ._format_key (key )}</h{level }>")
                html_parts .append (f"<div class='section'>{self ._dict_to_html (value ,level +1 )}</div>")
            elif isinstance (value ,list ):
                html_parts .append (f"<h{level }>{self ._format_key (key )}</h{level }>")
                html_parts .append (self ._list_to_html (value ))
            else :
                html_parts .append (f"<p><strong>{self ._format_key (key )}:</strong> {html .escape (str (value ))}</p>")

        return "\n".join (html_parts )

    def _list_to_html (self ,data :List [Any ])->str :
        if not data :
            return "<p><em>No items</em></p>"

        if isinstance (data [0 ],dict ):

            if not data :
                return "<p><em>No data</em></p>"

            headers =list (data [0 ].keys ())
            html ="<table><thead><tr>"
            for header in headers :
                html +=f"<th>{self ._format_key (header )}</th>"
            html +="</tr></thead><tbody>"

            for item in data :
                html +="<tr>"
                for header in headers :
                    value =item .get (header ,"")
                    html +=f"<td>{html .escape (str (value ))}</td>"
                html +="</tr>"

            html +="</tbody></table>"
            return html 
        else :

            html ="<ul>"
            for item in data :
                html +=f"<li>{html .escape (str (item ))}</li>"
            html +="</ul>"
            return html 

    def _generate_markdown (self ,data :Dict [str ,Any ])->str :
        lines =[
        "# 🔍 APASS ARYX Analysis Report",
        "",
        f"**Generated:** {datetime .now ().strftime ('%Y-%m-%d %H:%M:%S')}",
        f"**Generator:** APASS ARYX Malware Analysis Suite",
        "",
        "---",
        ""
        ]

        lines .extend (self ._dict_to_markdown (data ))
        return "\n".join (lines )

    def _dict_to_markdown (self ,data :Dict [str ,Any ],level :int =2 )->List [str ]:
        lines =[]

        for key ,value in data .items ():
            if isinstance (value ,dict ):
                lines .append (f"{'#'*level } {self ._format_key (key )}")
                lines .append ("")
                lines .extend (self ._dict_to_markdown (value ,level +1 ))
                lines .append ("")
            elif isinstance (value ,list ):
                lines .append (f"{'#'*level } {self ._format_key (key )}")
                lines .append ("")
                lines .extend (self ._list_to_markdown (value ))
                lines .append ("")
            else :
                lines .append (f"**{self ._format_key (key )}:** {value }")
                lines .append ("")

        return lines 

    def _list_to_markdown (self ,data :List [Any ])->List [str ]:
        lines =[]

        if not data :
            lines .append ("*No items*")
            return lines 

        if isinstance (data [0 ],dict ):

            if data :
                headers =list (data [0 ].keys ())


                header_line ="| "+" | ".join (self ._format_key (h )for h in headers )+" |"
                separator_line ="|"+"|".join ("---"for _ in headers )+"|"

                lines .append (header_line )
                lines .append (separator_line )


                for item in data :
                    row_data =[str (item .get (h ,""))for h in headers ]
                    row_line ="| "+" | ".join (row_data )+" |"
                    lines .append (row_line )
        else :

            for item in data :
                lines .append (f"- {item }")

        return lines 

    def _generate_executive_summary (self ,data :Dict [str ,Any ])->str :
        lines =[
        "APASS ARYX - EXECUTIVE SUMMARY",
        "="*50 ,
        "",
        f"Generated: {datetime .now ().strftime ('%Y-%m-%d %H:%M:%S')}",
        "",
        ]


        if "static_analysis"in data :
            static =data ["static_analysis"]
            lines .append ("STATIC ANALYSIS SUMMARY:")
            lines .append ("-"*25 )

            if "permissions"in static :
                lines .append (f"• Permissions found: {len (static ['permissions'])}")

            if "activities"in static :
                lines .append (f"• Activities found: {len (static ['activities'])}")

            if "services"in static :
                lines .append (f"• Services found: {len (static ['services'])}")

            lines .append ("")

        if "security_analysis"in data :
            security =data ["security_analysis"]
            lines .append ("SECURITY ANALYSIS:")
            lines .append ("-"*18 )

            if "risk_score"in security :
                risk_score =security ["risk_score"]
                risk_level ="LOW"if risk_score <30 else "MEDIUM"if risk_score <70 else "HIGH"
                lines .append (f"• Risk Score: {risk_score }/100 ({risk_level })")

            if "suspicious_permissions"in security :
                lines .append (f"• Suspicious Permissions: {len (security ['suspicious_permissions'])}")

            lines .append ("")

        if "network_analysis"in data :
            network =data ["network_analysis"]
            lines .append ("NETWORK ANALYSIS:")
            lines .append ("-"*16 )

            if "domains"in network :
                lines .append (f"• Domains found: {len (network ['domains'])}")

            if "ip_addresses"in network :
                lines .append (f"• IP Addresses: {len (network ['ip_addresses'])}")

            lines .append ("")


        lines .extend ([
        "RECOMMENDATIONS:",
        "-"*15 ,
        "• Review all identified permissions and network connections",
        "• Validate application behavior through dynamic analysis",
        "• Cross-reference findings with threat intelligence",
        "• Consider additional manual investigation if risk score is high",
        "",
        "This is an automated analysis. Manual review is recommended for critical applications."
        ])

        return "\n".join (lines )

    def _flatten_dict (self ,data :Dict [str ,Any ],parent_key :str ="",sep :str =".")->List [Dict [str ,Any ]]:
        items =[]

        for k ,v in data .items ():
            new_key =f"{parent_key }{sep }{k }"if parent_key else k 

            if isinstance (v ,dict ):
                items .extend (self ._flatten_dict (v ,new_key ,sep =sep ))
            elif isinstance (v ,list )and v and isinstance (v [0 ],dict ):

                for i ,item in enumerate (v ):
                    if isinstance (item ,dict ):
                        flattened_item =self ._flatten_dict (item ,f"{new_key }[{i }]",sep =sep )
                        items .extend (flattened_item )
            else :
                items .append ({new_key :v })

        return items if items else [data ]

    def _has_tabular_data (self ,data :Dict [str ,Any ])->bool :
        for value in data .values ():
            if isinstance (value ,list )and value and isinstance (value [0 ],dict ):
                return True 
        return False 

    def _format_key (self ,key :str )->str :
        return key .replace ("_"," ").title ()

    def get_output_directory (self )->Path :
        return self .output_dir 

    def set_output_directory (self ,path :Union [str ,Path ])->None :
        self .output_dir =Path (path )
        self .output_dir .mkdir (parents =True ,exist_ok =True )
