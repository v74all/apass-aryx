#!/usr/bin/env python3

import json 
from pathlib import Path 
from datetime import datetime 
from typing import Dict ,List ,Any 
import html as _html 
import shutil 
import os 

class AnalysisDashboard :
    def __init__ (self ,workspace_root :str ="."):
        self .workspace_root =Path (workspace_root )
        self .analysis_results =self .workspace_root /"analysis_results"
        self .timestamp =datetime .now ().strftime ("%Y%m%d_%H%M%S")

    def _esc (self ,s :Any )->str :
        try :
            return _html .escape (str (s ))
        except Exception :
            return ""

    def load_analysis_data (self )->Dict [str ,Any ]:
        data ={
        "metadata":{
        "generated":datetime .now ().isoformat (),
        "workspace":str (self .workspace_root .absolute ()),
        "timestamp":self .timestamp 
        },
        "static_analysis":[],
        "dynamic_analysis":[],
        "network_analysis":[],
        "sessions":[],
        "artifacts":[],
        "threat_summary":{}
        }


        json_reports =self .analysis_results /"reports"/"json"
        if json_reports .exists ():
            for json_file in json_reports .glob ("*.json"):
                try :
                    with open (json_file ,'r',encoding ='utf-8')as f :
                        report_data =json .load (f )
                        name =json_file .name .lower ()
                        if "static"in name :
                            data ["static_analysis"].append ({
                            "file":json_file .name ,
                            "data":report_data 
                            })
                        elif "network"in name :
                            data ["network_analysis"].append ({
                            "file":json_file .name ,
                            "data":report_data 
                            })
                        elif "dynamic"in name or "runtime"in name :
                            data ["dynamic_analysis"].append ({
                            "file":json_file .name ,
                            "data":report_data 
                            })
                        elif "comprehensive"in name or "session"in name :
                            data ["sessions"].append ({
                            "file":json_file .name ,
                            "data":report_data 
                            })
                        else :

                            if isinstance (report_data ,dict )and "manifest_analysis"in report_data :
                                data ["static_analysis"].append ({"file":json_file .name ,"data":report_data })
                            elif isinstance (report_data ,dict )and "network"in report_data :
                                data ["network_analysis"].append ({"file":json_file .name ,"data":report_data })
                            else :
                                data ["sessions"].append ({"file":json_file .name ,"data":report_data })
                except Exception as e :
                    print (f"Error loading {json_file }: {e }")


        artifacts_dir =self .analysis_results /"artifacts"
        if artifacts_dir .exists ():
            for artifact in artifacts_dir .rglob ("*"):
                if artifact .is_file ():
                    data ["artifacts"].append ({
                    "name":artifact .name ,
                    "path":str (artifact .relative_to (self .workspace_root )),
                    "size":artifact .stat ().st_size ,
                    "modified":datetime .fromtimestamp (artifact .stat ().st_mtime ).isoformat ()
                    })


        data ["threat_summary"]=self ._generate_threat_summary (data )

        return data 

    def _generate_threat_summary (self ,data :Dict [str ,Any ])->Dict [str ,Any ]:
        summary ={
        "total_analyses":len (data ["static_analysis"])+len (data ["sessions"]),
        "threat_level":"LOW",
        "key_findings":[],
        "permissions":[],
        "network_indicators":[],
        "malware_score":0 
        }


        for static in data ["static_analysis"]:
            report =static ["data"]
            if "security_analysis"in report :
                security =report ["security_analysis"]
                if "permissions"in security :
                    summary ["permissions"].extend (security ["permissions"])
                if "dangerous_permissions"in security :
                    if len (security ["dangerous_permissions"])>3 :
                        summary ["threat_level"]="MEDIUM"
                        summary ["key_findings"].append (f"Multiple dangerous permissions: {len (security ['dangerous_permissions'])}")

            if "threat_score"in report and report ["threat_score"]>0 :
                summary ["malware_score"]=max (summary ["malware_score"],report ["threat_score"])
                if report ["threat_score"]>5 :
                    summary ["threat_level"]="HIGH"


        for session in data ["sessions"]:
            session_data =session ["data"]
            if "static"in session_data and "domains"in session_data ["static"]:
                summary ["network_indicators"].extend (session_data ["static"]["domains"])


        net_unique =len (set (summary ["network_indicators"]))
        if net_unique >10 and summary ["threat_level"]=="LOW":
            summary ["threat_level"]="MEDIUM"
        if net_unique >30 :
            summary ["threat_level"]="HIGH"

        return summary 

    def generate_html_dashboard (self )->str :
        data =self .load_analysis_data ()

        html_template =f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Analysis Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: #fff;
            min-height: 100vh;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ 
            text-align: center; 
            margin-bottom: 30px;
            padding: 20px;
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }}
        .header h1 {{ 
            font-size: 2.5rem; 
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        .subtitle {{ 
            font-size: 1.1rem; 
            opacity: 0.9;
        }}
        .dashboard-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px;
        }}
        .card {{ 
            background: rgba(255,255,255,0.1); 
            border-radius: 15px; 
            padding: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.3s ease;
        }}
        .card:hover {{ transform: translateY(-5px); }}
        .card h3 {{ 
            margin-bottom: 15px; 
            color: #4fc3f7;
            font-size: 1.3rem;
        }}
        .metric {{ 
            display: flex; 
            justify-content: space-between; 
            margin-bottom: 10px;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        .metric:last-child {{ border-bottom: none; }}
        .threat-level {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .threat-low {{ background: #4caf50; }}
        .threat-medium {{ background: #ff9800; }}
        .threat-high {{ background: #f44336; }}
        .list-item {{ 
            padding: 8px 0; 
            border-bottom: 1px solid rgba(255,255,255,0.1);
            font-size: 0.9rem;
        }}
        .list-item:last-child {{ border-bottom: none; }}
        .artifact-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 10px;
            margin-top: 15px;
        }}
        .artifact-item {{
            background: rgba(255,255,255,0.05);
            padding: 10px;
            border-radius: 8px;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        .timestamp {{ 
            font-size: 0.8rem; 
            opacity: 0.7; 
            margin-top: 20px;
            text-align: center;
        }}
        .progress-bar {{
            background: rgba(255,255,255,0.2);
            border-radius: 10px;
            height: 20px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #4caf50, #2196f3);
            transition: width 0.3s ease;
        }}
        .json-preview {{
            background: rgba(0,0,0,0.3);
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            max-height: 300px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        .tab-container {{
            margin: 20px 0;
        }}
        .tab-buttons {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }}
        .tab-button {{
            padding: 10px 20px;
            background: rgba(255,255,255,0.1);
            border: none;
            border-radius: 8px;
            color: white;
            cursor: pointer;
            transition: background 0.3s ease;
        }}
        .tab-button.active {{
            background: rgba(79, 195, 247, 0.3);
        }}
        .tab-content {{
            display: none;
        }}
        .tab-content.active {{
            display: block;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔬 APK Analysis Dashboard</h1>
            <div class="subtitle">Comprehensive Security Analysis Report</div>
            <div class="timestamp">Generated: {self ._esc (data ['metadata']['generated'])}</div>
        </div>
        
        <div class="dashboard-grid">
            <div class="card">
                <h3>📊 Analysis Summary</h3>
                <div class="metric">
                    <span>Total Analyses:</span>
                    <span>{data ['threat_summary']['total_analyses']}</span>
                </div>
                <div class="metric">
                    <span>Threat Level:</span>
                    <span class="threat-level threat-{data ['threat_summary']['threat_level'].lower ()}">{self ._esc (data ['threat_summary']['threat_level'])}</span>
                </div>
                <div class="metric">
                    <span>Malware Score:</span>
                    <span>{data ['threat_summary']['malware_score']}/10</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {min (max (data ['threat_summary']['malware_score'],0 ),10 )*10 }%"></div>
                </div>
                <div class="metric">
                    <span>Static Reports:</span>
                    <span>{len (data ['static_analysis'])}</span>
                </div>
                <div class="metric">
                    <span>Network Reports:</span>
                    <span>{len (data ['network_analysis'])}</span>
                </div>
                <div class="metric">
                    <span>Analysis Sessions:</span>
                    <span>{len (data ['sessions'])}</span>
                </div>
                <div class="metric">
                    <span>Artifacts Found:</span>
                    <span>{len (data ['artifacts'])}</span>
                </div>
            </div>
            
            <div class="card">
                <h3>🔒 Security Findings</h3>
                <div style="max-height: 200px; overflow-y: auto;">
                    {self ._generate_findings_html (data ['threat_summary']['key_findings'])}
                    {self ._generate_permissions_html (data ['threat_summary']['permissions'])}
                </div>
            </div>
            
            <div class="card">
                <h3>🌐 Network Indicators</h3>
                <div style="max-height: 200px; overflow-y: auto;">
                    {self ._generate_network_html (data ['threat_summary']['network_indicators'])}
                </div>
            </div>
            
            <div class="card">
                <h3>📂 Artifacts</h3>
                <div class="artifact-grid">
                    {self ._generate_artifacts_html (data ['artifacts'])}
                </div>
            </div>
        </div>
        
        <div class="tab-container">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="showTab(event, 'static')">Static Analysis</button>
                <button class="tab-button" onclick="showTab(event, 'dynamic')">Dynamic Analysis</button>
                <button class="tab-button" onclick="showTab(event, 'network')">Network Analysis</button>
                <button class="tab-button" onclick="showTab(event, 'sessions')">Analysis Sessions</button>
                <button class="tab-button" onclick="showTab(event, 'raw')">Raw Data</button>
            </div>
            
            <div id="static" class="tab-content active">
                <div class="card">
                    <h3>📋 Static Analysis Reports</h3>
                    {self ._generate_static_reports_html (data ['static_analysis'])}
                </div>
            </div>

            <div id="dynamic" class="tab-content">
                <div class="card">
                    <h3>⚙️ Dynamic Analysis Reports</h3>
                    {self ._generate_generic_reports_list (data ['dynamic_analysis'])}
                </div>
            </div>

            <div id="network" class="tab-content">
                <div class="card">
                    <h3>🌐 Network Analysis Reports</h3>
                    {self ._generate_generic_reports_list (data ['network_analysis'])}
                </div>
            </div>
            
            <div id="sessions" class="tab-content">
                <div class="card">
                    <h3>🔄 Analysis Sessions</h3>
                    {self ._generate_sessions_html (data ['sessions'])}
                </div>
            </div>
            
            <div id="raw" class="tab-content">
                <div class="card">
                    <h3>📄 Raw Analysis Data</h3>
                    <div class="json-preview">
                        <pre>{self ._esc (json .dumps (data ,indent =2 ,ensure_ascii =False )[:5000 ])}...</pre>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function showTab(evt, tabName) {{
            // Hide all tab contents
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            // Remove active class from all buttons
            const buttons = document.querySelectorAll('.tab-button');
            buttons.forEach(button => button.classList.remove('active'));
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to clicked button
            if (evt && evt.target) {{
                evt.target.classList.add('active');
            }}
        }}
    </script>
</body>
</html>
"""
        return html_template 

    def _generate_findings_html (self ,findings :List [str ])->str :
        if not findings :
            return '<div class="list-item">No security findings detected</div>'

        html =""
        for finding in findings [:10 ]:
            html +=f'<div class="list-item">⚠️ {self ._esc (finding )}</div>'
        return html 

    def _generate_permissions_html (self ,permissions :List [str ])->str :
        if not permissions :
            return '<div class="list-item">No permissions analyzed</div>'

        html =""
        unique_permissions =list (set (permissions ))[:10 ]
        for perm in unique_permissions :
            html +=f'<div class="list-item">🔐 {self ._esc (perm )}</div>'
        return html 

    def _generate_network_html (self ,indicators :List [str ])->str :
        if not indicators :
            return '<div class="list-item">No network indicators found</div>'

        html =""
        unique_indicators =list (set (indicators ))[:10 ]
        for indicator in unique_indicators :
            html +=f'<div class="list-item">🔗 {self ._esc (indicator )}</div>'
        return html 

    def _generate_artifacts_html (self ,artifacts :List [Dict ])->str :
        if not artifacts :
            return '<div class="artifact-item">No artifacts found</div>'

        html =""
        html_dir =self .analysis_results /"reports"/"html"
        for artifact in artifacts [:12 ]:
            size_mb =artifact ['size']/(1024 *1024 )
            safe_name =self ._esc (artifact ['name'])
            safe_path =self ._esc (artifact ['path'])
            artifact_full_path =self .workspace_root /artifact ['path']
            try :
                relative_path =os .path .relpath (artifact_full_path ,html_dir )
                href =relative_path .replace ("\\","/")
            except (ValueError ,OSError ):
                href =safe_path 
            html +=f'''
            <div class="artifact-item">
                <div style="font-weight: bold; margin-bottom: 5px;">
                    <a href="{href }" target="_blank" rel="noopener">{safe_name }</a>
                </div>
                <div style="font-size: 0.8rem; opacity: 0.8;">
                    Size: {size_mb :.2f} MB<br>
                    Path: {safe_path }
                </div>
            </div>
            '''
        return html 

    def _generate_static_reports_html (self ,reports :List [Dict ])->str :
        if not reports :
            return '<div class="list-item">No static analysis reports found</div>'

        html =""
        for report in reports :
            pkg =report ['data'].get ('manifest_analysis',{}).get ('package_name','Unknown')
            html +=f'''
            <div class="list-item">
                <div style="font-weight: bold;">{self ._esc (report ['file'])}</div>
                <div style="font-size: 0.8rem; opacity: 0.8; margin-top: 5px;">
                    Package: {self ._esc (pkg )}
                </div>
            </div>
            '''
        return html 

    def _generate_generic_reports_list (self ,reports :List [Dict ])->str :
        if not reports :
            return '<div class="list-item">No reports found</div>'
        items =[]
        for r in reports :
            items .append (f'''
            <div class="list-item">
                <div style="font-weight: bold;">{self ._esc (r .get ('file','unknown.json'))}</div>
                <div style="font-size: 0.8rem; opacity: 0.8; margin-top: 5px;">
                    Size: {len (json .dumps (r .get ('data',{ {} })))if isinstance (r .get ('data'),(dict ,list ))else 'n/a'} bytes
                </div>
            </div>
            ''')
        return "".join (items )

    def _generate_sessions_html (self ,sessions :List [Dict ])->str :
        if not sessions :
            return '<div class="list-item">No analysis sessions found</div>'

        html =""
        for session in sessions :
            session_data =session ['data']
            html +=f'''
            <div class="list-item">
                <div style="font-weight: bold;">Session: {self ._esc (session ['file'])}</div>
                <div style="font-size: 0.8rem; opacity: 0.8; margin-top: 5px;">
                    Timestamp: {self ._esc (session_data .get ('timestamp','Unknown'))}<br>
                    Package: {self ._esc (session_data .get ('package','Unknown'))}<br>
                    Static Analysis: {'✓'if session_data .get ('static',{ {} }).get ('artifacts_present')else '✗'}
                </div>
            </div>
            '''
        return html 

    def save_dashboard (self )->Path :
        dashboard_html =self .generate_html_dashboard ()
        output_path =self .analysis_results /"reports"/"html"/f"analysis_dashboard_{self .timestamp }.html"
        output_path .parent .mkdir (parents =True ,exist_ok =True )

        with open (output_path ,'w',encoding ='utf-8')as f :
            f .write (dashboard_html )


        latest_path =output_path .parent /"latest_dashboard.html"
        if latest_path .exists ()or latest_path .is_symlink ():
            try :
                latest_path .unlink ()
            except Exception :
                pass 
        try :
            latest_path .symlink_to (output_path .name )
        except Exception :

            try :
                shutil .copy2 (output_path ,latest_path )
            except Exception as e :
                print (f"Warning: failed to create latest dashboard alias: {e }")

        return output_path 

def main ():
    dashboard =AnalysisDashboard ()
    output_path =dashboard .save_dashboard ()
    print (f"✓ Dashboard generated: {output_path }")
    print (f"✓ Latest dashboard: {output_path .parent }/latest_dashboard.html")
    print (f"🌐 Open in browser: file://{output_path .absolute ()}")

if __name__ =="__main__":
    main ()
