#!/usr/bin/env python3

import json 
import hashlib 
import requests 
import time 
from pathlib import Path 
from datetime import datetime ,timedelta 
from typing import Dict ,List ,Optional ,Any ,Union ,Set ,Tuple 
from dataclasses import dataclass ,asdict 
import threading 
from concurrent .futures import ThreadPoolExecutor 
import queue 

try :
    from .logger import get_logger 
except ImportError :

    import logging 
    def get_logger ():
        return logging .getLogger (__name__ )


@dataclass 
class IOCInfo :
    value :str 
    type :str 
    first_seen :Optional [str ]=None 
    last_seen :Optional [str ]=None 
    threat_types :List [str ]=None 
    confidence :float =0.0 
    source :str =""
    tags :List [str ]=None 

    def __post_init__ (self ):
        if self .threat_types is None :
            self .threat_types =[]
        if self .tags is None :
            self .tags =[]


@dataclass 
class ThreatReport :
    iocs :List [IOCInfo ]
    risk_score :float 
    threat_categories :List [str ]
    recommendations :List [str ]
    analysis_timestamp :str 
    sources_used :List [str ]


class ThreatIntelligence :

    def __init__ (self ,config_path :Optional [str ]=None ,cache_dir :Optional [str ]=None ):
        self .logger =get_logger ()
        self .config =self ._load_config (config_path )
        self .cache_dir =Path (cache_dir )if cache_dir else Path .cwd ()/".ti_cache"
        self .cache_dir .mkdir (parents =True ,exist_ok =True )


        self .threat_feeds ={
        'domains_watchlist':self ._load_domains_watchlist (),
        'ip_blacklist':self ._load_ip_blacklist (),
        'hash_database':self ._load_hash_database (),
        'malware_families':self ._load_malware_families ()
        }


        self .session =requests .Session ()
        self .session .headers .update ({
        'User-Agent':'APASS-ARYX-TI/1.0'
        })


        self .rate_limiter ={
        'calls':queue .Queue (),
        'max_calls':100 ,
        'time_window':3600 
        }

    def _load_config (self ,config_path :Optional [str ])->Dict [str ,Any ]:
        default_config ={
        'api_keys':{},
        'sources':{
        'virustotal':{'enabled':False ,'api_key':''},
        'hybrid_analysis':{'enabled':False ,'api_key':''},
        'alienvault':{'enabled':False ,'api_key':''},
        'threatminer':{'enabled':True ,'api_key':''},
        'local_feeds':{'enabled':True }
        },
        'cache_ttl':86400 ,
        'timeout':30 ,
        'max_retries':3 
        }

        if config_path and Path (config_path ).exists ():
            try :
                with open (config_path ,'r')as f :
                    user_config =json .load (f )
                    default_config .update (user_config .get ('threat_intelligence',{}))
            except Exception as e :
                self .logger .warning (f"Could not load TI config: {e }")

        return default_config 

    def _load_domains_watchlist (self )->Set [str ]:
        domains =set ()


        watchlist_paths =[
        Path .cwd ()/"resources"/"signatures"/"domains_watchlist.txt",
        Path (__file__ ).parent .parent .parent /"resources"/"signatures"/"domains_watchlist.txt"
        ]

        for path in watchlist_paths :
            if path .exists ():
                try :
                    with open (path ,'r')as f :
                        for line in f :
                            domain =line .strip ()
                            if domain and not domain .startswith ('#'):
                                domains .add (domain .lower ())
                    self .logger .debug (f"Loaded {len (domains )} domains from watchlist")
                    break 
                except Exception as e :
                    self .logger .warning (f"Error loading domains watchlist: {e }")


        domains .update ([
        'malware.com','badsite.ru','phishing.net',
        'trojan.org','c2server.biz','malicious.info'
        ])

        return domains 

    def _load_ip_blacklist (self )->Set [str ]:


        return {
        '192.168.1.100',
        '10.0.0.50',
        '203.0.113.1',
        '198.51.100.1'
        }

    def _load_hash_database (self )->Dict [str ,Dict [str ,Any ]]:

        return {

        'da39a3ee5e6b4b0d3255bfef95601890afd80709':{
        'family':'Example Malware',
        'type':'trojan',
        'first_seen':'2025-01-01'
        }
        }

    def _load_malware_families (self )->Dict [str ,Dict [str ,Any ]]:
        return {
        'banker':{
        'description':'Banking Trojan',
        'risk_level':'high',
        'indicators':['banking','credential','overlay']
        },
        'adware':{
        'description':'Advertisement Software',
        'risk_level':'medium',
        'indicators':['ads','popup','advertisement']
        },
        'spyware':{
        'description':'Spying Software',
        'risk_level':'high',
        'indicators':['spy','monitor','keylog']
        }
        }

    def analyze_ioc (self ,ioc :str ,ioc_type :str )->IOCInfo :
        self .logger .debug (f"Analyzing IOC: {ioc } (type: {ioc_type })")

        ioc_info =IOCInfo (
        value =ioc ,
        type =ioc_type ,
        first_seen =datetime .now ().isoformat (),
        source ="APASS ARYX"
        )

        try :

            if ioc_type =='domain':
                ioc_info =self ._analyze_domain (ioc ,ioc_info )
            elif ioc_type =='ip':
                ioc_info =self ._analyze_ip (ioc ,ioc_info )
            elif ioc_type =='hash':
                ioc_info =self ._analyze_hash (ioc ,ioc_info )
            elif ioc_type =='url':
                ioc_info =self ._analyze_url (ioc ,ioc_info )


            if self .config ['sources']['local_feeds']['enabled']:
                ioc_info =self ._enrich_with_external_sources (ioc ,ioc_info )

        except Exception as e :
            self .logger .error (f"Error analyzing IOC {ioc }: {e }")

        return ioc_info 

    def _analyze_domain (self ,domain :str ,ioc_info :IOCInfo )->IOCInfo :
        domain_lower =domain .lower ()


        if domain_lower in self .threat_feeds ['domains_watchlist']:
            ioc_info .threat_types .append ('malicious_domain')
            ioc_info .confidence =0.8 
            ioc_info .tags .append ('watchlist')


        suspicious_keywords =['malware','phish','trojan','c2','cmd','bot']
        for keyword in suspicious_keywords :
            if keyword in domain_lower :
                ioc_info .threat_types .append ('suspicious_domain')
                ioc_info .confidence =max (ioc_info .confidence ,0.6 )
                ioc_info .tags .append (f'contains_{keyword }')


        suspicious_tlds =['.tk','.ml','.ga','.cf','.bit']
        for tld in suspicious_tlds :
            if domain_lower .endswith (tld ):
                ioc_info .threat_types .append ('suspicious_tld')
                ioc_info .confidence =max (ioc_info .confidence ,0.4 )
                ioc_info .tags .append ('suspicious_tld')

        return ioc_info 

    def _analyze_ip (self ,ip :str ,ioc_info :IOCInfo )->IOCInfo :

        if ip in self .threat_feeds ['ip_blacklist']:
            ioc_info .threat_types .append ('malicious_ip')
            ioc_info .confidence =0.9 
            ioc_info .tags .append ('blacklist')


        if self ._is_private_ip (ip ):
            ioc_info .threat_types .append ('private_ip_contact')
            ioc_info .confidence =0.5 
            ioc_info .tags .append ('private_ip')

        return ioc_info 

    def _analyze_hash (self ,hash_value :str ,ioc_info :IOCInfo )->IOCInfo :
        hash_lower =hash_value .lower ()


        if hash_lower in self .threat_feeds ['hash_database']:
            hash_info =self .threat_feeds ['hash_database'][hash_lower ]
            ioc_info .threat_types .append ('known_malware')
            ioc_info .confidence =0.95 
            ioc_info .tags .extend (['known_hash',hash_info .get ('family','unknown')])

            if 'type'in hash_info :
                ioc_info .threat_types .append (hash_info ['type'])

        return ioc_info 

    def _analyze_url (self ,url :str ,ioc_info :IOCInfo )->IOCInfo :
        url_lower =url .lower ()


        try :
            from urllib .parse import urlparse 
            parsed =urlparse (url )
            if parsed .netloc :
                domain_info =self ._analyze_domain (parsed .netloc ,IOCInfo (
                value =parsed .netloc ,type ='domain'
                ))
                ioc_info .threat_types .extend (domain_info .threat_types )
                ioc_info .confidence =max (ioc_info .confidence ,domain_info .confidence )
                ioc_info .tags .extend (domain_info .tags )
        except Exception :
            pass 


        suspicious_patterns =['admin','login','bank','paypal','amazon','update']
        for pattern in suspicious_patterns :
            if pattern in url_lower :
                ioc_info .threat_types .append ('suspicious_url')
                ioc_info .confidence =max (ioc_info .confidence ,0.3 )
                ioc_info .tags .append (f'contains_{pattern }')

        return ioc_info 

    def _enrich_with_external_sources (self ,ioc :str ,ioc_info :IOCInfo )->IOCInfo :




        cache_key =hashlib .md5 (f"{ioc }_{ioc_info .type }".encode ()).hexdigest ()
        cache_file =self .cache_dir /f"{cache_key }.json"

        if cache_file .exists ():
            try :
                cache_age =time .time ()-cache_file .stat ().st_mtime 
                if cache_age <self .config ['cache_ttl']:
                    with open (cache_file ,'r')as f :
                        cached_data =json .load (f )
                        if cached_data .get ('threat_types'):
                            ioc_info .threat_types .extend (cached_data ['threat_types'])
                        if cached_data .get ('confidence',0 )>ioc_info .confidence :
                            ioc_info .confidence =cached_data ['confidence']
                        return ioc_info 
            except Exception :
                pass 


        external_data =self ._simulate_external_lookup (ioc ,ioc_info .type )

        if external_data :
            ioc_info .threat_types .extend (external_data .get ('threat_types',[]))
            ioc_info .confidence =max (ioc_info .confidence ,external_data .get ('confidence',0 ))
            ioc_info .tags .extend (external_data .get ('tags',[]))


            try :
                with open (cache_file ,'w')as f :
                    json .dump (external_data ,f )
            except Exception :
                pass 

        return ioc_info 

    def _simulate_external_lookup (self ,ioc :str ,ioc_type :str )->Optional [Dict [str ,Any ]]:



        if 'malware'in ioc .lower ()or 'bad'in ioc .lower ():
            return {
            'threat_types':['external_malicious'],
            'confidence':0.85 ,
            'tags':['external_feed','high_confidence'],
            'source':'simulated_ti_feed'
            }

        return None 

    def batch_analyze_iocs (self ,iocs :List [Tuple [str ,str ]])->List [IOCInfo ]:
        self .logger .info (f"Analyzing {len (iocs )} IOCs in batch")

        results =[]


        with ThreadPoolExecutor (max_workers =5 )as executor :
            future_to_ioc ={
            executor .submit (self .analyze_ioc ,ioc ,ioc_type ):(ioc ,ioc_type )
            for ioc ,ioc_type in iocs 
            }

            for future in future_to_ioc :
                try :
                    result =future .result (timeout =30 )
                    results .append (result )
                except Exception as e :
                    ioc ,ioc_type =future_to_ioc [future ]
                    self .logger .error (f"Error analyzing IOC {ioc }: {e }")

                    results .append (IOCInfo (value =ioc ,type =ioc_type ,source ="error"))

        return results 

    def generate_threat_report (self ,iocs :List [IOCInfo ])->ThreatReport :
        self .logger .info ("Generating threat intelligence report")


        if iocs :
            avg_confidence =sum (ioc .confidence for ioc in iocs )/len (iocs )
            threat_count =sum (1 for ioc in iocs if ioc .threat_types )
            risk_score =min (100 ,(avg_confidence *100 +(threat_count /len (iocs ))*50 ))
        else :
            risk_score =0 


        threat_categories =set ()
        for ioc in iocs :
            threat_categories .update (ioc .threat_types )


        recommendations =self ._generate_recommendations (list (threat_categories ),risk_score )

        return ThreatReport (
        iocs =iocs ,
        risk_score =risk_score ,
        threat_categories =list (threat_categories ),
        recommendations =recommendations ,
        analysis_timestamp =datetime .now ().isoformat (),
        sources_used =list (self .config ['sources'].keys ())
        )

    def _generate_recommendations (self ,threat_categories :List [str ],risk_score :float )->List [str ]:
        recommendations =[]

        if risk_score >70 :
            recommendations .append ("HIGH RISK: Immediate investigation recommended")
            recommendations .append ("Consider blocking identified indicators")
            recommendations .append ("Implement additional monitoring")
        elif risk_score >40 :
            recommendations .append ("MEDIUM RISK: Enhanced monitoring recommended")
            recommendations .append ("Review and validate findings")
        else :
            recommendations .append ("LOW RISK: Standard monitoring sufficient")

        if 'malicious_domain'in threat_categories :
            recommendations .append ("Block malicious domains at DNS level")

        if 'malicious_ip'in threat_categories :
            recommendations .append ("Block malicious IP addresses at firewall level")

        if 'known_malware'in threat_categories :
            recommendations .append ("Quarantine and analyze identified malware samples")

        if 'suspicious_url'in threat_categories :
            recommendations .append ("Investigate suspicious URLs for phishing or malware")

        recommendations .append ("Cross-reference findings with additional threat intelligence sources")
        recommendations .append ("Document findings for future reference")

        return recommendations 

    def _is_private_ip (self ,ip :str )->bool :
        try :
            import ipaddress 
            ip_obj =ipaddress .ip_address (ip )
            return ip_obj .is_private 
        except Exception :
            return False 

    def _rate_limit_check (self )->bool :
        current_time =time .time ()


        while not self .rate_limiter ['calls'].empty ():
            try :
                call_time =self .rate_limiter ['calls'].queue [0 ]
                if current_time -call_time >self .rate_limiter ['time_window']:
                    self .rate_limiter ['calls'].get_nowait ()
                else :
                    break 
            except (IndexError ,queue .Empty ):
                break 


        if self .rate_limiter ['calls'].qsize ()<self .rate_limiter ['max_calls']:
            self .rate_limiter ['calls'].put (current_time )
            return True 

        return False 

    def get_threat_feeds_status (self )->Dict [str ,Any ]:
        return {
        'feeds':{
        'domains_watchlist':len (self .threat_feeds ['domains_watchlist']),
        'ip_blacklist':len (self .threat_feeds ['ip_blacklist']),
        'hash_database':len (self .threat_feeds ['hash_database']),
        'malware_families':len (self .threat_feeds ['malware_families'])
        },
        'sources':self .config ['sources'],
        'cache_dir':str (self .cache_dir ),
        'last_updated':datetime .now ().isoformat ()
        }

    def update_threat_feeds (self )->bool :
        self .logger .info ("Updating threat intelligence feeds")

        try :


            self .threat_feeds ['domains_watchlist']=self ._load_domains_watchlist ()
            self .threat_feeds ['ip_blacklist']=self ._load_ip_blacklist ()
            self .threat_feeds ['hash_database']=self ._load_hash_database ()
            self .threat_feeds ['malware_families']=self ._load_malware_families ()

            self .logger .info ("Threat intelligence feeds updated successfully")
            return True 

        except Exception as e :
            self .logger .error (f"Error updating threat feeds: {e }")
            return False 
