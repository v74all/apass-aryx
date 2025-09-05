
from __future__ import annotations 

from dataclasses import dataclass 
from pathlib import Path 
from typing import Callable ,Dict ,List ,Optional ,Tuple 
import importlib 
import sys 


REPO_ROOT =Path (__file__ ).resolve ().parents [2 ]
SRC_DIR =REPO_ROOT /"src"
if str (SRC_DIR )not in sys .path :
	sys .path .insert (0 ,str (SRC_DIR ))


RunFn =Callable [[str ],Tuple [int ,Optional [str ],Optional [str ]]]


@dataclass 
class Analyzer :
	id :str 
	label :str 
	run :RunFn 
	available :bool =True 


def _wrap_unified ()->Analyzer :
	def run (apk_path :str )->Tuple [int ,Optional [str ],Optional [str ]]:
		try :
			mod =importlib .import_module ("core.unified_analysis")
			AnalyzerCls =getattr (mod ,"UnifiedAPKAnalyzer")
			analyzer =AnalyzerCls (apk_path )
			outdir =analyzer .run_complete_analysis ()

			reports =str (Path (outdir )/"reports")if outdir and not str (outdir ).startswith ("FAILED")else None 
			return (0 ,outdir ,reports )if outdir and not str (outdir ).startswith ("FAILED")else (1 ,None ,None )
		except Exception :
			return (1 ,None ,None )


	avail =True 
	try :
		importlib .import_module ("core.unified_analysis")
	except Exception :
		avail =False 
	return Analyzer ("unified","Unified Analyzer",run ,avail )


def _wrap_advanced ()->Analyzer :
	def run (apk_path :str )->Tuple [int ,Optional [str ],Optional [str ]]:
		try :
			mod =importlib .import_module ("core.advanced_analysis")
			AnalyzerCls =getattr (mod ,"AdvancedAPKAnalyzer")
			analyzer =AnalyzerCls (apk_path )
			outdir =analyzer .run_complete_analysis ()
			reports =str (Path (outdir )/"reports")if outdir and not str (outdir ).startswith ("FAILED")else None 
			return (0 ,outdir ,reports )if outdir and not str (outdir ).startswith ("FAILED")else (1 ,None ,None )
		except Exception :
			return (1 ,None ,None )

	avail =True 
	try :
		importlib .import_module ("core.advanced_analysis")
	except Exception :
		avail =False 
	return Analyzer ("advanced","Advanced Analyzer",run ,avail )


def _wrap_advanced_static ()->Analyzer :

	def run (apk_path :str )->Tuple [int ,Optional [str ],Optional [str ]]:
		try :
			mod =importlib .import_module ("analyzers.advanced_static_analyzer")
			AnalyzerCls =getattr (mod ,"AdvancedAPKAnalyzer")
			analyzer =AnalyzerCls (apk_path )

			outdir =Path ("analysis_results")/"unified_output"/f"advanced_static_{Path (apk_path ).stem }"
			outdir .mkdir (parents =True ,exist_ok =True )
			reports =outdir /"reports"
			reports .mkdir (exist_ok =True )

			try :
				analyzer .calculate_file_hashes ()
				analyzer .extract_and_analyze_manifest ()
			except Exception :
				pass 

			(reports /"summary.txt").write_text ("Advanced static analysis completed\n",encoding ="utf-8")
			return 0 ,str (outdir ),str (reports )
		except Exception :
			return (1 ,None ,None )

	avail =True 
	try :
		importlib .import_module ("analyzers.advanced_static_analyzer")
	except Exception :
		avail =False 
	return Analyzer ("advanced_static","Advanced Static Analyzer",run ,avail )


def _wrap_enhanced_extractor ()->Analyzer :
	def run (apk_path :str )->Tuple [int ,Optional [str ],Optional [str ]]:
		try :
			mod =importlib .import_module ("analyzers.enhanced_data_extractor")
			AnalysisConfig =getattr (mod ,"AnalysisConfig")
			EnhancedDataExtractor =getattr (mod ,"EnhancedDataExtractor")

			outdir =Path ("analysis_results")/"unified_output"/f"enhanced_extraction_{Path (apk_path ).stem }"
			cfg =AnalysisConfig (
			apk_path =str (apk_path ),
			package_name =Path (apk_path ).stem ,
			output_dir =str (outdir ),
			timeout =180 ,
			analyze_permissions =True ,
			analyze_resources =True ,
			analyze_strings =True ,
			analyze_cert =True ,
			verbose =False ,
			max_workers =4 ,
			)
			extractor =EnhancedDataExtractor (cfg )

			run_method =getattr (extractor ,"run",None )
			if callable (run_method ):
				run_method ()
			reports =outdir /"reports"
			reports .mkdir (parents =True ,exist_ok =True )
			(reports /"summary.txt").write_text ("Enhanced data extraction completed\n",encoding ="utf-8")
			return 0 ,str (outdir ),str (reports )
		except Exception :
			return (1 ,None ,None )

	avail =True 
	try :
		importlib .import_module ("analyzers.enhanced_data_extractor")
	except Exception :
		avail =False 
	return Analyzer ("enhanced_data_extractor","Enhanced Data Extractor",run ,avail )


def get_analyzers ()->List [Analyzer ]:
	analyzers =[
	_wrap_unified (),
	_wrap_advanced (),
	_wrap_advanced_static (),
	_wrap_enhanced_extractor (),
	]
	return analyzers 


def get_analyzer_map ()->Dict [str ,Analyzer ]:
	return {a .id :a for a in get_analyzers ()}


def run_analyzer (engine :str ,apk_path :str )->Tuple [int ,Optional [str ],Optional [str ]]:
	amap =get_analyzer_map ()
	if engine =="auto":

		for pref in ("advanced","unified","advanced_static","enhanced_data_extractor"):
			a =amap .get (pref )
			if a and a .available :
				return a .run (apk_path )
		return (1 ,None ,None )
	a =amap .get (engine )
	if not a or not a .available :
		return (1 ,None ,None )
	return a .run (apk_path )

