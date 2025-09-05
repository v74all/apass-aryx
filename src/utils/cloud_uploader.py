#!/usr/bin/env python3

import os 
import sys 
import json 
import argparse 
import logging 
from pathlib import Path 
import shutil 
import tempfile 
import zipfile 
from typing import Dict ,List ,Optional ,Union 


logging .basicConfig (
level =logging .INFO ,
format ="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger =logging .getLogger ("CloudUploader")


class CloudUploader :

    def __init__ (self ,provider :str ,config :Dict ,analysis_id :str ):
        self .provider =provider .lower ()
        self .config =config 
        self .analysis_id =analysis_id 
        self .supported_providers ={
        "azure":self ._upload_to_azure ,
        "aws":self ._upload_to_aws ,
        "gcp":self ._upload_to_gcp 
        }

        if self .provider not in self .supported_providers :
            raise ValueError (f"Unsupported cloud provider: {provider }. Supported providers: {', '.join (self .supported_providers .keys ())}")

    def upload (self ,output_dir :Path )->bool :
        if not output_dir .exists ()or not output_dir .is_dir ():
            logger .error (f"Output directory not found: {output_dir }")
            return False 


        with tempfile .TemporaryDirectory ()as temp_dir :
            archive_path =Path (temp_dir )/f"{self .analysis_id }.zip"

            try :
                logger .info (f"Creating archive of analysis results: {archive_path }")
                self ._create_archive (output_dir ,archive_path )


                upload_func =self .supported_providers .get (self .provider )
                if not upload_func :
                    logger .error (f"No upload implementation for provider: {self .provider }")
                    return False 

                return upload_func (archive_path )

            except Exception as e :
                logger .error (f"Error uploading to {self .provider }: {e }",exc_info =True )
                return False 

    def _create_archive (self ,source_dir :Path ,archive_path :Path )->None :
        with zipfile .ZipFile (archive_path ,'w',zipfile .ZIP_DEFLATED )as zipf :
            for root ,_ ,files in os .walk (source_dir ):
                for file in files :
                    file_path =Path (root )/file 
                    arcname =file_path .relative_to (source_dir )
                    zipf .write (file_path ,arcname )

    def _upload_to_azure (self ,archive_path :Path )->bool :
        try :
            from azure .storage .blob import BlobServiceClient 


            connection_string =self .config .get ("connection_string")
            if not connection_string :

                connection_string =os .environ .get ("AZURE_STORAGE_CONNECTION_STRING")

            if not connection_string :
                logger .error ("Azure connection string not provided in config or environment")
                return False 

            container_name =self .config .get ("container_name","malware-analysis-results")


            logger .info (f"Uploading to Azure Blob Storage container: {container_name }")
            blob_service_client =BlobServiceClient .from_connection_string (connection_string )


            try :
                blob_service_client .create_container (container_name )
                logger .info (f"Created container: {container_name }")
            except :

                pass 


            blob_name =f"{self .analysis_id }/{archive_path .name }"
            blob_client =blob_service_client .get_blob_client (
            container =container_name ,
            blob =blob_name 
            )

            with open (archive_path ,"rb")as data :
                blob_client .upload_blob (data ,overwrite =True )

            logger .info (f"Successfully uploaded to Azure Blob Storage: {blob_name }")


            metadata ={
            "analysis_id":self .analysis_id ,
            "upload_time":self ._get_current_timestamp (),
            "provider":"azure",
            "container":container_name ,
            "blob_path":blob_name 
            }


            with tempfile .NamedTemporaryFile (mode ='w',delete =False ,suffix ='.json')as temp :
                json .dump (metadata ,temp ,indent =2 )
                temp_path =temp .name 


            metadata_blob_name =f"{self .analysis_id }/metadata.json"
            metadata_blob_client =blob_service_client .get_blob_client (
            container =container_name ,
            blob =metadata_blob_name 
            )

            with open (temp_path ,"rb")as data :
                metadata_blob_client .upload_blob (data ,overwrite =True )


            os .unlink (temp_path )

            return True 

        except ImportError :
            logger .error ("Azure SDK not installed. Run 'pip install azure-storage-blob'")
            return False 
        except Exception as e :
            logger .error (f"Error uploading to Azure: {e }",exc_info =True )
            return False 

    def _upload_to_aws (self ,archive_path :Path )->bool :
        try :
            import boto3 


            bucket_name =self .config .get ("bucket_name")
            region =self .config .get ("region","us-east-1")

            if not bucket_name :
                logger .error ("AWS bucket name not provided in config")
                return False 


            if not self ._aws_credentials_available ():
                logger .error ("AWS credentials not found. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
                return False 


            logger .info (f"Uploading to AWS S3 bucket: {bucket_name }")
            s3_client =boto3 .client ('s3',region_name =region )


            object_key =f"{self .analysis_id }/{archive_path .name }"
            s3_client .upload_file (
            str (archive_path ),
            bucket_name ,
            object_key 
            )

            logger .info (f"Successfully uploaded to AWS S3: {object_key }")


            metadata ={
            "analysis_id":self .analysis_id ,
            "upload_time":self ._get_current_timestamp (),
            "provider":"aws",
            "bucket":bucket_name ,
            "object_key":object_key 
            }


            with tempfile .NamedTemporaryFile (mode ='w',delete =False ,suffix ='.json')as temp :
                json .dump (metadata ,temp ,indent =2 )
                temp_path =temp .name 


            metadata_key =f"{self .analysis_id }/metadata.json"
            s3_client .upload_file (
            temp_path ,
            bucket_name ,
            metadata_key 
            )


            os .unlink (temp_path )

            return True 

        except ImportError :
            logger .error ("AWS SDK not installed. Run 'pip install boto3'")
            return False 
        except Exception as e :
            logger .error (f"Error uploading to AWS: {e }",exc_info =True )
            return False 

    def _upload_to_gcp (self ,archive_path :Path )->bool :
        try :
            from google .cloud import storage 


            bucket_name =self .config .get ("bucket_name")
            credentials_file =self .config .get ("credentials_file")

            if not bucket_name :
                logger .error ("GCP bucket name not provided in config")
                return False 


            if credentials_file :
                os .environ ["GOOGLE_APPLICATION_CREDENTIALS"]=credentials_file 


            logger .info (f"Uploading to Google Cloud Storage bucket: {bucket_name }")
            storage_client =storage .Client ()


            try :
                bucket =storage_client .get_bucket (bucket_name )
            except Exception :
                logger .error (f"GCS bucket not found: {bucket_name }")
                return False 


            blob_name =f"{self .analysis_id }/{archive_path .name }"
            blob =bucket .blob (blob_name )
            blob .upload_from_filename (str (archive_path ))

            logger .info (f"Successfully uploaded to Google Cloud Storage: {blob_name }")


            metadata ={
            "analysis_id":self .analysis_id ,
            "upload_time":self ._get_current_timestamp (),
            "provider":"gcp",
            "bucket":bucket_name ,
            "blob_name":blob_name 
            }


            with tempfile .NamedTemporaryFile (mode ='w',delete =False ,suffix ='.json')as temp :
                json .dump (metadata ,temp ,indent =2 )
                temp_path =temp .name 


            metadata_blob_name =f"{self .analysis_id }/metadata.json"
            metadata_blob =bucket .blob (metadata_blob_name )
            metadata_blob .upload_from_filename (temp_path )


            os .unlink (temp_path )

            return True 

        except ImportError :
            logger .error ("Google Cloud SDK not installed. Run 'pip install google-cloud-storage'")
            return False 
        except Exception as e :
            logger .error (f"Error uploading to Google Cloud: {e }",exc_info =True )
            return False 

    def _aws_credentials_available (self )->bool :
        return (
        os .environ .get ("AWS_ACCESS_KEY_ID")is not None and 
        os .environ .get ("AWS_SECRET_ACCESS_KEY")is not None 
        )

    def _get_current_timestamp (self )->str :
        from datetime import datetime 
        return datetime .now ().isoformat ()


def main ():
    parser =argparse .ArgumentParser (description ="Upload analysis results to cloud storage")
    parser .add_argument ("--provider",required =True ,help ="Cloud provider (azure, aws, gcp)")
    parser .add_argument ("--analysis-id",required =True ,help ="Analysis ID")
    parser .add_argument ("--config",required =True ,help ="Cloud configuration as JSON string")
    parser .add_argument ("--output-dir",required =True ,help ="Directory containing analysis results")

    args =parser .parse_args ()

    try :
        config =json .loads (args .config )
    except json .JSONDecodeError :
        logger .error ("Invalid JSON configuration")
        sys .exit (1 )

    output_dir =Path (args .output_dir )
    if not output_dir .exists ()or not output_dir .is_dir ():
        logger .error (f"Output directory not found: {output_dir }")
        sys .exit (1 )

    try :
        uploader =CloudUploader (args .provider ,config ,args .analysis_id )
        success =uploader .upload (output_dir )

        if success :
            logger .info ("Upload completed successfully")
            sys .exit (0 )
        else :
            logger .error ("Upload failed")
            sys .exit (1 )

    except Exception as e :
        logger .error (f"Error: {e }",exc_info =True )
        sys .exit (1 )


if __name__ =="__main__":
    main ()
