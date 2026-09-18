import boto3
import json
from botocore.exceptions import ClientError

secrets_client = boto3.client('secretsmanager')
s3 = boto3.client('s3')

def get_database_credentials():
    """ GOOD: Fetch secrets from Secrets Manager at runtime"""
    try:
        response = secrets_client.get_secret_value(SecretId='prod/database/credentials')
        return json.loads(response['SecretString'])
    except ClientError as e:
        print(f"[ERROR] Failed to retrieve secrets: {str(e)}")
        raise

def lambda_handler(event, context):
    try:
        # GOOD: Get credentials from Secrets Manager
        db_creds = get_database_credentials()
        
        # GOOD: Don't log the actual secrets
        print("[INFO] Successfully retrieved database credentials from Secrets Manager")
        
        # GOOD: Only access specific bucket (from environment)
        app_bucket = os.environ.get('APP_BUCKET')
        response = s3.get_object(Bucket=app_bucket, Key='config.json')
        
        return {'statusCode': 200, 'body': 'Success'}
    except Exception as e:
        print(f"[ERROR] Lambda failed: {str(e)}")
        return {'statusCode': 500, 'body': 'Internal error'}