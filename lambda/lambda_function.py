import boto3
from botocore.exceptions import ClientError
import psycopg2
import json

def lambda_handler(event, context):
    print('hello')
    db_info = get_secret()
    print('secret')
    print( db_info )
    db_conn = psycopg2.connect( user=db_info['username'],
    password = db_info['password'], host = db_info['host'],
    database = 'jsonPolicies' )
    
    db_cursor = db_conn.cursor()
    db_query = "SELECT version() AS version"
    db_cursor.execute(db_query)
    db_results = db_cursor.fecthone()
    db_cusor.close()
    db_conn.commit()
    
    return {
        'statusCode': 200,
        'body': db_results
    }

def get_secret():

    secret_name = "pg_proguser"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    print('get s1')

    try:
        get_secret_value_response = client.get_secret_value( SecretId=secret_name )
        print('get s2')
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        print('get se')
        raise e

    # Decrypts secret using the associated KMS key.
    print('get s32')
    secret = json.loads( get_secret_value_response['SecretString'] )
    print('get s3')
    return secret