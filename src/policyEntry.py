#import boto3
#from botocore.exceptions import ClientError
import psycopg2
import json
import azureEntry
import awsEntry
from policyJson import reduceJson, update_kJson, reducePolicy

def get_secret():
    secret = '{ "host":"test-dev.cxinsaq0qdf9.us-east-1.rds.amazonaws.com",'\
     +'"database":"jsonPolicies", "username":"proguser", "password":"abc123" }'
    return json.loads(secret)


def insertPolicy(db_cur, db_table, parent_id, pJson):
    insertStr = 'insert into '+db_table+'(parent, name, cloud, domain, operator)'+\
    ' values (%s, %s, %s, %s, %s) returning id'

    db_cur.execute(insertStr, (parent_id, pJson['name'], pJson['cloud'], pJson['domain'], pJson['operator']))
    cur_id = db_cur.fetchone()[0]

    if 'conditions' in pJson:
        updateCond = 'update '+db_table+' set conditions = %s where id = %s'
        db_cur.execute(updateCond, (json.dumps(pJson['conditions']), cur_id))

    if 'children' in pJson:
        for childPolicy in pJson['children']:
            insertPolicy(db_cur, db_table, cur_id, childPolicy)

def replaceValues(aIn, fromStr, toStr):
    if isinstance(aIn, list):
        for i, v in enumerate(aIn):
            if isinstance(v, str):
                if v.startswith(fromStr):
                    aIn[i] = v.replace(fromStr, toStr, 1)
            elif isinstance(v, list) or isinstance(x, dict):
                replaceValues(aIn[i], fromStr, toStr)
    if isinstance(aIn, dict):
        for k, v in aIn.items():
            if isinstance(v, str):
                if v.startswith(fromStr):
                    aIn[k] = v.replace(fromStr, toStr, 1)
            elif isinstance(v, list) or isinstance(v, dict):
                replaceValues(aIn[k], fromStr, toStr)
                

def az2awsTranslate(aJson):
    if 'children' in aJson:
        for c in aJson['children']:
            az2awsTranslate(c)
    if 'conditions' in aJson:
        replaceValues(aJson['conditions'], 'Microsoft.', '')
        replaceValues(aJson['conditions'], 'ClassicCompute/', 'ec2:')
    

################################3
policyJson = azureEntry.azJson(azureEntry.AZpolicyName, azureEntry.AZpolicyStr)
print( json.dumps(policyJson, indent=2) )
#policyJson = awsEntry.awsJson(awsEntry.AWSpolicyName, awsEntry.AWSpolicyStr)
#az2awsTranslate(policyJson)
#print( json.dumps(policyJson, indent=2) )
reducePolicy(policyJson)
print( json.dumps(policyJson, indent=2) )
'''
db_name = 'jsonPolicies'
db_table = 'policy'

db_info = get_secret()
db_conn = psycopg2.connect(user=db_info['username'],
    password = db_info['password'], host = db_info['host'],
    database = db_name)
db_cursor = db_conn.cursor()

insertPolicy(db_cursor, db_table, None, policyJson)

db_cursor.close()
db_conn.commit()
'''