import json

def awsJson( pName, pStr ):
    pJson = json.loads( pStr )

    pJson['name'] = pName
    pJson['cloud'] = 'AWS'
    pJson['domain'] = 'arn:aws'
    pJson['operator'] = 'OR'
    if 'Statement' in pJson:
        pJson['children'] = pJson.pop('Statement')

    for x in pJson['children']:
        if 'Sid' in x:
            x['name'] = x.pop('Sid')
        else:
            x['name'] = 'AWS statements'
        x['cloud'] = 'AWS'
        x['domain'] = 'arn:aws'
        x['operator'] = 'AND'
        conditions = {}
        if 'Resource' in x:
            conditions = {'Resource': x['Resource']}
        if 'Action' in x:
            conditions['Action'] = x['Action']
        if 'Noaction' in x:
            conditions['Noaction'] = x['Noaction']
        x['conditions'] = conditions

    #print(pJson)
    return pJson

AWSpolicyName = "https://us-east-1.console.aws.amazon.com/iam/home?region=us-east-1#/policies/arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess$jsonEditor"
AWSpolicyStr = '''
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "ec2:Describe*",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "elasticloadbalancing:Describe*",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:ListMetrics",
                "cloudwatch:GetMetricStatistics",
                "cloudwatch:Describe*"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "autoscaling:Describe*",
            "Resource": "*"
        }
    ]
}
'''
AWSpolicyStr1='''
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetResourcePolicy",
                "secretsmanager:GetSecretValue",
                "secretsmanager:DescribeSecret",
                "secretsmanager:ListSecretVersionIds"
            ],
            "Resource": "arn:aws:secretsmanager:us-east-1:279052253001:secret:pg_proguser-xrn7hy"
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": "secretsmanager:GetRandomPassword",
            "Resource": "*"
        }
    ]
}
'''