##### Importing Azure roles (equivalent to AWS policies)
#
import json

### parse an Action condition ########
def azParseRID(aRay):
  rJson = []
  for i, aStr in enumerate(aRay):
    rJson.append({})
    s1 = aStr.split('/')
    sLen = len(s1)
    if sLen>0:
      rJson[i]['service'] = s1[0].replace('Microsoft.', '')
      if s1[sLen-1]=='action' and sLen>3:
          rJson[i]['action'] = s1[sLen-2]
          --sLen
      else:
          rJson[i]['action'] = s1[sLen-1]
      if sLen>2:
         rJson[i]['component'] = s1[1]
         if sLen>3:
            for j in range(2,sLen-1):
               rJson[i]['component'] += '/'+s1[j]

  return rJson

### turn an Azure policy string pStr to a JSON variable with pName being the policy 'name' in the JSON ###########
def azJson( pName, pStr ):
    pJson = json.loads( pStr )

    #pJson['name'] = pName
    pJson['cloud'] = 'AZ'
    pJson['domain'] = 'Microsoft'
    pJson['operator'] = 'OR'
    if 'permissions' in pJson:
      pJson['children'] = []
      for x in pJson['permissions']:
        c = {}
        c['name'] = 'Azure permission'
        c['cloud'] = 'AZ'
        c['domain'] = 'Microsoft'
        c['operator'] = 'AND' ## really?
        c['children'] = []
        for k, v in x.items():
          if v: ## skip lines with empty value?
            s = {}
            s['name'] = 'Azure permission'
            s['cloud'] = 'AZ'
            s['domain'] = 'Microsoft'
            s['operator'] = 'AND'
            s['conditions'] = {}
            s['conditions'][k] = azParseRID(v)
            c['children'].append(s)
        pJson['children'].append(c)
      pJson.pop('permissions')
    return pJson

### Azure-AWS maps
serviceMap ='''
{
  "ClassicCompute": "ec2"
  "Compute": "ec2"
  "ClassicNetwork": "ec2"
  "ClassicStorage": "ec2"
}
'''
AZpolicyName = "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#classic-virtual-machine-contributor"
AZpolicyStr = '''
{
  "assignableScopes": [
    "/"
  ],
  "description": "Lets you manage classic virtual machines, but not access to them, and not the virtual network or storage account they're connected to.",
  "id": "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/d73bb868-a0df-4d4d-bd69-98a00b01fccb",
  "name": "d73bb868-a0df-4d4d-bd69-98a00b01fccb",
  "permissions": [
    {
      "actions": [
        "Microsoft.Authorization/*/read",
        "Microsoft.ClassicCompute/domainNames/*",
        "Microsoft.ClassicCompute/virtualMachines/*",
        "Microsoft.ClassicNetwork/networkSecurityGroups/join/action",
        "Microsoft.ClassicNetwork/reservedIps/link/action",
        "Microsoft.ClassicNetwork/reservedIps/read",
        "Microsoft.ClassicNetwork/virtualNetworks/join/action",
        "Microsoft.ClassicNetwork/virtualNetworks/read",
        "Microsoft.ClassicStorage/storageAccounts/disks/read",
        "Microsoft.ClassicStorage/storageAccounts/images/read",
        "Microsoft.ClassicStorage/storageAccounts/listKeys/action",
        "Microsoft.ClassicStorage/storageAccounts/read",
        "Microsoft.Insights/alertRules/*",
        "Microsoft.ResourceHealth/availabilityStatuses/read",
        "Microsoft.Resources/deployments/*",
        "Microsoft.Resources/subscriptions/resourceGroups/read",
        "Microsoft.Support/*"
      ],
      "notActions": [],
      "dataActions": [],
      "notDataActions": []
    }
  ],
  "roleName": "Classic Virtual Machine Contributor",
  "roleType": "BuiltInRole",
  "type": "Microsoft.Authorization/roleDefinitions"
}
'''
AZpolicyStr1 ='''
{
  "assignableScopes": [
    "/"
  ],
  "description": "Allow read, write and delete access to Azure Spring Cloud Service Registry",
  "id": "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/f5880b48-c26d-48be-b172-7927bfa1c8f1",
  "name": "f5880b48-c26d-48be-b172-7927bfa1c8f1",
  "permissions": [
    {
      "actions": [],
      "notActions": [],
      "dataActions": [
        "Microsoft.AppPlatform/Spring/eurekaService/read",
        "Microsoft.AppPlatform/Spring/eurekaService/write",
        "Microsoft.AppPlatform/Spring/eurekaService/delete"
      ],
      "notDataActions": []
    }
  ],
  "roleName": "Azure Spring Cloud Service Registry Contributor",
  "roleType": "BuiltInRole",
  "type": "Microsoft.Authorization/roleDefinitions"
}
'''