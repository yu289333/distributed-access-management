import json

def reduceJson(aJson):
    rJson={}
    for k, v in aJson.items():
        if isinstance(v, dict):
            c = reduceJson(v)
            if c:
                rJson[k] = c            
        elif v:
            rJson[k] = v
    return rJson

### update aJson's value of k with bJson
def update_kJson(aJson, k, bJson):
    if k in aJson:
        aJson[k].update(bJson)
    elif bJson:
        aJson[k] = bJson

### iterate over policy JSON pJson to reduce the level of operators
def reducePolicy(pJson):
    reducedCond = {}
    reducedChild = []
    ## if a child hasthe same set operator as the parent pJson, combine it with pJson
    if 'children' in pJson:
        for c in pJson['children']:
            reducePolicy(c)
            if c['operator'] == pJson['operator']:
                if 'conditions' in c:
                    reducedCond.update(c['conditions'])
                if 'children' in c:
                    reducedChild.append(c['children'])
                del c
        pJson['children'] += reducedChild
    update_kJson(pJson, 'conditions', reducedCond)

    ## remove empty conditions? shouldn't
    #if 'conditions' in pJson:
    #    pJson['conditions'] = reduceJson(pJson['conditions'])

    if 'children' in pJson:
        if len(pJson['children'])==1:
            if 'children' not in pJson['children'][0]:
                if 'conditions' in pJson['children'][0]:
                    if len(pJson['children'][0]['conditions'])==1:
                        update_kJson(pJson, 'conditions', pJson['children'][0]['conditions'])
                        del pJson['children']
            elif len(pJson['children'][0]['children'])==1:
                if 'conditions' not in pJson['children'][0]:
                    pJson['children'] = pJson['children'][0]['children']