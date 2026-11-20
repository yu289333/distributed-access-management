"""Format-aware conversion of original conditions into expression output."""
from .awsCondition import aws
from .azureCondition import azure


def condition_to_cel(condition_json=None, condition_raw=None, *, provider, provider_detail=None, condition_origin=None):
    from .conditionSource import normalize_condition
    condition_json, native = normalize_condition(condition_json, condition_raw, condition_origin)
    if native is not None:
        return native
    if provider == 'AWS':
        return aws(condition_json)
    if provider == 'Azure':
        return azure(condition_json, provider_detail)
    raise ValueError(f'Unsupported provider: {provider}')


def populate_condition_cel(tree):
    """Fill expression leaves and empty-set constants; annotate unsupported syntax."""
    if tree['children']:
        for child in tree['children']:
            populate_condition_cel(child)
    elif tree['condition_json'] is None and not tree['condition_raw']:
        tree['condition_cel'] = 'false' if tree['operator'] in ('OR', 'XOR') else 'true'
    else:
        try:
            from .conditionSource import normalize_condition
            expression, native = normalize_condition(
                tree['condition_json'], tree['condition_raw'], tree.get('condition_origin'))
            tree['condition_cel'] = condition_to_cel(
                tree['condition_json'], tree['condition_raw'], provider=tree['provider'],
                provider_detail=tree['provider_detail'], condition_origin=tree.get('condition_origin'))
            if expression is not None:
                tree['condition_json'] = expression
                if tree.get('condition_origin') is None:
                    tree['condition_origin'] = 'json'
        except ValueError as exc:
            tree['condition_cel'] = None
            note = f'CEL conversion unavailable: {exc}'
            if note not in (tree['comment'] or ''):
                tree['comment'] = '\n'.join(filter(None, [tree['comment'], note]))
    return tree
