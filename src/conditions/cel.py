"""Optional CEL enrichment using a caller-supplied provider translation."""
from .source import normalize_condition


def condition_to_cel(condition_json=None, condition_raw=None, *,
                     condition_raw_type=None, translate=None, provider=None,
                     provider_detail=None):
    expression, native = normalize_condition(condition_json, condition_raw, condition_raw_type)
    if native is not None:
        return native
    if translate is None:
        raise ValueError(f'Unsupported provider: {provider}')
    return translate(expression, provider_detail)


def populate_condition_cel(tree, *, translate=None):
    """Fill expression leaves and constants, retaining unsupported sources."""
    if tree['children']:
        for child in tree['children']:
            populate_condition_cel(child, translate=translate)
    elif tree['condition_json'] is None and not tree['condition_raw']:
        tree['condition_cel'] = 'false' if tree['operator_onChildren'] == 'OR' else 'true'
    else:
        try:
            raw_type = tree.get('condition_raw_type')
            expression, native = normalize_condition(tree['condition_json'], tree['condition_raw'], raw_type)
            if native is not None:
                tree['condition_cel'] = native
            elif translate is None:
                raise ValueError(f'Unsupported provider: {tree["provider"]}')
            else:
                tree['condition_cel'] = translate(expression, tree['provider_detail'])
                if raw_type in (None, 'json'):
                    tree['condition_json'] = expression
                    tree['condition_raw_type'] = 'json'
        except ValueError as exc:
            tree['condition_cel'] = None
            note = f'CEL conversion unavailable: {exc}'
            if note not in (tree['comment'] or ''):
                tree['comment'] = '\n'.join(filter(None, [tree['comment'], note]))
    return tree
