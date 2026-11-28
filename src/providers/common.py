"""Small helpers shared by the provider emitters."""
import json


def check_provider(tree, provider):
    """Reject a tree whose nodes do not all belong to ``provider``."""
    pending = [tree]
    while pending:
        node = pending.pop()
        if node.get('provider') != provider:
            raise ValueError(
                f'emit_policy requires a tree whose nodes all have provider {provider}')
        pending.extend(node.get('children', []))


def read_raw(tree):
    """Return the root's raw document, or an empty object when it is unusable."""
    raw = tree.get('condition_raw')
    if not raw:
        return {}
    try:
        document = json.loads(raw)
    except ValueError:
        return {}
    return document if isinstance(document, dict) else {}
