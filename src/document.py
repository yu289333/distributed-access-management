"""JSON policy loading, independent of provider and database code."""
from copy import deepcopy
import json


def load_document(source):
    """Return an independent JSON object; reject duplicates and non-JSON values."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f'Duplicate JSON key: {key}')
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f'Invalid JSON constant: {value}')

    if isinstance(source, str):
        document = json.loads(source, object_pairs_hook=unique,
                              parse_constant=invalid_constant)
    else:
        document = deepcopy(source)
    if not isinstance(document, dict):
        raise ValueError('A policy document must be a JSON object')
    json.dumps(document, allow_nan=False)
    return document
