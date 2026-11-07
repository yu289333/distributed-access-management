import json
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def documents(filename):
    text = (ROOT / filename).read_text(encoding='utf-8')
    decoder = json.JSONDecoder()
    offset = 0
    while (start := text.find('{', offset)) != -1:
        document, length = decoder.raw_decode(text[start:])
        yield document
        offset = start + length


def walk(tree):
    yield tree
    for child in tree.get('children', []):
        yield from walk(child)


def evaluate(tree, predicate):
    if tree.get('condition_json') is not None:
        return predicate(tree['condition_json'])
    values = [evaluate(child, predicate) for child in tree['children']]
    if tree['operator'] == 'AND':
        return all(values)
    if tree['operator'] == 'OR':
        return any(values)
    if tree['operator'] == 'NOT':
        return not values[0]
    if tree['operator'] == 'XOR':
        return sum(values) % 2 == 1
    raise AssertionError(tree['operator'])


class RecordingCursor:
    def __init__(self):
        self.rows = []

    def execute(self, query, params):
        # Only identifier rendering requires a live libpq connection in psycopg2.
        with patch('psycopg2.extensions.quote_ident',
                   side_effect=lambda value, context: '"' + value.replace('"', '""') + '"'):
            query = query.as_string(None)
        self.rows.append({'query': query, 'params': [getattr(v, 'adapted', v) for v in params]})

    def fetchone(self):
        return (len(self.rows),)
