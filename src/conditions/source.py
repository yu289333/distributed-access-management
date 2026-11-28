"""Original condition text and explicit serialization-format handling.

Provider identifies policy language; condition_raw_type identifies serialization.
JSON raw text may be an object or an exact object-member fragment from the input.
"""
import json
from ..document import load_document


def decode_json_condition(raw):
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError('Raw JSON condition must be nonempty text')
    try:
        return load_document(raw)
    except (ValueError, TypeError):
        # Parsers retain exact member fragments, including key and punctuation.
        return load_document('{' + raw + '}')


_FORMAT_READERS = {'json': decode_json_condition}


def register_condition_format(name, reader):
    """Register an explicit future-format adapter returning a condition object."""
    if not isinstance(name, str) or not name or name in _FORMAT_READERS or name == 'cel':
        raise ValueError('Format must be a new nonempty name')
    _FORMAT_READERS[name] = reader


def normalize_condition(condition_json, condition_raw, condition_raw_type=None):
    origin = condition_raw_type
    if origin is None:
        # Compatibility: only infer JSON from actual JSON data, never provider.
        if condition_json is not None:
            origin = 'json'
        elif condition_raw:
            decode_json_condition(condition_raw)
            origin = 'json'
        else:
            raise ValueError('No condition source')
    if origin == 'cel':
        if condition_json is not None or not isinstance(condition_raw, str) or not condition_raw.strip():
            raise ValueError('Native CEL requires raw text and no JSON without a registered translation')
        return None, condition_raw
    if origin not in _FORMAT_READERS:
        raise ValueError(f'Unsupported condition_raw_type: {origin}; register a format adapter')
    decoded = _FORMAT_READERS[origin](condition_raw) if condition_raw is not None else None
    if condition_json is not None and decoded is not None:
        if canonical(condition_json) != canonical(decoded):
            raise ValueError('condition_raw and condition_json describe different conditions')
    expression = condition_json if condition_json is not None else decoded
    if not isinstance(expression, dict) or not expression:
        raise ValueError('Condition must be a nonempty object')
    return expression, None


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)


def json_source_fragments(text):
    """Index exact input object/member spans by their normalized JSON content."""
    fragments = {}
    decoder = json.JSONDecoder()

    def whitespace(position):
        while position < len(text) and text[position].isspace():
            position += 1
        return position

    def visit(position):
        start = position = whitespace(position)
        if text[position] == '{':
            result = {}
            position = whitespace(position + 1)
            while text[position] != '}':
                member_start = position
                key, position = decoder.raw_decode(text, position)
                position = whitespace(position)
                assert text[position] == ':'
                value, position = visit(position + 1)
                result[key] = value
                fragments.setdefault(canonical({key: value}), text[member_start:position])
                position = whitespace(position)
                if text[position] == ',':
                    position = whitespace(position + 1)
                else:
                    break
            position += 1
            fragments[canonical(result)] = text[start:position]
            return result, position
        if text[position] == '[':
            result = []
            position = whitespace(position + 1)
            while text[position] != ']':
                value, position = visit(position)
                result.append(value)
                position = whitespace(position)
                if text[position] == ',':
                    position = whitespace(position + 1)
                else:
                    break
            return result, position + 1
        return decoder.raw_decode(text, position)

    load_document(text)  # Validate duplicates, nonfinite values and full document first.
    visit(0)
    return fragments


def attach_json_source(tree, source):
    """Replace synthesized raw text with exact input spans wherever available.

    A dict has no original textual representation: do not invent raw leaf text.
    Transformed leaves with no matching input fragment likewise leave raw NULL.
    """
    fragments = json_source_fragments(source) if isinstance(source, str) else {}

    def visit(node, root=False):
        expression = node.get('condition_json')
        if expression is not None:
            node['condition_raw_type'] = 'json'
            node['condition_raw'] = fragments.get(canonical(expression))
        elif node.get('condition_raw') is not None:
            if root:
                node['condition_raw_type'] = 'json'
            elif isinstance(source, str):
                old = decode_json_condition(node['condition_raw'])
                node['condition_raw'] = fragments.get(canonical(old))
                node['condition_raw_type'] = 'json' if node['condition_raw'] else None
            else:
                # Object input has no lexical text; this is its canonical JSON serialization.
                node['condition_raw_type'] = 'json'
        for child in node['children']:
            visit(child)
    visit(tree, True)
    return tree
