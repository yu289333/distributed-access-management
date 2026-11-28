"""Shared expression formatting and legacy activation helpers."""
import json


def literal(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False)


def join(parts, op='&&'):
    parts = list(parts)
    return ('(' + f' {op} '.join(f'({p})' for p in parts) + ')'
            if parts else ('true' if op == '&&' else 'false'))


def regex_escape(value):
    return ''.join('\\' + c if c in r'\.^$|?*+()[]{}' else c for c in value)


def cel_activation(request, context=None, fields=None, resource=None):
    """Inputs for CEL, including regex-safe IAM policy variable substitution.

    Do not accept regex_context directly from an untrusted caller.
    """
    context = dict(context or {})
    return dict(request=dict(request), context=context, fields=dict(fields or {}),
                resource=dict(resource or {}),
                regex_context={k: regex_escape(v) for k, v in context.items()
                               if isinstance(v, str)})
