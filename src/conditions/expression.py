"""Select the provider CEL converter and expose the shared API."""
from . import cel
from ..providers.aws.cel import aws
from ..providers.azure.cel import azure


_TRANSLATORS = {'AWS': aws, 'Azure': azure}


def condition_to_cel(condition_json=None, condition_raw=None, *, provider,
                     provider_detail=None, condition_raw_type=None):
    return cel.condition_to_cel(
        condition_json, condition_raw, condition_raw_type=condition_raw_type,
        translate=_TRANSLATORS.get(provider), provider=provider, provider_detail=provider_detail)


def populate_condition_cel(tree):
    return cel.populate_condition_cel(tree, translate=_TRANSLATORS.get(tree['provider']))
