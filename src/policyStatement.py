"""Provider-neutral policy statements used by the morph engine.

A source adapter reads its policy and returns statements in this shape. Action
strings stay provider-specific at this point: the engine decodes them with the
source's decoder, so a source adapter does not need to know the neutral
vocabulary. ``untranslated`` carries fields the source could not express (for
AWS: ``NotAction``, ``NotResource``, ``Principal``) so the engine reports them
instead of dropping them.
"""

EFFECTS = ('allow', 'deny')


def make_statement(effect, actions=(), resources=(), conditions=(), untranslated=()):
    """Build a neutral statement; validate the effect."""
    if effect not in EFFECTS:
        raise ValueError(f'Effect must be one of {EFFECTS}')
    return {
        'effect': effect,
        'actions': list(actions),
        'resources': list(resources),
        'conditions': list(conditions),
        'untranslated': [tuple(item) for item in untranslated],
    }
