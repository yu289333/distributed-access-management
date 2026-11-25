"""Compatibility entry point for src.providers.azure.emitter."""

if not __package__:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.providers.azure.emitter import emit_policy, emit_azure, main


if __name__ == '__main__':
    raise SystemExit(main())
