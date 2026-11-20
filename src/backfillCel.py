"""Deprecated compatibility entry point; use python -m src.convertConditions."""
from .convertConditions import convert_conditions as backfill, main

if __name__ == "__main__":
    main()
