"""Local entry points. No provider connection or account configuration."""
from __future__ import annotations

import argparse
import json

from . import connector, provenance


def _main(module) -> int:
    parser = argparse.ArgumentParser(description=module.TOOL["description"])
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--example", action="store_true")
    action.add_argument("--schema", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        value = module.self_test()
    elif args.example:
        value = module.fixture()
    elif args.schema:
        value = module.INPUT_SCHEMA
    else:
        return module.serve()
    print(json.dumps(value, sort_keys=True, indent=2))
    return 0


def connector_main() -> int:
    return _main(connector)


def provenance_main() -> int:
    return _main(provenance)
