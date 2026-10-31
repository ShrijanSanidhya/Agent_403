import sys

import yaml


def main() -> None:
    loader_name = sys.argv[1]
    with open(sys.argv[2], encoding="utf-8") as handle:
        getattr(yaml, loader_name)(handle)
