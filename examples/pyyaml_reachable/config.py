import yaml


def load_config(path: str):
    with open(path, encoding="utf-8") as handle:
        return yaml.full_load(handle)
