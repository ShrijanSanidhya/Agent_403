import yaml


def load_with_loader(path: str) -> None:
    with open(path, encoding="utf-8") as handle:
        yaml.load(handle, Loader=yaml.FullLoader)


def read_single(stream: object) -> None:
    yaml.FullLoader(stream).get_single_data()
