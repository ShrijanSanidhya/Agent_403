import vulnlib


def main() -> None:
    data = input()
    name = input()
    getattr(vulnlib, name)(data)
