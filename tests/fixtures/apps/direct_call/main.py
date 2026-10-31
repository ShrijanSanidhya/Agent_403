import vulnlib


def main() -> None:
    data = input()
    vulnlib.unsafe_parse(data)
