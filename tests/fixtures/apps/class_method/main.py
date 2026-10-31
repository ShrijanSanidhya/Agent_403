import vulnlib


def main() -> None:
    data = input()
    parser = vulnlib.Parser()
    parser.unsafe(data)
