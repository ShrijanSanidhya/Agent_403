import vulnlib


def main() -> None:
    items = input().split()
    list(map(vulnlib.unsafe_parse, items))
