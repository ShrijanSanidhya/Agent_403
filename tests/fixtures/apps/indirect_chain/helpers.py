import vulnlib


def process(data: str) -> None:
    vulnlib.unsafe_parse(data)
