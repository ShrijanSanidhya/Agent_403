from vulnlib import unsafe_parse


def load(data: str) -> None:
    unsafe_parse(data)


def load_safe(data: str) -> None:
    import vulnlib

    return vulnlib.safe_parse(data)
