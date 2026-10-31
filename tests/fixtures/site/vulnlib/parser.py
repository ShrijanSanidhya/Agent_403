def _decode(data: str) -> str:
    return data


def unsafe_parse(data: str) -> str:
    return _decode(data)


def safe_parse(data: str) -> str:
    return data


class Parser:
    def unsafe(self, data: str) -> str:
        return unsafe_parse(data)

    def safe(self, data: str) -> str:
        return safe_parse(data)
