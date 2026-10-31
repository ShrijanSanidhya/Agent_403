from jinja2.sandbox import SandboxedEnvironment


def main(source: str) -> str:
    environment = SandboxedEnvironment()
    return environment.from_string(source).render()
