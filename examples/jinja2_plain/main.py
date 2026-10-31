from jinja2 import Template


def main() -> str:
    template = Template("Hello {{ name }}")
    return template.render(name="world")
