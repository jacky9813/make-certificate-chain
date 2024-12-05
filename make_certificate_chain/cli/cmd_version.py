from .cli import cli
import importlib.metadata

@cli.command()
def version():
    "Shows current program version"
    print(importlib.metadata.version("make_certificate_chain"))
