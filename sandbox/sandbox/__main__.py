"""Entrypoint: ``python -m sandbox``."""
import asyncio

from .app import run

if __name__ == "__main__":
    asyncio.run(run())
