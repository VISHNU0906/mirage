"""MIRAGE -- a deliberately-vulnerable LLM-powered SaaS for security research.

WARNING: This application is INTENTIONALLY insecure by default. Run it only on
your own machine, never expose it to the internet.
"""

from .app import create_app
from .config import Config

__all__ = ["create_app", "Config"]
__version__ = "0.1.0"
