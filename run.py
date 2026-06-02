"""Convenience launcher: ``python run.py`` (reads config from the environment).

Equivalent to::

    uvicorn mirage.app:app --host 0.0.0.0 --port 8000

but builds the app via the factory so MIRAGE_SECURE etc. are honoured.
"""

from __future__ import annotations

import os

import uvicorn

from mirage import Config, create_app

app = create_app(Config.from_env())


if __name__ == "__main__":
    host = os.environ.get("MIRAGE_HOST", "127.0.0.1")
    port = int(os.environ.get("MIRAGE_PORT", "8000"))
    mode = "SECURE (hardened)" if app.state.config.secure else "INSECURE (vulnerable)"
    print(f"[MIRAGE] starting in {mode} mode, provider={app.state.config.llm_provider}")
    print(f"[MIRAGE] chat UI:  http://{host}:{port}/")
    uvicorn.run(app, host=host, port=port)
