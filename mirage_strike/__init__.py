"""mirage-strike -- the MIRAGE attack framework.

One module per vulnerability class.  Each module exposes a callable that takes a
:class:`~mirage_strike.client.TargetClient` and returns a
:class:`~mirage_strike.client.ExploitResult`.  The same exploit code runs:

* against a live server (``python -m mirage_strike --target http://...``), and
* in-process against a FastAPI ``TestClient`` (the test-suite),

because the HTTP client is injected rather than hard-coded.
"""

from .client import ExploitResult, TargetClient
from .runner import ALL_MODULES, run_all

__all__ = ["ExploitResult", "TargetClient", "ALL_MODULES", "run_all"]
