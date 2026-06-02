# MIRAGE Architecture

MIRAGE has three parts:

1. **The app** (`mirage/`) — a FastAPI LLM-powered document-assistant SaaS.
2. **The attack framework** (`mirage_strike/`) — exploits the app and reports.
3. **Hardened mode** — the same app with every fix switched on (`MIRAGE_SECURE`).

```
                          ┌──────────────────────────────────────────────┐
                          │                  MIRAGE app                   │
                          │                                               │
  Browser ── chat UI ───► │  FastAPI (mirage/app.py)                      │
  (templates/chat.html)   │   ├─ /register /login /oauth   (auth.py, JWT) │
                          │   ├─ /chat ───► Agent (agent.py)              │
                          │   │              ├─ build context w/ provenance│
                          │   │              ├─ LLM provider (llm/*)       │
                          │   │              │    mock | gemini | openai   │
                          │   │              └─ tools (tools.py):          │
  mirage_strike ───HTTP──►│   │                   web_fetch  (SSRF)        │
  (requests OR            │   │                   doc_search (RAG/BOLA)    │
   in-proc TestClient)    │   │                   send_email (agency)     │
                          │   │                   db_query   (agency)     │
                          │   ├─ /docs (upload/read)        (BOLA)         │
                          │   └─ /profile (GET/PUT)         (mass assign)  │
                          │                                               │
                          │  SQLite (db.py): users, documents, messages,  │
                          │                  email_log                     │
                          └──────────────────────────────────────────────┘
```

## Components

### `mirage/config.py`
One `Config` dataclass per app instance. The `secure` flag is read **at app
construction** (`create_app`), never at import — that is what lets the test
suite build an insecure and a secure app side-by-side in one process and assert
the same exploit succeeds against one and is blocked by the other.

### `mirage/app.py` — the app factory
`create_app(config)` wires endpoints, the JWT auth dependency, and the chat UI.
Every vulnerability's insecure/secure behaviour is gated on `config.secure`,
with the fix living in its **real layer** (an HTTP-layer authz check, output
encoding, an SSRF guard) rather than in the model.

### `mirage/llm/` — provider abstraction
- `base.py` — `LLMMessage` (with a `source`/provenance tag), `ToolCall`,
  `LLMResult`, and the `LLMProvider` interface.
- `mock.py` — a deterministic, offline instruction-follower. It parses
  `[[tool:...]]` directives and obeys in-context instructions, which is what
  makes injection/agency vulnerabilities emergent and real. In secure mode it
  honours provenance (ignores directives from `document`/`tool` text) and a
  hardened system prompt.
- `gemini.py`, `openai.py` — real adapters, **lazily imported** so mock mode
  never needs an SDK or API key.

### `mirage/agent.py` — the tool-using agent
Builds the model context (system prompt + retrieved documents + user message),
runs a bounded tool loop, dispatches tool calls, and feeds results back. It tags
each context block's provenance so secure mode can quarantine untrusted text.

### `mirage/tools.py`
The four agent tools, each with insecure and hardened behaviour. The SSRF guard
(`_ssrf_guard`) resolves a hostname and blocks any private/loopback/link-local
address — the resolve-then-pin pattern. RAG ranking is a lightweight TF-IDF
(`_rank_documents`); real embeddings are a roadmap item.

### `mirage/db.py`
Stdlib `sqlite3` (zero external dependency). `:memory:` databases give each app
instance / test full isolation.

### `mirage_strike/`
- `client.py` — `TargetClient` wraps either a live `requests` session **or** an
  in-process FastAPI `TestClient`, behind one interface. The HTTP client is
  **injected**, so the exact same exploit code runs from the CLI (`make attack`)
  and from the test suite.
- `modules/*.py` — one exploit per vulnerability class; each returns an
  `ExploitResult(success, severity, evidence, ...)`.
- `runner.py` — runs every module; `report.py` emits Markdown + SARIF v2.1.0.
- `__main__.py` — the `python -m mirage_strike --target URL` CLI.

## Data / trust-boundary flow (the interview whiteboard)

```
input (user msg | RAG doc | tool output)
        │  all of it is just text to the model
        ▼
   model context  ◄── system prompt sits in the SAME channel
        │
        ▼
      LLM  ── emits ──►  tool call  ── runs with the APP's privileges ──►  effect
        ▲                                                                   │
        └──────────────────────  tool output fed back  ─────────────────────┘
```

The whole class of LLM vulnerabilities follows from this picture: there is no
hard boundary between data and instructions inside the context, so control of
any in-context text is control of the model — and through its tools, the app.

## Test strategy

- `tests/test_auth.py` — auth + endpoint sanity (both modes).
- `tests/test_vulns.py` — for every vuln: **succeeds insecure / blocked secure**,
  driven by the real strike modules against an in-process app.
- `tests/test_guards_and_report.py` — SSRF IP classification, tenant isolation,
  RAG ranking, and SARIF/Markdown report validity.

All tests run **offline in mock mode** — no API key, no network.

## Roadmap

- Real vector embeddings for RAG (currently TF-IDF keyword ranking).
- Next.js frontend + admin panel (the bundled single-page UI is enough to demo).
- More LLM providers; per-user rate limiting; Postgres + pgvector (compose has a
  `postgres` profile scaffolded).
- Dual-LLM / quarantined-evaluator pattern for stronger indirect-injection
  defense.
