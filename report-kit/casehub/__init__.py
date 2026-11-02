"""casehub: correlation layer over an report.py case.

report.py remains the only writer of evidence (case.json, transcripts, screenshots,
scripts, build artifacts). casehub keeps an append-only record ledger in
`<case>/casehub.db` (SQLite, WAL) for everything that is *about* that evidence:
observations, entities, edges, claims, tasks, handoffs, heartbeats, and epochs.
Every record cites evidence event IDs; projections are rebuildable from records.
"""

from .ledger import CaseHub, CaseHubError  # noqa: F401

__all__ = ["CaseHub", "CaseHubError"]
__version__ = "0.1.0"
