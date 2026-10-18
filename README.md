# PathLens (starter MVP)

Deterministic, offline analysis of **synthetic** Active Directory-style relationship graphs.
This prototype does **not** import BloodHound exports yet and does not establish exploitability.

## Run

Requires Python 3.11+.

```bash
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\pathlens.exe analyze --input data/sample_domain.json --source ICHYABOY --target "DOMAIN ADMINS"
.\.venv\Scripts\python.exe -m pytest -q
```

For Linux/macOS, activate `.venv/bin/activate` and run the same `pip`, `pathlens`, and `pytest` commands.

## Limitations
- Only a custom JSON graph schema is supported.
- The shortest path minimizes graph hops, not exploit difficulty.
- Multiple parallel edges are stored, but the CLI explains only the first edge between each pair.
- Only four relationship types have preliminary explanatory text.
- Graph relationships do not prove practical exploitability.
- Do not upload or publish real customer directory data.
