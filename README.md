# NetAudit

A local network auditing tool for Windows: live packet capture, traffic statistics,
a searchable traffic log, and concrete recommended actions based on what it sees.

Everything runs on your own machine against your own network. Nothing is uploaded.

## Layout

```
backend/    FastAPI service — capture engine, stats, log store, recommendation rules
frontend/   React + Vite dashboard
docs/       API_CONTRACT.md (frozen interface between the two)
```

## Capture tiers

The capture layer degrades gracefully depending on what the host allows:

| Tier | Requirement | What you get |
|---|---|---|
| `npcap` | [Npcap](https://npcap.com) installed + admin | Full packet headers, all protocols, both directions |
| `rawsocket` | Admin only | IPv4 packet headers via `SIO_RCVALL` promiscuous raw sockets |
| `polling` | Nothing | Connection-table deltas from `psutil` — flows and byte counts, no per-packet detail |

`GET /api/health` reports the active tier and why it fell back.

## Running

Backend:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m netaudit.server        # http://127.0.0.1:8787
```

Run that terminal **as Administrator** to get the `npcap` or `rawsocket` tiers.

Frontend:

```powershell
cd frontend
npm install
npm run dev                      # http://localhost:5173
```

## Scope note

This tool observes traffic on interfaces you own and reports on it. It does not
execute firewall changes, block traffic, or touch other machines beyond passive
observation and ARP-level discovery of devices already talking on your subnet.
Recommended actions are presented as copyable commands for you to run deliberately.
