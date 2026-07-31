# Dependencies

None beyond what the backend already installs (`fastapi`, `pydantic`,
standard library `socket`/`ipaddress`/`threading`/`secrets`). The real
connector (`providers.RealPortConnector`) uses a plain `socket.socket(...)`
TCP connect -- no `scapy`, no raw sockets, no third-party scanning library.
