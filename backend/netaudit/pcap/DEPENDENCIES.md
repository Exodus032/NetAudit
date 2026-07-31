# Dependencies -- `netaudit/pcap/`

**Nothing new is needed.** This package uses only the Python standard
library: `struct` (binary packing/unpacking for pcap/pcapng and synthesised
frame headers), `socket` (`inet_aton` for IPv4 literal parsing/validation in
`synth.py`), `ipaddress` (address/network validation and containment checks
in `bpf.py`), `sqlite3`, `threading`, `secrets`, `tempfile`, `pathlib`,
`dataclasses`, `re`.

Per the task instructions, the pcap reader and writer are hand-written
against the libpcap and pcapng file formats (`format.py`) rather than using
`scapy` or `dpkt` -- nothing was added to `requirements.txt`, and nothing
should be, for the parsing itself.

## One runtime dependency needed: `python-multipart`

E2 (`POST /api/capture/pcap/import`) is a `multipart/form-data` upload.
FastAPI's `UploadFile`/`File(...)` machinery requires the `python-multipart`
package to be installed to parse multipart bodies at all -- without it,
FastAPI raises `RuntimeError: Form data requires "python-multipart" to be
installed` at route-registration time (this is FastAPI's own dependency,
not something this package invented). It is not a pcap-parsing dependency;
it only lets Starlette pull the uploaded file's bytes out of the HTTP
request body so `pcap/router.py` can stream them to disk itself under the
200 MB cap (`import_pipeline.py` and `router.py`'s own chunked
`await file.read(...)` loop still do all the actual size-capping and
parsing by hand).

Installed into `backend/.venv` for this task's own test runs
(`pip install python-multipart`, resolved to `0.0.32`). **Not added to
`requirements.txt`** per the ownership rules -- the orchestrator needs to
add a line for it (e.g. `python-multipart==0.0.32  # required by FastAPI's
UploadFile/File for multipart uploads (pcap import, E2)`) when wiring this
router in, or `POST /api/capture/pcap/import` will fail to start.
