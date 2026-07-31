"""`/ws/live` broadcaster. Each connection gets its own independent send
loop at the cadence in API_CONTRACT.md section 13: stats + connections
every 2s, log batched every 1s (max 200 entries, newest first), alerts on
change. Survives client disconnects (each connection is isolated; one
dropping doesn't affect others), and tolerates the frontend never sending
anything at all.
"""
from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from . import config
from .rules import engine as rules_engine
from .store import flows as flows_store
from .store import packets as packets_store
from .store import stats as stats_store

router = APIRouter()


@router.websocket("/ws/live")
async def ws_live(websocket: WebSocket) -> None:
    await websocket.accept()
    db_path = websocket.app.state.db_path

    stop_event = asyncio.Event()

    async def receiver() -> None:
        try:
            while True:
                await websocket.receive_text()
                # Frontend may send {"type":"subscribe",...}; we broadcast
                # everything regardless, so there's nothing to act on.
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            stop_event.set()

    async def sender() -> None:
        last_stats = 0.0
        last_conn = 0.0
        last_log = 0.0
        last_log_id = await asyncio.to_thread(packets_store.max_id, db_path)
        last_alert_seen: dict[str, str] = {}

        try:
            while not stop_event.is_set():
                now = time.time()

                if now - last_stats >= config.WS_STATS_INTERVAL_SECONDS:
                    data = await asyncio.to_thread(stats_store.get_summary, "5m", db_path)
                    await websocket.send_json({"type": "stats", "data": data})
                    last_stats = now

                if now - last_conn >= config.WS_CONNECTIONS_INTERVAL_SECONDS:
                    data = await asyncio.to_thread(flows_store.query_connections, db_path)
                    await websocket.send_json({"type": "connections", "data": data})
                    last_conn = now

                if now - last_log >= config.WS_LOG_INTERVAL_SECONDS:
                    entries, new_max = await asyncio.to_thread(
                        packets_store.query_since_id, last_log_id, config.WS_LOG_MAX_ENTRIES, db_path,
                    )
                    if entries:
                        await websocket.send_json({"type": "log", "data": list(reversed(entries))})
                        last_log_id = new_max
                    last_log = now

                recs = await asyncio.to_thread(rules_engine.list_recommendations, True, db_path)
                for r in recs:
                    if last_alert_seen.get(r["id"]) != r["last_seen"]:
                        await websocket.send_json({"type": "alert", "data": r})
                        last_alert_seen[r["id"]] = r["last_seen"]

                await asyncio.sleep(0.25)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            stop_event.set()

    await asyncio.gather(receiver(), sender(), return_exceptions=True)
