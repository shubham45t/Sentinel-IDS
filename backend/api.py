import asyncio
import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="DevSecOps IDS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "/app/logs/alerts.json")
BLOCKED_IPS_PATH = os.getenv("BLOCKED_IPS_PATH", "/app/logs/blocked_ips.json")
MAX_ALERTS_RESPONSE = int(os.getenv("MAX_ALERTS_RESPONSE", "500"))


def _safe_load_json_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def read_alerts(limit: int | None = None) -> list[dict[str, Any]]:
    if not os.path.exists(LOG_FILE_PATH):
        return []

    alerts: list[dict[str, Any]] = []
    try:
        with open(LOG_FILE_PATH, "r", encoding="utf-8") as file:
            for line in file:
                record = _safe_load_json_line(line)
                if record is not None:
                    alerts.append(record)
    except Exception as exc:
        print(f"Error reading log file: {exc}")
        return []

    if limit is not None and limit > 0:
        return alerts[-limit:]
    return alerts


def read_blocked_ips() -> list[str]:
    if not os.path.exists(BLOCKED_IPS_PATH):
        return []
    try:
        with open(BLOCKED_IPS_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)
        if isinstance(data, list):
            return sorted(str(ip) for ip in data)
    except Exception:
        pass
    return []


def build_stats(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts: dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    top_attackers: Counter[str] = Counter()
    timeline: defaultdict[str, int] = defaultdict(int)
    attack_types: Counter[str] = Counter()

    for alert in alerts:
        severity = str(alert.get("severity", "LOW")).upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        src_ip = alert.get("src_ip")
        if src_ip:
            top_attackers[str(src_ip)] += 1

        attack_type = alert.get("attack_type")
        if attack_type:
            attack_types[str(attack_type)] += 1

        timestamp = alert.get("timestamp")
        if isinstance(timestamp, str):
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                timeline[dt.strftime("%H:%M")] += 1
            except ValueError:
                pass

    return {
        "total_alerts": len(alerts),
        "severity_counts": severity_counts,
        "top_attackers": [
            {"ip": ip, "count": count}
            for ip, count in top_attackers.most_common(5)
        ],
        "timeline": [
            {"time": minute, "count": count}
            for minute, count in sorted(timeline.items())[-30:]
        ],
        "top_attack_types": [
            {"type": name, "count": count}
            for name, count in attack_types.most_common(5)
        ],
        "blocked_ips": read_blocked_ips(),
    }


@app.get("/")
def health_check() -> dict[str, str]:
    return {"status": "healthy"}


@app.get("/api/alerts")
def get_alerts() -> list[dict[str, Any]]:
    return read_alerts(limit=MAX_ALERTS_RESPONSE)


@app.get("/api/stats")
def get_stats() -> dict[str, Any]:
    return build_stats(read_alerts())


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket) -> None:
    await websocket.accept()

    last_pos = os.path.getsize(LOG_FILE_PATH) if os.path.exists(LOG_FILE_PATH) else 0

    try:
        while True:
            if os.path.exists(LOG_FILE_PATH):
                current_size = os.path.getsize(LOG_FILE_PATH)

                if current_size < last_pos:
                    last_pos = 0

                if current_size > last_pos:
                    with open(LOG_FILE_PATH, "r", encoding="utf-8") as file:
                        file.seek(last_pos)
                        new_data = file.read()
                        last_pos = file.tell()

                    lines = [line for line in new_data.splitlines() if line.strip()]
                    parsed_alerts = []
                    for line in lines:
                        alert = _safe_load_json_line(line)
                        if alert is not None:
                            parsed_alerts.append(alert)

                    if parsed_alerts:
                        stats = build_stats(read_alerts())
                        for index, alert in enumerate(parsed_alerts):
                            payload: dict[str, Any] = {
                                "type": "update",
                                "alert": alert,
                            }
                            if index == len(parsed_alerts) - 1:
                                payload["stats"] = stats
                            await websocket.send_json(payload)

            await asyncio.sleep(1)
    except WebSocketDisconnect:
        return
    except Exception as exc:
        print(f"WebSocket closed: {exc}")
