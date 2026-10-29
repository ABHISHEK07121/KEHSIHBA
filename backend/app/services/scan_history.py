import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "kesihba_scans.db"


def _db_path() -> Path:
    return Path(os.getenv("KESHIHBA_HISTORY_DB", DEFAULT_DB_PATH))


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            classification TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            threat_types TEXT NOT NULL,
            indicators TEXT NOT NULL,
            source_count INTEGER NOT NULL DEFAULT 0,
            user_id INTEGER
        )
        """
    )
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
    if "user_id" not in columns:
        connection.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER")
    connection.execute("CREATE INDEX IF NOT EXISTS scans_user_id_idx ON scans(user_id, id DESC)")
    return connection


def record_scan(
    scan_type: str,
    target: str,
    classification: str,
    risk_score: int,
    threat_types: list[str],
    indicators: list[str],
    source_count: int = 0,
    user_id: int | None = None,
) -> None:
    if user_id is None:
        return
    safe_target = target[:500]
    with closing(_connect()) as connection, connection:
        connection.execute(
            """
            INSERT INTO scans (
                created_at, scan_type, target, classification, risk_score,
                threat_types, indicators, source_count, user_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                scan_type,
                safe_target,
                classification,
                int(risk_score),
                json.dumps(threat_types),
                json.dumps(indicators[:20]),
                source_count,
                user_id,
            ),
        )


def _row_to_scan(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "scan_type": row["scan_type"],
        "target": row["target"],
        "classification": row["classification"],
        "risk_score": row["risk_score"],
        "threat_types": json.loads(row["threat_types"]),
        "indicators": json.loads(row["indicators"]),
        "source_count": row["source_count"],
    }


def list_scans(
    limit: int = 50,
    scan_type: str | None = None,
    classification: str | None = None,
    search: str | None = None,
    user_id: int | None = None,
) -> list[dict[str, Any]]:
    safe_limit = max(1, min(limit, 200))
    clauses: list[str] = ["user_id IS NULL"] if user_id is None else ["user_id = ?"]
    parameters: list[object] = []
    if user_id is not None:
        parameters.append(user_id)
    if scan_type:
        clauses.append("scan_type = ?")
        parameters.append(scan_type)
    if classification:
        clauses.append("lower(classification) = ?")
        parameters.append(classification.lower().replace("_", " "))
    if search and search.strip():
        clauses.append("(target LIKE ? OR indicators LIKE ?)")
        pattern = f"%{search.strip()[:200]}%"
        parameters.extend((pattern, pattern))
    where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    parameters.append(safe_limit)
    with closing(_connect()) as connection, connection:
        rows = connection.execute(
            f"SELECT * FROM scans {where_clause} ORDER BY id DESC LIMIT ?",
            parameters,
        ).fetchall()
    return [_row_to_scan(row) for row in rows]


def scan_summary(user_id: int | None = None) -> dict[str, Any]:
    scans = list_scans(200, user_id=user_id)
    counts = {"total": len(scans), "safe": 0, "suspicious": 0, "high_risk": 0, "malicious": 0, "unknown": 0}
    for scan in scans:
        key = scan["classification"].lower().replace(" ", "_")
        if key == "no_known_threat_detected":
            key = "safe"
        if key in counts:
            counts[key] += 1
    return {
        "counts": counts,
        "recent": [],
    }
