"""审计存储：SQLite 单表有序链 + 尾状态 + 独立尾锚。"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import zipfile
from pathlib import Path
from typing import Any, Iterator

from ..errors import AuditError
from ..utils import canonical_json, utc_now_iso
from .chain import (
    GENESIS,
    AnchorState,
    ChainRecord,
    Keyring,
    VerifyResult,
    read_anchor,
    write_anchor,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_records (
    seq         INTEGER PRIMARY KEY,
    ts          TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    session_id  TEXT,
    action      TEXT,
    tool        TEXT,
    payload     TEXT    NOT NULL,
    prev        TEXT    NOT NULL,
    current     TEXT    NOT NULL,
    key_id      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_records_session ON audit_records(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_records_kind ON audit_records(kind, seq);
CREATE INDEX IF NOT EXISTS idx_records_action ON audit_records(action, seq);

CREATE TABLE IF NOT EXISTS chain_tail (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    chain_tail  TEXT    NOT NULL,
    tail_count  INTEGER NOT NULL,
    hmac_tail   TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class AuditStore:
    """只追加（append-only）的审计库。

    所有写操作串行化；读取与校验可并发。写使用 ``BEGIN IMMEDIATE`` 保证
    跨进程也不会出现序号冲突（SQLite 会串行化写事务）。
    """

    def __init__(
        self,
        db_path: str | Path = "var/agentjudge.db",
        keyring: Keyring | None = None,
        *,
        anchor_path: str | Path | None = "var/tail.anchor",
        seal_interval_s: int = 300,
    ) -> None:
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=8000")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.RLock()
        self.keyring = keyring or Keyring.from_env_or_file(key_file="var/hmac.key")
        self.anchor_path = str(anchor_path) if anchor_path else None
        self.seal_interval_s = int(seal_interval_s)
        self._last_seal = 0.0
        self._init()

    # -- 初始化 -----------------------------------------------------------
    def _init(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA)
            row = self._conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO meta(key, value) VALUES('schema_version', ?)", ("1",)
                )
            row = self._conn.execute("SELECT tail_count FROM chain_tail WHERE id=1").fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO chain_tail(id, chain_tail, tail_count, hmac_tail, updated_at)"
                    " VALUES(1, ?, 0, ?, ?)",
                    (GENESIS, self.keyring.hmac_tail(GENESIS, 0), utc_now_iso()),
                )

    # -- 写入 -------------------------------------------------------------
    def append(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        session_id: str | None = None,
        action: str | None = None,
        tool: str | None = None,
    ) -> ChainRecord:
        if not isinstance(payload, dict):
            payload = {"value": payload}
        payload = _jsonable(payload)
        with self._lock:
            conn = self._conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT chain_tail, tail_count FROM chain_tail WHERE id=1").fetchone()
                prev = row["chain_tail"] if row else GENESIS
                seq = (row["tail_count"] if row else 0) + 1
                ts = utc_now_iso()
                current = self.keyring.sign(seq=seq, ts=ts, kind=kind, payload=payload, prev=prev)
                conn.execute(
                    "INSERT INTO audit_records(seq, ts, kind, session_id, action, tool, payload, prev, current, key_id)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (seq, ts, kind, session_id, action, tool, canonical_json(payload), prev, current, self.keyring.key_id),
                )
                conn.execute(
                    "UPDATE chain_tail SET chain_tail=?, tail_count=?, hmac_tail=?, updated_at=? WHERE id=1",
                    (current, seq, self.keyring.hmac_tail(current, seq), ts),
                )
                conn.execute("COMMIT")
            except Exception as exc:  # noqa: BLE001 - 任何失败都不能留下半条链
                conn.execute("ROLLBACK")
                raise AuditError(f"审计写入失败: {exc}") from exc
        record = ChainRecord(
            seq=seq,
            ts=ts,
            kind=kind,
            payload=payload,
            prev=prev,
            current=current,
            key_id=self.keyring.key_id,
            session_id=session_id,
            action=action,
            tool=tool,
        )
        self._maybe_seal()
        return record

    # -- 读取 -------------------------------------------------------------
    def tail(self) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM chain_tail WHERE id=1").fetchone()
        return dict(row) if row else {"chain_tail": GENESIS, "tail_count": 0, "hmac_tail": "", "updated_at": ""}

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM audit_records").fetchone()
        return int(row["c"]) if row else 0

    def get(self, seq: int) -> ChainRecord | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM audit_records WHERE seq=?", (seq,)).fetchone()
        return _row_to_record(row) if row else None

    def records(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        session_id: str | None = None,
        kind: str | None = None,
        descending: bool = True,
    ) -> list[ChainRecord]:
        sql = "SELECT * FROM audit_records WHERE 1=1"
        params: list[Any] = []
        if session_id:
            sql += " AND session_id=?"
            params.append(session_id)
        if kind:
            sql += " AND kind=?"
            params.append(kind)
        sql += f" ORDER BY seq {'DESC' if descending else 'ASC'} LIMIT ? OFFSET ?"
        params.extend([max(1, min(limit, 1000)), max(0, offset)])
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_record(r) for r in rows]

    def iter_records(self, *, ascending: bool = True) -> Iterator[ChainRecord]:
        sql = f"SELECT * FROM audit_records ORDER BY seq {'ASC' if ascending else 'DESC'}"
        with self._lock:
            cursor = self._conn.execute(sql)
            while True:
                row = cursor.fetchone()
                if row is None:
                    break
                yield _row_to_record(row)

    def session_records(self, session_id: str, limit: int = 500) -> list[ChainRecord]:
        return self.records(session_id=session_id, limit=limit, descending=False)

    # -- 校验 -------------------------------------------------------------
    def verify(self) -> VerifyResult:
        rows = list(self.iter_records())
        result = VerifyResult(ok=True, records=len(rows), key_id=self.keyring.key_id)
        prev = GENESIS
        for expected, row in enumerate(rows, 1):
            if row.seq != expected:
                return _fail(result, "sequence_gap", row.seq, f"期望序号 {expected}，实际 {row.seq}（记录被删/插入）")
            if row.prev != prev:
                return _fail(result, "link_mismatch", row.seq, f"记录 #{row.seq} 的 prev 与上一条指纹不匹配")
            try:
                payload = row.payload if isinstance(row.payload, dict) else json.loads(row.payload)
            except json.JSONDecodeError:
                return _fail(result, "payload_corrupt", row.seq, f"记录 #{row.seq} 的 payload 不是合法 JSON")
            recomputed = self.keyring.sign(
                seq=row.seq,
                ts=row.ts,
                kind=row.kind,
                payload=payload,
                prev=row.prev,
                key_id=row.key_id,
            )
            if recomputed != row.current:
                return _fail(result, "hash_mismatch", row.seq, f"记录 #{row.seq} 的内容与 HMAC 不一致（内容被改）")
            prev = row.current

        result.first_seq = rows[0].seq if rows else None
        result.last_seq = rows[-1].seq if rows else None
        result.chain_tail = prev
        result.tail_count = len(rows)

        tail = self.tail()
        result.tail_matches = int(tail["tail_count"]) == len(rows) and tail["chain_tail"] == prev
        if not result.tail_matches:
            return _fail(
                result,
                "tail_mismatch",
                len(rows),
                f"尾状态不一致：库内 count={tail['tail_count']} tail={tail['chain_tail'][:12]}…，"
                f"实际 count={len(rows)} tail={prev[:12]}…（尾部被删改）",
            )
        if rows and self.keyring.hmac_tail(prev, len(rows)) != tail["hmac_tail"]:
            return _fail(result, "tail_hmac_mismatch", len(rows), "尾状态 HMAC 不符，尾部被替换")

        if self.anchor_path:
            try:
                anchor = read_anchor(self.anchor_path)
            except AuditError as exc:
                return _fail(result, "anchor_unreadable", None, str(exc))
            if anchor is None:
                result.anchor_present = False
                result.anchor_detail = "尚未封存尾锚（首次运行或间隔未到）"
            else:
                result.anchor_present = True
                result.anchor_matches, result.anchor_detail = self._check_anchor(anchor, prev, len(rows))
                if not result.anchor_matches:
                    return _fail(result, "anchor_mismatch", None, result.anchor_detail)
        return result

    def _check_anchor(self, anchor: AnchorState, chain_tail: str, count: int) -> tuple[bool, str]:
        valid, detail = self.keyring.verify_anchor(anchor)
        if not valid:
            return False, detail
        if anchor.tail_count > count:
            return False, (
                f"记录缺失：尾锚封存于 {anchor.tail_count} 条，当前仅 {count} 条"
                "（历史被截断/清空）"
            )
        if anchor.tail_count == count and anchor.chain_tail != chain_tail:
            return False, "尾指纹与独立锚不一致（尾部记录被替换）"
        if anchor.tail_count < count:
            return True, f"尾锚封存于 {anchor.tail_count} 条，之后新增 {count - anchor.tail_count} 条（未封存）"
        return True, "尾锚与链尾一致"

    # -- 封存 -------------------------------------------------------------
    def seal(self, *, force: bool = False) -> AnchorState | None:
        if not self.anchor_path:
            return None
        with self._lock:
            tail = self.tail()
        state = self.keyring.make_anchor(str(tail["chain_tail"]), int(tail["tail_count"]))
        maybe_write = force or time.monotonic() - self._last_seal >= self.seal_interval_s
        if maybe_write:
            write_anchor(self.anchor_path, state)
            self._last_seal = time.monotonic()
        return state

    def _maybe_seal(self) -> None:
        if not self.anchor_path:
            return
        if time.monotonic() - self._last_seal >= max(1, self.seal_interval_s):
            try:
                self.seal(force=True)
            except OSError:  # 锚写失败不应阻断审计主链，但会在下次校验中暴露
                pass

    # -- 导出 -------------------------------------------------------------
    def export_jsonl(self, dest: str | Path | None = None) -> str:
        lines: list[str] = []
        for rec in self.iter_records():
            lines.append(canonical_json(rec.to_dict()))
        text = "\n".join(lines) + ("\n" if lines else "")
        if dest:
            Path(dest).parent.mkdir(parents=True, exist_ok=True)
            Path(dest).write_text(text, encoding="utf-8")
        return text

    def export_bundle(self, dest: str | Path, *, policy_snapshot: dict[str, Any] | None = None) -> Path:
        """导出取证包（zip）：记录、尾锚、校验结论、策略快照。"""
        path = Path(dest)
        path.parent.mkdir(parents=True, exist_ok=True)
        verification = self.verify()
        records_jsonl = self.export_jsonl()
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("records.jsonl", records_jsonl)
            zf.writestr("verify.json", json.dumps(verification.to_dict(), ensure_ascii=False, indent=2))
            if self.anchor_path and Path(self.anchor_path).exists():
                zf.writestr("tail.anchor", Path(self.anchor_path).read_text(encoding="utf-8"))
            if policy_snapshot is not None:
                zf.writestr("policy.json", json.dumps(policy_snapshot, ensure_ascii=False, indent=2))
            zf.writestr(
                "README.txt",
                "AgentJudge 取证包\n"
                "=================\n"
                f"导出时间：{utc_now_iso()}\n"
                f"记录条数：{verification.records}\n"
                f"链校验：{'通过' if verification.ok else '失败 - ' + verification.reason}\n"
                f"链尾指纹：{verification.chain_tail}\n\n"
                "records.jsonl：每行一条审计记录（含 prev/current 指纹）\n"
                "verify.json：导出时的链校验结论\n"
                "tail.anchor：独立尾锚（数据库之外的可信副本）\n"
                "policy.json：导出时生效的策略快照\n\n"
                "复核方式：agentjudge audit verify --db <db> --anchor <anchor>\n",
            )
        return path

    # -- 维护 -------------------------------------------------------------
    def stats(self) -> dict[str, Any]:
        with self._lock:
            by_kind = {
                row["kind"]: row["c"]
                for row in self._conn.execute(
                    "SELECT kind, COUNT(*) AS c FROM audit_records GROUP BY kind"
                ).fetchall()
            }
            by_action = {
                row["action"]: row["c"]
                for row in self._conn.execute(
                    "SELECT action, COUNT(*) AS c FROM audit_records WHERE action IS NOT NULL GROUP BY action"
                ).fetchall()
            }
            sessions = self._conn.execute(
                "SELECT COUNT(DISTINCT session_id) AS c FROM audit_records WHERE session_id IS NOT NULL"
            ).fetchone()["c"]
        return {
            "db_path": self.db_path,
            "records": self.count(),
            "by_kind": by_kind,
            "by_action": by_action,
            "sessions": int(sessions),
            "tail": self.tail(),
        }

    def checkpoint(self) -> None:
        with self._lock:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:  # pragma: no cover
                pass

    def close(self) -> None:
        try:
            self.seal(force=True)
        except Exception:  # noqa: BLE001
            pass
        self.checkpoint()
        with self._lock:
            self._conn.close()

    def __enter__(self) -> AuditStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def _row_to_record(row: sqlite3.Row) -> ChainRecord:
    try:
        payload = json.loads(row["payload"])
    except (json.JSONDecodeError, TypeError):
        payload = {"_raw": row["payload"]}
    return ChainRecord(
        seq=int(row["seq"]),
        ts=str(row["ts"]),
        kind=str(row["kind"]),
        payload=payload,
        prev=str(row["prev"]),
        current=str(row["current"]),
        key_id=str(row["key_id"]),
        session_id=row["session_id"],
        action=row["action"],
        tool=row["tool"],
    )


def _fail(result: VerifyResult, reason: str, seq: int | None, detail: str) -> VerifyResult:
    result.ok = False
    result.reason = reason
    result.broken_at = seq
    result.detail = detail
    return result


def _jsonable(obj: Any) -> Any:
    """把任意对象压缩成可 JSON 序列化的结构。"""
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        if isinstance(obj, str) and len(obj) > 20_000:
            return obj[:20_000] + "…<truncated>"
        return obj
    return str(obj)


__all__ = ["AuditStore", "SCHEMA"]
