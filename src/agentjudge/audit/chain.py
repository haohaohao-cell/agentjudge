"""防篡改审计链的密码学原语。

每条记录：``current = HMAC-SHA256(key, canonical({seq, ts, kind, payload, prev}))``。

* 改任意一条记录 → 该条 ``current`` 与实际重算值不符；
* 改一条并重算 → 后续记录的 ``prev`` 与实际值不符（链断）；
* 删尾/清空/替换尾部 → 与独立尾锚（``tail.anchor``）的 ``tail_count`` /
  ``chain_tail`` 不一致。

因此攻击者若要“干净地”篡改，必须同时拿到密钥、重写整条链、并改写独立锚，
这正是我们把锚写到数据库之外（文件/外部存储）的原因。
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..errors import AuditError, ConfigError
from ..utils import canonical_json, hmac_hex, utc_now_iso

GENESIS = "0" * 64


@dataclass(slots=True)
class ChainRecord:
    seq: int
    ts: str
    kind: str
    payload: dict[str, Any]
    prev: str
    current: str
    key_id: str
    session_id: str | None = None
    action: str | None = None
    tool: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "kind": self.kind,
            "session_id": self.session_id,
            "action": self.action,
            "tool": self.tool,
            "payload": self.payload,
            "prev": self.prev,
            "current": self.current,
            "key_id": self.key_id,
        }


@dataclass(slots=True)
class AnchorState:
    """独立尾锚：数据库之外的可信副本。"""

    chain_tail: str
    tail_count: int
    hmac_tail: str
    sealed_at: str
    key_id: str
    anchor_hmac: str = ""

    def body(self) -> dict[str, Any]:
        return {
            "chain_tail": self.chain_tail,
            "tail_count": self.tail_count,
            "hmac_tail": self.hmac_tail,
            "sealed_at": self.sealed_at,
            "key_id": self.key_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "anchor_hmac": self.anchor_hmac}


@dataclass(slots=True)
class VerifyResult:
    ok: bool
    records: int = 0
    reason: str = "ok"
    broken_at: int | None = None
    detail: str = ""
    first_seq: int | None = None
    last_seq: int | None = None
    chain_tail: str = ""
    tail_count: int = 0
    tail_matches: bool = True
    anchor_present: bool = False
    anchor_matches: bool = True
    anchor_detail: str = ""
    key_id: str = ""
    checked_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "records": self.records,
            "reason": self.reason,
            "broken_at": self.broken_at,
            "detail": self.detail,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "chain_tail": self.chain_tail,
            "tail_count": self.tail_count,
            "tail_matches": self.tail_matches,
            "anchor_present": self.anchor_present,
            "anchor_matches": self.anchor_matches,
            "anchor_detail": self.anchor_detail,
            "key_id": self.key_id,
            "checked_at": self.checked_at,
        }


class Keyring:
    """签名密钥集合，支持密钥轮换（旧密钥仅用于验证）。"""

    def __init__(self, key: bytes, key_id: str = "k1", old: dict[str, bytes] | None = None):
        if len(key) < 16:
            raise ConfigError("HMAC 密钥过短（至少 16 字节）")
        self.key = key
        self.key_id = key_id
        self.old = dict(old or {})

    # -- 构造 -------------------------------------------------------------
    @classmethod
    def from_env_or_file(
        cls,
        *,
        key_file: str | Path,
        key_env: str = "AGENTJUDGE_HMAC_KEY",
        key_id: str = "k1",
    ) -> Keyring:
        raw = os.environ.get(key_env, "").strip()
        if raw:
            return cls(_decode_key(raw), key_id)
        path = Path(key_file)
        if path.exists():
            text = path.read_text(encoding="utf-8").strip()
            if not text:
                raise ConfigError(f"密钥文件为空: {path}")
            return cls(_decode_key(text), key_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        path.write_text(key.hex(), encoding="utf-8")
        _chmod_private(path)
        return cls(key, key_id)

    # -- 签名 -------------------------------------------------------------
    @staticmethod
    def _body(seq: int, ts: str, kind: str, payload: dict[str, Any], prev: str) -> str:
        return canonical_json({"seq": seq, "ts": ts, "kind": kind, "payload": payload, "prev": prev})

    def sign(self, *, seq: int, ts: str, kind: str, payload: dict[str, Any], prev: str, key_id: str | None = None) -> str:
        key = self._key_for(key_id)
        return hmac_hex(key, self._body(seq, ts, kind, payload, prev))

    def hmac_tail(self, chain_tail: str, count: int, key_id: str | None = None) -> str:
        key = self._key_for(key_id)
        return hmac_hex(key, f"tail|{count}|{chain_tail}")

    def _key_for(self, key_id: str | None) -> bytes:
        if key_id is None or key_id == self.key_id:
            return self.key
        if key_id in self.old:
            return self.old[key_id]
        raise ConfigError(f"未知密钥 id: {key_id}")

    # -- 尾锚 -------------------------------------------------------------
    def make_anchor(self, chain_tail: str, count: int) -> AnchorState:
        state = AnchorState(
            chain_tail=chain_tail,
            tail_count=count,
            hmac_tail=self.hmac_tail(chain_tail, count),
            sealed_at=utc_now_iso(),
            key_id=self.key_id,
        )
        state.anchor_hmac = hmac_hex(self.key, canonical_json(state.body()))
        return state

    def verify_anchor(self, anchor: AnchorState) -> tuple[bool, str]:
        """校验尾锚自身的完整性（防止锚文件被改写/伪造）。"""
        expected_hmac = self.hmac_tail(anchor.chain_tail, anchor.tail_count, key_id=anchor.key_id)
        if expected_hmac != anchor.hmac_tail:
            return False, "尾锚自身的 hmac_tail 不匹配（锚文件被改写）"
        if anchor.anchor_hmac:
            expected = hmac_hex(self._key_for(anchor.key_id), canonical_json(anchor.body()))
            if expected != anchor.anchor_hmac:
                return False, "尾锚签名不匹配（锚文件被伪造或损坏）"
        return True, ""


def _decode_key(raw: str) -> bytes:
    text = raw.strip()
    if text.startswith("base64:"):
        return base64.b64decode(text.split(":", 1)[1])
    if text.startswith("hex:"):
        return bytes.fromhex(text.split(":", 1)[1])
    if len(text) == 64:
        try:
            return bytes.fromhex(text)
        except binascii.Error:
            pass
    try:
        decoded = base64.b64decode(text, validate=True)
        if len(decoded) >= 16:
            return decoded
    except (binascii.Error, ValueError):
        pass
    return text.encode("utf-8")


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - Windows 上可能不支持
        pass


def write_anchor(path: str | Path, state: AnchorState) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(state.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def read_anchor(path: str | Path) -> AnchorState | None:
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"尾锚文件损坏 {p}: {exc}") from exc
    try:
        return AnchorState(
            chain_tail=str(data["chain_tail"]),
            tail_count=int(data["tail_count"]),
            hmac_tail=str(data["hmac_tail"]),
            sealed_at=str(data.get("sealed_at", "")),
            key_id=str(data.get("key_id", "k1")),
            anchor_hmac=str(data.get("anchor_hmac", "")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AuditError(f"尾锚字段缺失 {p}: {exc}") from exc
