"""Server-authenticated seal of a plugin invocation origin (``hermes.plugin-origin/v1``).

The seal is HMAC-SHA256 over the canonical JSON of the origin's fields. Those fields are the schema,
the plugin, the profile, the store, the session, the route, the origin admission, its request and its
generation. The key is a random 32-byte secret, one per session store. It is created once inside the
store's own write transaction under ``state_meta`` key ``plugin_origin_seal_key_v1`` and never leaves
this module: it is not in the origin, not in its serialization, and not exposed through
``PluginContext``.

A serialized origin therefore keeps working after a restart against the same store. An origin rebuilt
from plain fields, or carried to another store, profile, session or plugin, fails verification before
anything is read or written.

Trust limit: the seal authenticates origins that crossed a serialization boundary (a producer's ledger,
model text, another process without the store). It does NOT isolate a malicious plugin running
in-process or as the same OS user. Such code can read the store file or call these functions directly.
Out-of-process plugin hosts get no origin at all (``hermes_cli/plugin_isolation.py``).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import weakref
from typing import Any, Mapping

SCHEMA = "hermes.plugin-origin/v1"
FIELDS = ("schema", "plugin_id", "profile_id", "store_id", "session_id", "route", "admission_id",
          "request_id", "generation")
_META_KEY = "plugin_origin_seal_key_v1"
_STORE_ID_LABEL = b"hermes.plugin-origin/v1 store-id"
_KEYS: weakref.WeakKeyDictionary[Any, bytes] = weakref.WeakKeyDictionary()
_LOCK = threading.Lock()


def store_key(db) -> bytes:
    """This store's seal key, created atomically on first use (thread-safe; blocking I/O once)."""
    with _LOCK:
        cached = _KEYS.get(db)
    if cached is not None:
        return cached

    def _do(conn):
        conn.execute("INSERT OR IGNORE INTO state_meta(key, value) VALUES(?, ?)",
                     (_META_KEY, secrets.token_hex(32)))
        return conn.execute("SELECT value FROM state_meta WHERE key = ?", (_META_KEY,)).fetchone()[0]

    key = bytes.fromhex(db._execute_write(_do))
    if len(key) != 32:
        raise RuntimeError("plugin origin seal key in state_meta is malformed")
    with _LOCK:
        return _KEYS.setdefault(db, key)


def store_id(key: bytes) -> str:
    """A public, stable name of the store derived from its key (reveals nothing about the key)."""
    return hmac.new(key, _STORE_ID_LABEL, hashlib.sha256).hexdigest()[:32]


def canonical(fields: Mapping[str, Any]) -> bytes:
    """The exact bytes the seal covers: the fixed field set, sorted keys, no whitespace."""
    return json.dumps({name: fields[name] for name in FIELDS}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def seal(key: bytes, fields: Mapping[str, Any]) -> str:
    return hmac.new(key, canonical(fields), hashlib.sha256).hexdigest()


def verify(key: bytes, fields: Mapping[str, Any], presented: str) -> bool:
    """Constant-time comparison of *presented* against the seal of *fields* under *key*."""
    if not isinstance(presented, str) or len(presented) != 64:
        return False
    return hmac.compare_digest(seal(key, fields), presented)


def issue(key: bytes, *, plugin_id: str, bound: Mapping[str, Any]) -> dict[str, Any]:
    """The sealed origin fields for *plugin_id* from the drain's bound turn (``executing_origin``)."""
    fields = {"schema": SCHEMA, "plugin_id": plugin_id, "profile_id": bound["profile_id"],
              "store_id": store_id(key), "session_id": bound["session_id"], "route": bound["route"],
              "admission_id": bound["admission_id"], "request_id": bound["request_id"],
              "generation": bound["generation"]}
    return {**fields, "seal": seal(key, fields)}
