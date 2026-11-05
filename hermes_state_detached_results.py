"""Results that arrive between turns, recorded once as user rows: a detached API delegation's delivery and
an unviewed local completion's note (#134889 LC-7). Split out of ``hermes_state_messages`` and bound onto
SessionDB through ``SessionMessagesMixin``; built on its _message_row_params/_execute_write primitives."""

from __future__ import annotations

import json
import time
from typing import Any

from agent.message_metadata import stamp_message_uid

# Rows of a session and of the parents it was compressed from; a detached result's match condition follows.
_LINEAGE_MATCH_SQL = """WITH RECURSIVE lineage(id) AS (SELECT ? UNION
    SELECT s.parent_session_id FROM sessions s JOIN lineage l ON s.id = l.id
    JOIN sessions p ON p.id = s.parent_session_id WHERE p.end_reason = 'compression'
) SELECT m.id FROM messages m JOIN lineage l ON m.session_id = l.id WHERE """
_DELEGATION_DELIVERY_MATCH = ("m.display_kind IN ('async_delegation_complete', 'hidden') AND json_extract(m.display_metadata, "
                              "'$.delegation_id') = ? AND coalesce(json_extract(m.display_metadata, '$.delivery_notice'), '') = ?")

_PLUGIN_RESULT_MATCH = ("m.display_kind = 'async_delegation_complete' AND "
                        "json_extract(m.display_metadata, '$.plugin_result.delivery_key') = ?")


def _plugin_result_row(conn, session_id: str, delivery_key: str) -> dict[str, Any] | None:
    found = conn.execute(_LINEAGE_MATCH_SQL + _PLUGIN_RESULT_MATCH + " LIMIT 1", (session_id, delivery_key)).fetchone()
    if found is None:
        return None
    row = conn.execute("SELECT id, session_id, message_uid, timestamp, content, display_metadata FROM messages "
                       "WHERE id = ?", (found[0],)).fetchone()
    return {"message_id": row[0], "session_id": row[1], "message_uid": row[2], "timestamp": row[3],
            "content": row[4], "plugin_result": json.loads(row[5])["plugin_result"]}


class SessionDetachedResultsMixin:
    """Detached API delegation deliveries and unviewed completion notes."""

    def append_delegation_delivery(self, session_id: str, content: str, metadata: dict[str, Any]) -> int:
        """Record a detached API result once, keyed by the event's unit id (not its text or active flag)."""
        delegation_id = metadata.get("delegation_id")
        if not delegation_id:
            raise ValueError("Delegation delivery requires a stable delegation_id")
        kind = "hidden" if metadata.get("presentation_suppressed") else "async_delegation_complete"
        return self._append_detached_result(session_id, content, kind, metadata, _DELEGATION_DELIVERY_MATCH,
                                            (delegation_id, metadata.get("delivery_notice", "")))

    def append_completion_note(self, session_id: str, admission_id: str, content: str, display_kind: str,
                               metadata: dict[str, Any]) -> int:
        """Record an unviewed completion's note once, keyed by its admission (stored as ``completion_admission``)."""
        return self._append_detached_result(
            session_id, content, display_kind, {**metadata, "completion_admission": admission_id},
            "json_extract(m.display_metadata, '$.completion_admission') = ?", (admission_id,))

    def find_plugin_result(self, session_id: str, delivery_key: str) -> dict[str, Any] | None:
        """The plugin result recorded under *delivery_key* in *session_id*'s compression lineage, read-only."""
        with self._read_ctx() as conn:
            return _plugin_result_row(conn, session_id, delivery_key)

    def append_plugin_result(self, session_id: str, delivery_key: str, content: str, api_content: str,
                             display_text: str, receipt: dict[str, Any]) -> dict[str, Any]:
        """Record a plugin's late result as ONE visible transcript row that is also its receipt, once per
        *delivery_key* (``gateway/plugin_result_delivery.py``). Lookup and insert share the writer
        transaction: concurrent or repeated calls in any process return the first row (``created``
        False) with its stored ``content_sha256``, which the caller compares. No turn is admitted."""
        from hermes_state_messages import _INSERT_MESSAGE_SQL  # that module binds this mixin
        metadata = {"display_text": display_text, "plugin_result": {**receipt, "delivery_key": delivery_key}}
        msg = {"content": content, "api_content": api_content, "display_kind": "async_delegation_complete",
               "display_metadata": metadata}
        stamp_message_uid(msg)
        row = self._message_row_params(session_id, "user", msg, None, time.time(), keep_reasoning=True)

        def _do(conn):
            existing = _plugin_result_row(conn, session_id, delivery_key)
            if existing is not None:
                return {**existing, "created": False}
            self._check_transcript_write_guards(conn, session_id, None, reject_active_turn_lease=True)
            conn.execute(_INSERT_MESSAGE_SQL, row)
            self._bump_session_counters(conn, session_id, 1, 0, unit=True)
            return {**_plugin_result_row(conn, session_id, delivery_key), "created": True}

        return self._execute_write(_do, patience_s=self._TRANSCRIPT_WRITE_PATIENCE_S)

    def _append_detached_result(self, session_id: str, content: str, display_kind: str, metadata: dict[str, Any],
                                match_sql: str, params: tuple) -> int:
        """Record a result that arrived between turns as a user row once, including replay after rotation: a row
        ``match_sql`` (a condition on ``m``) finds in the compression lineage is returned instead. Check and insert
        share the writer transaction, so independent gateway processes cannot duplicate it; a live turn refuses it."""
        from hermes_state_messages import _INSERT_MESSAGE_SQL  # that module binds this mixin
        msg = {"content": content, "display_kind": display_kind, "display_metadata": metadata}
        stamp_message_uid(msg)  # a fresh occurrence: mint its durable id
        row = self._message_row_params(session_id, "user", msg, None, time.time(), keep_reasoning=True)

        def _do(conn):
            existing = conn.execute(_LINEAGE_MATCH_SQL + match_sql + " LIMIT 1", (session_id, *params)).fetchone()
            if existing is not None:
                return existing[0]
            self._check_transcript_write_guards(conn, session_id, None, reject_active_turn_lease=True)
            msg_id = conn.execute(_INSERT_MESSAGE_SQL, row).lastrowid
            self._bump_session_counters(conn, session_id, 1, 0, unit=True)
            return msg_id

        return self._execute_write(_do, patience_s=self._TRANSCRIPT_WRITE_PATIENCE_S)
