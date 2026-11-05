"""Sealed invocation origin and the native result sink for plugin tools.

``PluginContext.invocation_origin()`` names the admitted turn a plugin tool is running in. Its fields
are the profile, the session store, the session (the logical owner), the route, and the claimed
admission with its request and generation, all bound to THIS plugin. The fields come only from the
drain's task-local ``executing_origin`` (``gateway/session_ingress.py``), never from ``os.environ``,
a tool argument or model text. The gateway seals them with the store's private key
(``gateway/plugin_origin_seal.py``). Outside an admitted turn, without a live gateway, or without the
plugin's opt-in it returns ``None``.

``to_dict()`` keeps the seal (never the key), so a producer may persist the origin and use it again
after a restart. A dict or object rebuilt from plain fields carries no valid seal and is refused.

``PluginContext.deliver_result()`` records a later result in the origin conversation as one durable,
visible transcript row that is also its receipt (``gateway/plugin_result_delivery.py``):

* the same ``delivery_id`` with the same text returns the same receipt and writes no second message
  (ACK lost, restart, concurrent resend);
* the same ``delivery_id`` with other text is ``conflict`` and writes nothing;
* an origin that fails authentication is ``origin_unknown`` before any lookup or write;
* a new result for a route that now names another conversation is ``origin_moved``;
* it never admits, claims or starts a model turn.

``PluginContext.delivery_receipt()`` reads that receipt without writing, even after ``/new``.
Trust limit: this authenticates origins across serialization boundaries; it does not sandbox a
malicious in-process plugin (same process, same OS user).
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, fields
from typing import Any

_DELIVERY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")
_HEX = re.compile(r"^[0-9a-f]+$")
_MAX_CONTENT = 64 * 1024
DEFAULT_TIMEOUT_S = 30.0


@dataclass(frozen=True)
class InvocationOrigin:
    """A sealed admitted turn, issued to one plugin (immutable). Only the seal makes it authority."""

    schema: str
    plugin_id: str
    profile_id: str
    store_id: str
    session_id: str
    route: str
    admission_id: str
    request_id: str
    generation: int
    seal: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_fields(self) -> dict[str, Any]:
        """The sealed fields (everything but the seal)."""
        out = asdict(self)
        out.pop("seal")
        return out

    @classmethod
    def from_dict(cls, data: Any) -> InvocationOrigin:
        """Strict parse of ``to_dict()`` output: exact keys and types; raises ``ValueError``."""
        names = [f.name for f in fields(cls)]
        if not isinstance(data, dict) or sorted(data) != sorted(names):
            raise ValueError("origin must carry exactly the fields of hermes.plugin-origin/v1")
        for name in names:
            value = data[name]
            ok = (type(value) is int and value >= 0) if name == "generation" else (isinstance(value, str) and value)
            if not ok:
                raise ValueError(f"origin field {name!r} is malformed")
        if len(data["seal"]) != 64 or not _HEX.fullmatch(data["seal"]):
            raise ValueError("origin seal is malformed")
        return cls(**data)


def _refuse(code: str, detail: str = "") -> dict[str, Any]:
    return {"ok": False, "error": code, **({"detail": detail} if detail else {})}


def _gateway(ctx: Any):
    registered = ctx._manager._gateway_message_injector
    return registered[0] if registered is not None else None


def _available(ctx: Any) -> dict[str, Any] | None:
    manager = ctx._manager
    if manager._cli_ref is not None or not manager.has_gateway_message_injector or _gateway(ctx) is None:
        return _refuse("unsupported", "result delivery needs a live gateway session authority")
    if not ctx._gateway_injection_allowed():
        return _refuse("not_allowed", f"set plugins.entries.{ctx.plugin_id}.allow_gateway_injection: true")
    return None


def current_origin(ctx: Any) -> InvocationOrigin | None:
    """The executing admission's origin sealed for *ctx*'s plugin, or ``None``."""
    if _available(ctx) is not None:
        return None
    from gateway.plugin_result_delivery import issue_origin

    issued = issue_origin(_gateway(ctx), plugin_id=ctx.plugin_id, plugin_home=ctx._manager.home_path)
    return InvocationOrigin(**issued) if issued is not None else None


def _checked(ctx: Any, origin: Any, delivery_id: Any) -> tuple[InvocationOrigin | None, dict[str, Any] | None]:
    refused = _available(ctx)
    if refused is not None:
        return None, refused
    try:
        # A caller-built object is parsed exactly like a dict: only the seal is authority.
        parsed = InvocationOrigin.from_dict(origin.to_dict() if isinstance(origin, InvocationOrigin) else origin)
    except ValueError as exc:
        return None, _refuse("invalid_origin", str(exc))
    if not isinstance(delivery_id, str) or not _DELIVERY_ID.fullmatch(delivery_id):
        return None, _refuse("invalid_delivery_id", "16-128 chars of [A-Za-z0-9._:-], alphanumeric first")
    return parsed, None


def deliver(ctx: Any, content: Any, *, origin: Any, delivery_id: Any,
            timeout: float = DEFAULT_TIMEOUT_S) -> dict[str, Any]:
    parsed, refused = _checked(ctx, origin, delivery_id)
    if refused is not None:
        return refused
    if not isinstance(content, str) or not content.strip() or len(content) > _MAX_CONTENT:
        return _refuse("invalid_content", f"non-empty text up to {_MAX_CONTENT} characters")
    return _gateway(ctx)._deliver_plugin_result(origin=parsed, content=content, delivery_id=delivery_id,
                                                plugin_id=ctx.plugin_id, plugin_home=ctx._manager.home_path,
                                                timeout=timeout, read_only=False)


def receipt(ctx: Any, *, origin: Any, delivery_id: Any, timeout: float = DEFAULT_TIMEOUT_S) -> dict[str, Any]:
    parsed, refused = _checked(ctx, origin, delivery_id)
    if refused is not None:
        return refused
    return _gateway(ctx)._deliver_plugin_result(origin=parsed, content=None, delivery_id=delivery_id,
                                                plugin_id=ctx.plugin_id, plugin_home=ctx._manager.home_path,
                                                timeout=timeout, read_only=True)


class PluginOriginCtxMixin:
    """Mixed into :class:`hermes_cli.plugins.PluginContext` (``_manager``, ``plugin_id``)."""

    def invocation_origin(self) -> InvocationOrigin | None:
        """The admitted turn this call runs in, sealed for this plugin; ``None`` outside one."""
        return current_origin(self)

    def deliver_result(self, content: str, *, origin: InvocationOrigin | dict, delivery_id: str,
                       timeout: float = DEFAULT_TIMEOUT_S) -> dict[str, Any]:
        """Record *content* in *origin*'s conversation as one durable visible row + receipt, once per
        *delivery_id*: ``{ok, found, created, receipt}`` or ``{ok: False, error}``. Never starts a turn.
        Blocks the calling thread (never the gateway loop) up to *timeout*; ``error='unknown'`` or
        ``'busy'`` means resend the same pair or read ``delivery_receipt``."""
        return deliver(self, content, origin=origin, delivery_id=delivery_id, timeout=timeout)

    def delivery_receipt(self, *, origin: InvocationOrigin | dict, delivery_id: str,
                         timeout: float = DEFAULT_TIMEOUT_S) -> dict[str, Any]:
        """Read-only: the receipt ``deliver_result`` recorded for this pair, if any."""
        return receipt(self, origin=origin, delivery_id=delivery_id, timeout=timeout)
