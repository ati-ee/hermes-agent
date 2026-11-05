"""``original-input-lookup-v1``: read-only original-input binding and lookup (authority-only verbs).

``gateway/session_input_lookup.py`` serves both on the authenticated native socket. Neither verb
writes, admits, schedules, restores, attaches or creates a session. The principal is always the
authenticated connection's subject: no param names or searches one, and ``session:control`` never
widens a lookup to another principal's admissions.
"""

from __future__ import annotations

from typing import Literal

from pydantic import StrictInt

from .base import Params, Result
from .canonical import CanonicalSessionRef
from .canonical_sessions import CanonicalIdleFence
from .registry import canonical_method


class OriginalInputFence(Result):
    """The accepted ``idle-admission-v1`` fence committed with the admission (``idle_fence_v1``)."""

    expected_generation: int


class PromptPrepareInputParams(Params):
    """The same keys a machine ``prompt.submit`` of plain text sends (no attachments: capturing them
    writes media). ``input_id`` is the exact original request id the submit will carry."""

    session_id: str
    input_id: str
    text: str
    finite: bool = False
    unattended: bool = False
    idle_fence: CanonicalIdleFence | None = None


class PreparedInputBinding(Result):
    """What the owner WOULD commit for those params, computed without writing. Persist it before
    the submit; ``prompt.lookup_input`` later compares against it."""

    version: Literal["original-input-lookup-v1"]
    ref: CanonicalSessionRef
    input_id: str
    principal_binding: str
    payload_fingerprint: str
    idle_fence: OriginalInputFence | None


class PromptLookupInputParams(Params):
    session_id: str
    input_id: str
    payload_fingerprint: str
    idle_fence: CanonicalIdleFence | None = None


class OriginalInputAdmission(Result):
    """``AdmissionStatus`` without the ref (the envelope carries it). A committed settlement whose
    completion is not yet published reads ``started``: ``terminal`` is settled-owner evidence only."""

    admission_id: str
    sequence: int
    status: Literal["queued", "started", "unknown", "terminal"]
    outcome: str | None
    authority_epoch: int
    execution_generation: StrictInt | None


class OriginalInputProof(Result):
    payload_fingerprint: str
    idle_fence: OriginalInputFence | None


class PromptLookupInputResult(Result):
    """``found``: an admission holds (this principal, session, ``input_id``); ``binding`` says whether
    its committed fingerprint AND fence equal the expected ones (``admission``/``proof`` only on
    ``exact``). ``not_found``: nothing at that exact key NOW, never proof a submit was refused.
    ``unavailable`` (``reason``): retired/draining/superseded owner or storage failure; proves nothing."""

    version: Literal["original-input-lookup-v1"]
    state: Literal["found", "not_found", "unavailable"]
    reason: Literal["runtime_retired", "runtime_draining", "stale_epoch", "storage_unavailable"] | None
    ref: CanonicalSessionRef
    input_id: str
    principal_binding: str
    binding: Literal["exact", "mismatch"] | None
    admission: OriginalInputAdmission | None
    proof: OriginalInputProof | None
    settled: bool


canonical_method("prompt.prepare_input", params=PromptPrepareInputParams, result=PreparedInputBinding,
                 doc="original-input-lookup-v1: the binding (opaque principal, payload fingerprint, fence) the same "
                     "prompt.submit params would commit, computed without writing. Needs a session live in this owner; "
                     "no attach. Refusals: not_found, permission_denied, unsupported_control, invalid_params.")
canonical_method("prompt.lookup_input", params=PromptLookupInputParams, result=PromptLookupInputResult,
                 doc="original-input-lookup-v1: read-only lookup of the caller's own admission at its exact original "
                     "input_id; no prefix/trim/alias, no other principal, no write. not_found never proves a refusal.")
