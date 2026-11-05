"""``original-input-lookup-v1``: read-only reconciliation of one ORIGINAL input by its exact identity.

A machine client that lost a ``prompt.submit`` reply (transport loss before the ACK) cannot use
``prompt.receipt``: that needs the ``admission_id`` the lost reply carried. Replaying the submit
is an admission-capable write. These two verbs close that gap without writing anything:

- ``prompt.prepare_input`` returns, BEFORE the submit, the exact binding the owner would commit
  for the same ``prompt.submit`` params: the authenticated principal's opaque binding and the
  payload fingerprint computed by the same canonicalization ``admit_session_input`` stores
  (``committed_payload`` + ``hermes_state_runtime.admission_digest``), plus the accepted
  ``idle_fence``. The client persists it, then submits.
- ``prompt.lookup_input`` reads the admission at the exact durable key (authenticated principal,
  session, ``input_id``) and answers ``found`` (``exact``/``mismatch`` against the prepared
  fingerprint and fence), ``not_found`` or ``unavailable``.

Both are pure: no write transaction, admission, scheduling, restore/mount/adopt, attach or session
creation (``dispatch`` skips its pre-handler adoption for ``ZERO_WRITE_METHODS``). The principal is
always the authenticated actor's subject; params cannot name one, and ``session:control`` never
widens the lookup to another principal. ``not_found`` is absence at this key now, never proof that a
submit was refused; ``unavailable`` (retired/retiring/superseded owner, storage failure) proves
nothing. A terminal status is reported only when settled: a committed settlement whose completion
is not yet published (``LiveSession.settling``) still reads as its started claim.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import sqlite3
from dataclasses import asdict
from functools import partial

from hermes_state_runtime import RuntimeStoreError

CAPABILITY = 'original-input-lookup-v1'
ZERO_WRITE_METHODS = frozenset({'prompt.prepare_input', 'prompt.lookup_input'})
# ``SessionAuthority._submit``'s accepted payload keys (``AuthorityConnection.submission`` builds them).
SUBMIT_KEYS = frozenset({'text', 'attachments', 'finite', 'unattended', 'surface', 'voice_context', 'interrupted',
                         'voice_turn', 'display_kind', 'title_preview', 'turn_author', 'api_text', 'model_override',
                         'clarify_batch', 'idle_fence'})
_FINGERPRINT = re.compile(r'[0-9a-f]{64}')
_ADMISSION_FIELDS = ('admission_id', 'sequence', 'status', 'outcome', 'authority_epoch', 'execution_generation')


def principal_binding(profile_id, principal_id) -> str:
    """Opaque, stable binding of the authenticated principal an admission's identity is keyed by."""
    encoded = json.dumps([CAPABILITY, profile_id, principal_id], ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(encoded.encode('utf-8', errors='surrogatepass')).hexdigest()


def submit_fence(authority, request, kanban_card=None):
    """``idle-admission-v1``'s validated fence of a submit (shape, LOCAL route), or None without one."""
    if not (isinstance(request.payload, dict) and 'idle_fence' in request.payload):
        return None
    # Idle-only, for THIS owner (never the restart wait's next owner), and only on an ordinary
    # LOCAL route whose source is a frozen local policy.
    fence = authority._idle_fence(request.payload['idle_fence'])
    from gateway.config import Platform
    live_source = authority.sessions[request.ref.session_id].source
    if live_source is None or live_source.platform != Platform.LOCAL or kanban_card is not None:
        raise RuntimeStoreError('unsupported_control', field='idle_fence')
    return fence


def committed_payload(authority, actor, request, *, fence, admitted=None, kanban_card=None) -> dict:
    """The exact payload ``SessionAuthority._submit`` commits for *request* (validated). Shared by the
    submit and ``prompt.prepare_input``, so a prepared fingerprint cannot drift from the committed one.
    Attachment capture writes media, so only the submit passes ``attachments`` (prepare refuses them)."""
    if (request.intent != 'queue' or not {'text'} <= set(request.payload) <= SUBMIT_KEYS
            or not isinstance(request.payload['text'], str)):
        raise RuntimeStoreError('invalid_params')
    from gateway.session_ingress_media import admit_attachments
    from gateway.session_finite import admit_finite
    from gateway.session_surface import admit_surface
    from gateway.session_display import admit_display
    from gateway.session_cli_turn import admit_cli_turn
    finite = admit_finite(request.payload)
    payload = {'text': request.payload['text'], **finite, **admit_surface(request.payload),
               **admit_display(request.payload), **admit_cli_turn(request.payload),
               **admit_attachments(request.payload.get('attachments'), admitted=admitted)}
    if kanban_card is not None:
        payload['kanban_card_v1'] = kanban_card
    if fence is not None:
        # Committed in the payload, so the admission fingerprint binds it: an exact retry replays
        # this admission, the same request id with another fence (or none) is admission_conflict.
        payload['idle_fence_v1'] = fence
    source = authority.sessions[request.ref.session_id].source
    from gateway.owner_identity import same_owner
    if source is not None and not same_owner(source.user_id, actor.subject):
        # Durable server authorization, not a client payload field. The original
        # principal remains the admission/retry identity across owner restarts.
        # Operator provenance is about who was authorized at this boundary, not
        # whether the bound session happens to use the LOCAL transport.
        payload['local_operator_v1'] = {
            'profile_id': authority.profile_id, 'session_id': request.ref.session_id,
            'principal_id': actor.subject}
    return payload


def _authorize_actor(authority, actor, ref):
    """``SessionAuthority.authorize``'s actor checks WITHOUT its restore/mount/retire-timer side effects."""
    if actor.profile_id != authority.profile_id or ref.profile_id != authority.profile_id:
        raise RuntimeStoreError('profile_mismatch')
    if 'session:submit' not in actor.capabilities:
        raise RuntimeStoreError('permission_denied')


def _input_id(value):
    """The exact original ``input_id``: a stored request id is 1..1024 chars; never trimmed or folded."""
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise RuntimeStoreError('invalid_params', field='input_id')
    return value


def _ref(authority, ref):
    return {'profile_id': authority.profile_id, 'session_id': ref.session_id}


async def prepare_input(connection, ref, params):
    """``prompt.prepare_input``: the binding the same ``prompt.submit`` params would commit, unwritten."""
    authority, actor = connection.authority, connection.actor
    _authorize_actor(authority, actor, ref)
    from gateway.session_authorities import require_serving
    require_serving(authority)
    live = authority.sessions.get(ref.session_id)
    if live is None:  # never a cold restore: the submit that follows needs the live route anyway
        raise RuntimeStoreError('not_found', field='session_id', detail='session is not live in this owner')
    from gateway.config import Platform
    from gateway.owner_identity import same_owner
    source = live.source
    if (source is not None and source.platform == Platform.LOCAL
            and not same_owner(source.user_id, actor.subject) and 'session:operator' not in actor.capabilities):
        raise RuntimeStoreError('permission_denied')
    request = connection.submission_request(ref, params)
    _input_id(request.request_id)
    fence = submit_fence(authority, request)
    payload = committed_payload(authority, actor, request, fence=fence)
    from hermes_state_runtime import admission_digest
    return {'version': CAPABILITY, 'ref': _ref(authority, ref), 'input_id': request.request_id,
            'principal_binding': principal_binding(authority.profile_id, actor.subject),
            'payload_fingerprint': admission_digest(ref.session_id, payload, request.intent), 'idle_fence': fence}


def _expected(authority, params):
    expected = params.get('payload_fingerprint')
    if not isinstance(expected, str) or not _FINGERPRINT.fullmatch(expected):
        raise RuntimeStoreError('invalid_params', field='payload_fingerprint')
    fence = params.get('idle_fence')
    return expected, (None if fence is None else authority._idle_fence(fence))


def _settled_view(authority, ref, row):
    """*row*'s receipt fields as lock holders see them: a committed settlement not yet published
    (``live.settling``) still reads as its started claim, so it is never early terminal proof."""
    live = authority.sessions.get(ref.session_id)
    if live is not None:
        with live.event_stream.lock:
            row = live.settling.get(row['admission_id'], row)
    receipt = asdict(authority._receipt(row))
    return {key: receipt[key] for key in _ADMISSION_FIELDS}


async def lookup_input(connection, ref, params):
    """``prompt.lookup_input``: the admission at (authenticated principal, session, ``input_id``)."""
    authority, actor = connection.authority, connection.actor
    _authorize_actor(authority, actor, ref)
    input_id = _input_id(params.get('input_id'))
    expected, fence = _expected(authority, params)
    envelope = {'version': CAPABILITY, 'state': 'not_found', 'reason': None, 'ref': _ref(authority, ref),
                'input_id': input_id, 'principal_binding': principal_binding(authority.profile_id, actor.subject),
                'binding': None, 'admission': None, 'proof': None, 'settled': False}
    if getattr(authority, 'retired', False) or authority.retiring:
        return {**envelope, 'state': 'unavailable',
                'reason': 'runtime_retired' if getattr(authority, 'retired', False) else 'runtime_draining'}
    import hermes_state_runtime
    try:
        row = await asyncio.to_thread(partial(hermes_state_runtime.find_input_binding, authority.db,
                                              epoch=authority.epoch, principal_id=actor.subject,
                                              session_id=ref.session_id, request_id=input_id))
    except RuntimeStoreError as exc:
        if exc.reason != 'stale_epoch':
            raise
        return {**envelope, 'state': 'unavailable', 'reason': 'stale_epoch'}
    except sqlite3.Error:
        return {**envelope, 'state': 'unavailable', 'reason': 'storage_unavailable'}
    if row is None:
        return envelope
    committed_fence = row['payload'].get('idle_fence_v1')
    if not (hmac.compare_digest(row['payload_digest'], expected) and committed_fence == fence):
        return {**envelope, 'state': 'found', 'binding': 'mismatch'}
    admission = _settled_view(authority, ref, row)
    return {**envelope, 'state': 'found', 'binding': 'exact', 'admission': admission,
            'proof': {'payload_fingerprint': row['payload_digest'], 'idle_fence': committed_fence},
            'settled': admission['status'] == 'terminal'}


def handlers(connection):
    return {'prompt.prepare_input': partial(prepare_input, connection),
            'prompt.lookup_input': partial(lookup_input, connection)}
