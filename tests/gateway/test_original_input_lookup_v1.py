"""original-input-lookup-v1: read-only lookup of one ORIGINAL input by its exact durable identity.

Real parser (``AuthorityConnection.dispatch`` + canonical contracts) -> ``SessionAuthority`` ->
real SQLite ``SessionDB``. No agent, model, network or installed profile: a disposable
HERMES_HOME per test and ``_schedule`` stubbed so nothing executes. Every lookup/prepare runs
under ``_ZeroWrites``: it counts SessionDB write transactions, tracked owner writes, scheduling,
restore/mount/adopt calls, new live sessions, new subscriptions and hashes the whole database,
so a "read" that writes, admits, schedules, restores or attaches fails the test.
"""
import asyncio
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault('HERMES_TEST_ISOLATION', '1')  # contract violations raise (registry.STRICT)

from gateway.config import Platform
from gateway.session_authority import LiveSession, SessionAuthority
from gateway.session_controls import AuthorityConnection
from hermes_state import SessionDB
from hermes_state_runtime import (
    admit_session_input, begin_runtime_epoch, claim_session_input, recover_session_inputs, settle_session_input,
)

SID = 'local-lookup-synthetic-0001'
OTHER_SID = 'local-lookup-synthetic-0002'
INPUT = 'mission-0001:assignment-0007'
CAPS = ['session:read', 'session:submit', 'session:control', 'session:approve', 'session:respond']
HUMAN = {'user_id': 'human', 'provider': 'local', 'profile_id': 'owned', 'instance_id': 'current', 'capabilities': CAPS}
STRANGER = {**HUMAN, 'user_id': 'stranger'}
VERSION = 'original-input-lookup-v1'


class _NoNetwork:
    def __enter__(self):
        self._orig = socket.socket.connect, socket.create_connection
        def refuse(*args, **kwargs):
            raise AssertionError('network use in original-input lookup test')
        socket.socket.connect, socket.create_connection = refuse, refuse
        return self

    def __exit__(self, *exc):
        socket.socket.connect, socket.create_connection = self._orig


class _ZeroWrites:
    """Fails unless the block performed no durable write, admission, scheduling, restore or attach."""

    def __init__(self, case, authority, *connections):
        self.case, self.authority, self.connections = case, authority, connections
        self.counts = {'db_writes': 0, 'tracked_writes': 0, 'scheduled': 0, 'restores': 0, 'adoptions': 0}

    def _count(self, key, original):
        def wrapped(*args, **kwargs):
            self.counts[key] += 1
            return original(*args, **kwargs)
        return wrapped

    def _acount(self, key, original):
        async def wrapped(*args, **kwargs):
            self.counts[key] += 1
            return await original(*args, **kwargs)
        return wrapped

    def __enter__(self):
        from gateway import (session_api, session_history_mount, session_local_adoption, session_local_recovery,
                             session_route_recovery, session_runtime_workers)
        db = self.authority.db
        self.patches = [
            (db, '_execute_write', self._count('db_writes', db._execute_write)),
            (self.authority, '_schedule', self._count('scheduled', self.authority._schedule)),
            (session_runtime_workers, 'tracked_write', self._acount('tracked_writes', session_runtime_workers.tracked_write)),
            (session_local_adoption, 'adopt_before_restore',
             self._acount('adoptions', session_local_adoption.adopt_before_restore)),
            (session_local_recovery, 'restore_local_session',
             self._count('restores', session_local_recovery.restore_local_session)),
            (session_route_recovery, 'restore_routed_session',
             self._count('restores', session_route_recovery.restore_routed_session)),
            (session_api, 'restore_api_session', self._count('restores', session_api.restore_api_session)),
            (session_history_mount, 'mount_history', self._count('restores', session_history_mount.mount_history)),
        ]
        self.saved = [(obj, name, obj.__dict__.get(name, _MISSING)) for obj, name, _ in self.patches]
        for obj, name, value in self.patches:
            setattr(obj, name, value)
        self.before = (self.case._dump(), sorted(self.authority.sessions),
                       [dict(c.subscriptions) for c in self.connections])
        return self

    def __exit__(self, exc_type, *exc):
        for obj, name, value in self.saved:
            if value is _MISSING:
                delattr(obj, name)
            else:
                setattr(obj, name, value)
        if exc_type is not None:
            return False
        after = (self.case._dump(), sorted(self.authority.sessions), [dict(c.subscriptions) for c in self.connections])
        self.case.assertEqual(self.counts, dict.fromkeys(self.counts, 0), 'a read-only lookup wrote/scheduled/restored')
        self.case.assertEqual(after[0], self.before[0], 'database changed during a read-only lookup')
        self.case.assertEqual(after[1], self.before[1], 'a live session was created/restored during lookup')
        self.case.assertEqual(after[2], self.before[2], 'lookup attached/subscribed a connection')
        print('COUNTERS', json.dumps(self.counts))
        return False


_MISSING = object()


class OriginalInputLookupV1(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.net = _NoNetwork().__enter__()
        self.tmp = Path(tempfile.mkdtemp(prefix='input-lookup-'))
        self._home = os.environ.get('HERMES_HOME')
        os.environ['HERMES_HOME'] = str(self.tmp)
        self.db = SessionDB(db_path=self.tmp / 'state.db')
        for sid in (SID, OTHER_SID, 'local-cold'):
            self.db.create_session(sid, source='desktop')
        self.db.create_session('api-route', source='api_server')
        self.epoch = begin_runtime_epoch(self.db, instance_id='current')
        self.runner = SimpleNamespace(_draining=False, config=SimpleNamespace(multiplex_profiles=False),
                                      _adapter_for_source=lambda source: None)
        self.authority = self._authority(self.epoch)
        from gateway import session_local_recovery, session_policy_refresh
        self._refresh = session_policy_refresh.refresh_resumed_policy
        async def no_refresh(*args, **kwargs):
            return None
        session_policy_refresh.refresh_resumed_policy = no_refresh
        # Harness boundary (as test_idle_admission_v1): synthetic LOCAL routes have no frozen local
        # receipt, so attach's history target is the logical id. Lookup itself never attaches.
        self._transcript_target = session_local_recovery.transcript_target
        session_local_recovery.transcript_target = lambda authority, ref: ref.session_id
        self.connections = []

    def _authority(self, epoch, *, live=(SID, OTHER_SID)):
        authority = SessionAuthority(self.runner, profile_id='owned', instance_id='current', db=self.db, epoch=epoch)
        authority._schedule = lambda ref: None
        for sid in live:
            authority.sessions[sid] = LiveSession(SimpleNamespace(platform=Platform.LOCAL, user_id='human',
                                                                  chat_id=sid), f'route-{sid}')
        authority.sessions['api-route'] = LiveSession(SimpleNamespace(platform=Platform.API_SERVER, user_id='human',
                                                                      chat_id='api-route'), 'route-api')
        return authority

    async def asyncTearDown(self):
        from gateway import session_local_recovery, session_policy_refresh
        session_policy_refresh.refresh_resumed_policy = self._refresh
        session_local_recovery.transcript_target = self._transcript_target
        for connection in self.connections:
            await connection.close()
        self.db.close()
        if self._home is None:
            os.environ.pop('HERMES_HOME', None)
        else:
            os.environ['HERMES_HOME'] = self._home
        shutil.rmtree(self.tmp, ignore_errors=True)
        self.net.__exit__(None, None, None)

    # helpers ---------------------------------------------------------------------------------
    def _dump(self):
        with self.db._read_ctx() as conn:
            return hashlib.sha256('\n'.join(conn.iterdump()).encode()).hexdigest()

    def _connection(self, identity=None, authority=None):
        connection = AuthorityConnection(authority or self.authority, object(), dict(identity or HUMAN))
        self.connections.append(connection)
        return connection

    async def _rpc(self, connection, method, **params):
        return await connection.dispatch({'id': 1, 'method': method, 'params': params})

    def _reason(self, reply):
        self.assertIn('error', reply, reply)
        return reply['error']['data']['reason']

    def _ok(self, reply):
        self.assertIn('result', reply, reply)
        return reply['result']

    async def _attach(self, connection, sid=SID):
        return self._ok(await self._rpc(connection, 'session.resume', session_id=sid, metadata_only=True))

    def _submit_params(self, generation, text='review exact artifact', input_id=INPUT, sid=SID):
        return {'session_id': sid, 'input_id': input_id, 'text': text, 'finite': False, 'unattended': False,
                'idle_fence': {'expected_generation': generation}}

    async def _prepare(self, connection, params, authority=None):
        with _ZeroWrites(self, authority or self.authority, connection):
            return await self._rpc(connection, 'prompt.prepare_input', **params)

    async def _lookup(self, connection, binding, authority=None, **override):
        params = {'session_id': binding['ref']['session_id'], 'input_id': binding['input_id'],
                  'payload_fingerprint': binding['payload_fingerprint'], 'idle_fence': binding['idle_fence']}
        params.update(override)
        with _ZeroWrites(self, authority or self.authority, connection):
            return await self._rpc(connection, 'prompt.lookup_input', **params)

    async def _prepared_and_submitted(self, connection=None):
        connection = connection or self._connection()
        generation = (await self._attach(connection))['execution_generation']
        params = self._submit_params(generation)
        binding = self._ok(await self._prepare(connection, params))
        receipt = self._ok(await self._rpc(connection, 'prompt.submit', **params))
        return connection, binding, receipt

    def _digest(self, request_id=INPUT, principal='human', sid=SID):
        with self.db._read_ctx() as conn:
            return conn.execute('SELECT payload_digest FROM session_admissions WHERE principal_id=? AND '
                                'target_session_id=? AND request_id=?', (principal, sid, request_id)).fetchone()[0]

    def _rows(self):
        with self.db._read_ctx() as conn:
            return conn.execute('SELECT COUNT(*) FROM session_admissions').fetchone()[0]

    # capability + contract -------------------------------------------------------------------
    async def test_capability_and_methods_are_advertised_by_the_canonical_contract(self):
        described = self._ok(await self._rpc(self._connection(), 'runtime.describe'))
        self.assertIn(VERSION, described['capabilities'])
        self.assertIn('idle-admission-v1', described['capabilities'])
        from tui_gateway.contracts.registry import CANONICAL_METHODS
        self.assertIn('prompt.prepare_input', CANONICAL_METHODS)
        self.assertIn('prompt.lookup_input', CANONICAL_METHODS)

    # exact binding -----------------------------------------------------------------------------
    async def test_prepared_binding_is_the_committed_fingerprint_and_lookup_matches_exactly(self):
        connection, binding, receipt = await self._prepared_and_submitted()
        self.assertEqual(binding['version'], VERSION)
        self.assertEqual(binding['ref'], {'profile_id': 'owned', 'session_id': SID})
        self.assertEqual(binding['input_id'], INPUT)
        self.assertEqual(binding['idle_fence'], {'expected_generation': 0})
        # Shared canonicalization: the fingerprint prepare returned IS the digest the admission committed.
        self.assertEqual(binding['payload_fingerprint'], self._digest())
        found = self._ok(await self._lookup(connection, binding))
        self.assertEqual((found['version'], found['state'], found['binding'], found['settled']),
                         (VERSION, 'found', 'exact', False))
        self.assertEqual(found['principal_binding'], binding['principal_binding'])
        self.assertEqual(found['admission'], {key: receipt[key] for key in (
            'admission_id', 'sequence', 'status', 'outcome', 'authority_epoch', 'execution_generation')})
        self.assertEqual(found['proof'], {'payload_fingerprint': binding['payload_fingerprint'],
                                          'idle_fence': {'expected_generation': 0}})
        self.assertNotIn('review exact artifact', json.dumps(found), 'prompt text must never cross the lookup')
        self.assertEqual(self._rows(), 1)

    async def test_prepare_is_pure_and_needs_no_attach_and_lookup_needs_no_attach_or_live_session(self):
        stranger_socket = self._connection()  # never attached
        params = self._submit_params(0)
        binding = self._ok(await self._prepare(stranger_socket, params))
        self.assertEqual(stranger_socket.subscriptions, {})
        self.assertEqual(self._rows(), 0, 'prepare must not admit')
        missing = self._ok(await self._lookup(stranger_socket, binding))
        self.assertEqual((missing['state'], missing['admission'], missing['proof'], missing['settled']),
                         ('not_found', None, None, False))

    async def test_duplicate_reads_are_identical_and_write_nothing(self):
        connection, binding, _ = await self._prepared_and_submitted()
        first = self._ok(await self._lookup(connection, binding))
        second = self._ok(await self._lookup(connection, binding))
        self.assertEqual(first, second)

    async def test_lost_ack_then_reconnect_finds_the_same_admission_with_the_same_principal(self):
        connection = self._connection()
        generation = (await self._attach(connection))['execution_generation']
        params = self._submit_params(generation)
        binding = self._ok(await self._prepare(connection, params))
        await self._rpc(connection, 'prompt.submit', **params)  # ACK lost: the reply is never read
        await connection.close()
        reconnected = self._connection()  # a new socket, same authenticated identity, no attach
        found = self._ok(await self._lookup(reconnected, binding))
        self.assertEqual((found['state'], found['binding']), ('found', 'exact'))
        self.assertEqual(found['principal_binding'], binding['principal_binding'])
        self.assertEqual(self._rows(), 1)

    async def test_owner_restart_reads_the_durable_row_without_restore_and_reports_unknown(self):
        _, binding, receipt = await self._prepared_and_submitted()
        claim_session_input(self.db, epoch=self.epoch, session_id=SID)  # started under the old owner
        epoch = begin_runtime_epoch(self.db, instance_id='current')
        recover_session_inputs(self.db, epoch=epoch)  # the new owner's own boot recovery: started -> unknown
        restarted = self._authority(epoch, live=())  # nothing restored yet in the new owner
        socket2 = self._connection(authority=restarted)
        found = self._ok(await self._lookup(socket2, binding, authority=restarted))
        self.assertEqual((found['state'], found['binding'], found['settled']), ('found', 'exact', False))
        self.assertEqual(found['admission']['admission_id'], receipt['admission_id'])
        self.assertEqual(found['admission']['status'], 'unknown')
        self.assertEqual(found['principal_binding'], binding['principal_binding'])
        self.assertNotIn(SID, restarted.sessions)

    async def test_not_found_is_never_a_prefix_trim_case_or_alias_match(self):
        connection, binding, _ = await self._prepared_and_submitted()
        for variant in (INPUT + ' ', ' ' + INPUT, INPUT[:-1], INPUT.upper(), 'mission-0001', INPUT + ':x'):
            missing = self._ok(await self._lookup(connection, binding, input_id=variant))
            self.assertEqual((missing['state'], missing['admission'], missing['input_id']),
                             ('not_found', None, variant))

    # foreign scope -------------------------------------------------------------------------
    async def test_foreign_principal_is_invisible_even_with_session_control(self):
        _, binding, _ = await self._prepared_and_submitted()
        stranger = self._connection(STRANGER)
        self.assertIn('session:control', stranger.actor.capabilities)
        missing = self._ok(await self._lookup(stranger, binding))
        self.assertEqual((missing['state'], missing['admission']), ('not_found', None))
        self.assertNotEqual(missing['principal_binding'], binding['principal_binding'])
        # The stranger's own row under the same input id does not answer the human either.
        admit_session_input(self.db, epoch=self.epoch, principal_id='stranger', session_id=OTHER_SID,
                            request_id='shared-id', payload={'text': 'x'})
        human = self._connection()
        other = self._ok(await self._lookup(human, binding, session_id=OTHER_SID, input_id='shared-id'))
        self.assertEqual(other['state'], 'not_found')

    async def test_json_cannot_name_or_search_a_principal_and_profile_is_bound(self):
        connection, binding, _ = await self._prepared_and_submitted()
        base = {'session_id': SID, 'input_id': INPUT, 'payload_fingerprint': binding['payload_fingerprint']}
        for extra in ({'principal_id': 'stranger'}, {'principal': 'human'}, {'user_id': 'human'},
                      {'admission_id': 'x'}, {'prefix': True}):
            self.assertEqual(self._reason(await self._rpc(connection, 'prompt.lookup_input', **base, **extra)),
                             'invalid_params', extra)
        self.assertEqual(self._reason(await self._rpc(connection, 'prompt.lookup_input', profile='other', **base)),
                         'profile_mismatch')
        foreign = self._connection({**HUMAN, 'profile_id': 'other'})
        self.assertEqual(self._reason(await self._rpc(foreign, 'prompt.lookup_input', **base)), 'profile_mismatch')
        reader = self._connection({**HUMAN, 'capabilities': ['session:read']})
        self.assertEqual(self._reason(await self._rpc(reader, 'prompt.lookup_input', **base)), 'permission_denied')
        unbound = self._connection({'profile_id': 'owned', 'instance_id': 'current'})
        self.assertEqual(self._reason(await self._rpc(unbound, 'prompt.lookup_input', **base)), 'permission_denied')

    async def test_foreign_session_input_fingerprint_and_fence_never_match(self):
        connection, binding, _ = await self._prepared_and_submitted()
        other_session = self._ok(await self._lookup(connection, binding, session_id=OTHER_SID))
        self.assertEqual(other_session['state'], 'not_found')
        other_text = self._ok(await self._prepare(connection, self._submit_params(0, text='altered')))
        self.assertNotEqual(other_text['payload_fingerprint'], binding['payload_fingerprint'])
        for override in ({'payload_fingerprint': other_text['payload_fingerprint']},
                         {'idle_fence': {'expected_generation': 1}}, {'idle_fence': None}):
            mismatch = self._ok(await self._lookup(connection, binding, **override))
            self.assertEqual((mismatch['state'], mismatch['binding'], mismatch['admission'], mismatch['proof'],
                              mismatch['settled']), ('found', 'mismatch', None, None, False), override)
        for bad in ('A' * 64, 'a' * 63, 'g' * 64, '', 'ａ' * 64):
            self.assertEqual(self._reason(await self._lookup(connection, binding, payload_fingerprint=bad)),
                             'invalid_params', bad)
        for bad_input in ('', 'x' * 1025, 7):
            self.assertEqual(self._reason(await self._lookup(connection, binding, input_id=bad_input)),
                             'invalid_params')
        self.assertEqual(self._reason(await self._lookup(connection, binding, idle_fence={'expected_generation': -1})),
                         'invalid_params')

    # unavailable / unknown -----------------------------------------------------------------
    async def test_retired_retiring_stale_owner_and_storage_failure_are_unavailable_not_absent(self):
        connection, binding, _ = await self._prepared_and_submitted()
        self.authority.retired = True
        retired = self._ok(await self._lookup(connection, binding))
        self.assertEqual((retired['state'], retired['reason'], retired['admission']), ('unavailable', 'runtime_retired', None))
        self.authority.retired = False
        self.authority.retiring = True
        retiring = self._ok(await self._lookup(connection, binding))
        self.assertEqual((retiring['state'], retiring['reason']), ('unavailable', 'runtime_draining'))
        self.authority.retiring = False
        begin_runtime_epoch(self.db, instance_id='successor')  # another owner took over the store
        stale = self._ok(await self._lookup(connection, binding))
        self.assertEqual((stale['state'], stale['reason'], stale['settled']), ('unavailable', 'stale_epoch', False))

    async def test_storage_failure_is_unavailable(self):
        connection, binding, _ = await self._prepared_and_submitted()
        import hermes_state_runtime
        original = hermes_state_runtime.find_input_binding
        def broken(*args, **kwargs):
            raise sqlite3.OperationalError('disk I/O error')
        hermes_state_runtime.find_input_binding = broken
        try:
            failed = self._ok(await self._lookup(connection, binding))
        finally:
            hermes_state_runtime.find_input_binding = original
        self.assertEqual((failed['state'], failed['reason'], failed['admission']),
                         ('unavailable', 'storage_unavailable', None))

    # settlement ordering -------------------------------------------------------------------
    async def test_committed_but_unpublished_settlement_reads_as_started_until_published(self):
        connection, binding, receipt = await self._prepared_and_submitted()
        claimed = claim_session_input(self.db, epoch=self.epoch, session_id=SID)
        live = self.authority.sessions[SID]
        with live.event_stream.lock:  # commit_and_publish's order: mask, then the SQLite write
            live.settling[claimed['admission_id']] = claimed
        settle_session_input(self.db, epoch=self.epoch, admission_id=claimed['admission_id'],
                             generation=claimed['generation'], outcome='completed')
        settling = self._ok(await self._lookup(connection, binding))
        self.assertEqual((settling['admission']['status'], settling['admission']['outcome'], settling['settled']),
                         ('started', None, False))
        with live.event_stream.lock:  # completion published
            live.settling.pop(claimed['admission_id'])
        settled = self._ok(await self._lookup(connection, binding))
        self.assertEqual((settled['admission']['status'], settled['admission']['outcome'], settled['settled']),
                         ('terminal', 'completed', True))
        self.assertEqual(settled['admission']['admission_id'], receipt['admission_id'])

    async def test_settlement_published_between_row_read_and_mask_check_never_reads_terminal_early(self):
        connection, binding, _ = await self._prepared_and_submitted()
        claimed = claim_session_input(self.db, epoch=self.epoch, session_id=SID)
        import hermes_state_runtime
        original = hermes_state_runtime.find_input_binding
        def read_then_settle(*args, **kwargs):
            row = original(*args, **kwargs)  # observed 'started'
            settle_session_input(self.db, epoch=self.epoch, admission_id=claimed['admission_id'],
                                 generation=claimed['generation'], outcome='completed')
            return row
        hermes_state_runtime.find_input_binding = read_then_settle
        try:
            reply = await self._rpc(connection, 'prompt.lookup_input', session_id=SID, input_id=INPUT,
                                    payload_fingerprint=binding['payload_fingerprint'], idle_fence=binding['idle_fence'])
        finally:
            hermes_state_runtime.find_input_binding = original
        raced = self._ok(reply)
        self.assertEqual((raced['admission']['status'], raced['settled']), ('started', False))

    # prepare refusals ------------------------------------------------------------------------
    async def test_prepare_refuses_attachments_cold_session_nonlocal_fence_and_unattended(self):
        connection = self._connection()
        params = self._submit_params(0)
        self.assertEqual(self._reason(await self._prepare(connection, {**params, 'attachments': []})), 'invalid_params')
        self.assertEqual(self._reason(await self._prepare(connection, {**params, 'session_id': 'local-cold'})),
                         'not_found')
        self.assertNotIn('local-cold', self.authority.sessions)
        self.assertEqual(self._reason(await self._prepare(connection, {**params, 'session_id': 'api-route'})),
                         'unsupported_control')
        self.assertEqual(self._reason(await self._prepare(connection, {**params, 'finite': True, 'unattended': True})),
                         'invalid_params')
        self.assertEqual(self._reason(await self._prepare(connection, {**params, 'idle_fence': {'expected_generation': '0'}})),
                         'invalid_params')
        stranger = self._connection(STRANGER)  # not this LOCAL session's user, not operator
        self.assertEqual(self._reason(await self._prepare(stranger, params)), 'permission_denied')
        self.assertEqual(self._rows(), 0)

    # old semantics -----------------------------------------------------------------------------
    async def test_existing_receipt_and_submit_semantics_are_unchanged(self):
        connection, _, receipt = await self._prepared_and_submitted()
        again = self._ok(await self._rpc(connection, 'prompt.receipt', session_id=SID,
                                         admission_id=receipt['admission_id']))
        self.assertEqual(again, receipt)
        # Exact retry still replays the same admission; the same id with another text is still a conflict.
        params = self._submit_params(0)
        self.assertEqual(self._ok(await self._rpc(connection, 'prompt.submit', **params))['admission_id'],
                         receipt['admission_id'])
        self.assertEqual(self._reason(await self._rpc(connection, 'prompt.submit', **{**params, 'text': 'altered'})),
                         'admission_conflict')
        # A stranger's receipt read by admission id is still refused by the LOCAL owner rule
        # (unchanged), and the input lookup never widens to another principal either.
        stranger = self._connection(STRANGER)
        other = await self._rpc(stranger, 'prompt.receipt', session_id=SID, admission_id=receipt['admission_id'])
        self.assertEqual(self._reason(other), 'permission_denied')  # LOCAL owner rule, unchanged
        self.assertEqual(self._rows(), 1)


if __name__ == '__main__':
    unittest.main()
