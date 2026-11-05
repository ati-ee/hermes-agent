"""idle-admission-v1: an idle-only ``prompt.submit`` and a metadata-only ``session.resume``.

Real parser (``AuthorityConnection.dispatch`` + canonical contracts) -> ``SessionAuthority`` ->
real SQLite ``SessionDB`` admission transaction. No agent, model, network or installed profile:
a disposable HERMES_HOME per test and ``_schedule`` stubbed so nothing executes. Stdlib
``unittest`` (runs without pytest): ``python -m unittest tests.gateway.test_idle_admission_v1``.
"""
import asyncio
import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault('HERMES_TEST_ISOLATION', '1')  # contract violations raise (registry.STRICT)

from gateway.config import Platform
from gateway.session_authority import LiveSession, SessionAuthority
from gateway.session_contract import SessionActor, SessionRef, Submission
from gateway.session_controls import AuthorityConnection
from hermes_state import SessionDB
from hermes_state_runtime import (
    RuntimeStoreError, admit_session_input, begin_runtime_epoch, claim_session_input, find_session_admission,
)

SID = 'local-reviewer-synthetic-0001'
# The private native bootstrap grant (provider ``local`` + server-stamped capabilities): its subject
# is the local session's own user, as for the Workspace bridge's attach-only client.
CAPS = ['session:read', 'session:submit', 'session:control', 'session:approve', 'session:respond']
HUMAN = {'user_id': 'human', 'provider': 'local', 'profile_id': 'owned', 'instance_id': 'current', 'capabilities': CAPS}
DASHBOARD = {'user_id': 'human', 'profile_id': 'owned', 'instance_id': 'current'}  # namespaced subject


class _NoNetwork:
    """Any socket use inside a test is a failure, not a silent pass."""

    def __enter__(self):
        self._orig = socket.socket.connect, socket.create_connection
        def refuse(*args, **kwargs):
            raise AssertionError('network use in idle-admission test')
        socket.socket.connect, socket.create_connection = refuse, refuse
        return self

    def __exit__(self, *exc):
        socket.socket.connect, socket.create_connection = self._orig


class IdleAdmissionV1(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.net = _NoNetwork().__enter__()
        self.tmp = Path(tempfile.mkdtemp(prefix='idle-admission-'))
        self._home = os.environ.get('HERMES_HOME')
        os.environ['HERMES_HOME'] = str(self.tmp)
        self.db = SessionDB(db_path=self.tmp / 'state.db')
        self.db.create_session(SID, source='desktop')
        self.db.create_session('local-cold', source='desktop')
        self.db.create_session('api-route', source='api_server')
        self.epoch = begin_runtime_epoch(self.db, instance_id='current')
        self.runner = SimpleNamespace(_draining=False, config=SimpleNamespace(multiplex_profiles=False),
                                      _adapter_for_source=lambda source: None)
        self.authority = self._authority(self.epoch)
        self.refreshes = []
        from gateway import session_local_recovery, session_policy_refresh
        self._refresh = session_policy_refresh.refresh_resumed_policy
        async def record_refresh(*args, **kwargs):
            self.refreshes.append(args)
        session_policy_refresh.refresh_resumed_policy = record_refresh
        # Harness boundary: these synthetic LOCAL routes carry no frozen local receipt/policy (that
        # needs a full SessionStore + LocalSessionAdapter). Their physical transcript IS the logical
        # session (no compression), which is all ``attach``'s history read resolves through the
        # receipt. Admission, fence, authorization and the store transaction are unpatched.
        self._transcript_target = session_local_recovery.transcript_target
        session_local_recovery.transcript_target = lambda authority, ref: ref.session_id
        self.connections = []

    def _authority(self, epoch):
        authority = SessionAuthority(self.runner, profile_id='owned', instance_id='current', db=self.db, epoch=epoch)
        authority._schedule = lambda ref: None  # nothing executes: admissions stay as committed
        authority.sessions[SID] = LiveSession(SimpleNamespace(platform=Platform.LOCAL, user_id='human',
                                                              chat_id=SID), 'route-reviewer')
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
    def _connection(self, identity=None, authority=None):
        connection = AuthorityConnection(authority or self.authority, object(), dict(identity or HUMAN))
        self.connections.append(connection)
        return connection

    async def _rpc(self, connection, method, **params):
        reply = await connection.dispatch({'id': 1, 'method': method, 'params': params})
        return reply

    async def _attach(self, connection, sid=SID):
        reply = await self._rpc(connection, 'session.resume', session_id=sid, metadata_only=True)
        self.assertIn('result', reply, reply)
        return reply['result']

    async def _fenced(self, connection, request_id, generation, text='review exact artifact', sid=SID):
        return await self._rpc(connection, 'prompt.submit', session_id=sid, input_id=request_id, text=text,
                               idle_fence={'expected_generation': generation})

    def _rows(self, sid=SID):
        with self.db._read_ctx() as conn:
            return [dict(row) for row in conn.execute(
                'SELECT admission_id, request_id, principal_id, status, payload_json, seq FROM session_admissions '
                'WHERE target_session_id=? ORDER BY seq', (sid,))]

    def _other(self, request_id='other-work', principal='someone-else'):
        return admit_session_input(self.db, epoch=self.epoch, principal_id=principal, session_id=SID,
                                   request_id=request_id, payload={'text': 'competing work'})

    def _reason(self, reply):
        self.assertIn('error', reply, reply)
        return reply['error']['data']['reason']

    # capability + metadata attach ------------------------------------------------------------
    async def test_capability_is_advertised(self):
        described = await self._rpc(self._connection(), 'runtime.describe')
        self.assertIn('idle-admission-v1', described['result']['capabilities'])
        self.assertIn('durable-admission-v1', described['result']['capabilities'])

    async def test_metadata_attach_returns_no_history_pending_text_or_policy_refresh(self):
        self.db.append_message(SID, role='user', content='PRIVATE-HISTORY-MARKER')
        self._other('queued-private', principal='human')
        snapshot = await self._attach(self._connection())
        dumped = json.dumps(snapshot)
        self.assertNotIn('PRIVATE-HISTORY-MARKER', dumped)
        self.assertNotIn('competing work', dumped)
        self.assertEqual((snapshot['messages'], snapshot['pending'], snapshot['prompts']), ([], [], []))
        self.assertEqual(snapshot['message_count'], 1)
        self.assertEqual((snapshot['pending_count'], snapshot['execution_state']), (1, 'idle'))
        self.assertEqual(snapshot['execution_generation'], 0)
        self.assertEqual(snapshot['info'], {'desktop_protocol': 'hermes-gateway-v1', 'source': 'desktop',
                                            'profile_id': 'owned', 'yolo': False})
        self.assertEqual(self.refreshes, [], 'metadata attach must not refresh the session policy')

    async def test_metadata_attach_fails_closed_for_cold_unknown_nonlocal_historic_and_extra_keys(self):
        connection = self._connection()
        self.assertEqual(self._reason(await self._rpc(connection, 'session.resume', session_id='local-cold',
                                                      metadata_only=True)), 'not_found')
        self.assertNotIn('local-cold', self.authority.sessions, 'a cold session must not be restored/mounted')
        self.assertEqual(self._reason(await self._rpc(connection, 'session.resume', session_id='missing-0001',
                                                      metadata_only=True)), 'not_found')
        self.assertEqual(self._reason(await self._rpc(connection, 'session.resume', session_id='api-route',
                                                      metadata_only=True)), 'unsupported_control')
        # Main's ``LiveSession.detached`` (29abd70464) replaced the baseline's history_mount/superseded flags.
        from unittest.mock import PropertyMock, patch as mock_patch
        from gateway.session_authority import LiveSession
        with mock_patch.object(LiveSession, 'detached', new_callable=PropertyMock, return_value=True):
            self.assertEqual(self._reason(await self._rpc(connection, 'session.resume', session_id=SID,
                                                          metadata_only=True)), 'unsupported_control')
        for extra in ({'display_projection': True}, {'title': 'x'}, {'omit_messages': True}):
            reply = await self._rpc(connection, 'session.resume', session_id=SID, metadata_only=True, **extra)
            self.assertEqual(self._reason(reply), 'invalid_params', extra)
        self.assertEqual(connection.subscriptions, {})

    # positive fenced admission ---------------------------------------------------------------
    async def test_fenced_submit_admits_one_new_admission_in_the_same_existing_session(self):
        connection = self._connection()
        snapshot = await self._attach(connection)
        reply = await self._fenced(connection, 'mission-1:assignment-7', snapshot['execution_generation'])
        receipt = reply['result']
        self.assertEqual((receipt['ref']['session_id'], receipt['ref']['profile_id'], receipt['status']),
                         (SID, 'owned', 'queued'))
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['admission_id'], receipt['admission_id'])
        self.assertEqual(json.loads(rows[0]['payload_json'])['idle_fence_v1'], {'expected_generation': 0})
        from gateway.session_operator import check_local_input
        row = find_session_admission(self.db, principal_id='human', session_id=SID, request_id='mission-1:assignment-7')
        check_local_input(self.authority, SessionRef('owned', SID), row)  # execution would accept its payload
        print('COUNTERS positive', json.dumps({'admissions': len(rows), 'sessions_created': 0}))

    async def test_legacy_queue_submit_is_unchanged_while_busy(self):
        connection = self._connection()
        await self._attach(connection)
        self._other()
        reply = await self._rpc(connection, 'prompt.submit', session_id=SID, input_id='plain', text='plain')
        self.assertEqual(reply['result']['status'], 'queued')
        rows = self._rows()
        self.assertEqual(len(rows), 2)
        self.assertNotIn('idle_fence_v1', json.loads(rows[1]['payload_json']))

    # busy / stale refusals ---------------------------------------------------------------------
    async def test_fence_refuses_queued_started_unknown_worker_and_settling_work(self):
        connection = self._connection()
        generation = (await self._attach(connection))['execution_generation']
        self._other('queued-1')
        self.assertEqual(self._reason(await self._fenced(connection, 'f-queued', generation)), 'session_busy')
        claimed = claim_session_input(self.db, epoch=self.epoch, session_id=SID)
        self.assertEqual(self._reason(await self._fenced(connection, 'f-started', claimed['generation'])),
                         'session_busy')
        self.db._execute_write(lambda conn: conn.execute(
            "UPDATE session_admissions SET status='unknown' WHERE admission_id=?", (claimed['admission_id'],)))
        self.assertEqual(self._reason(await self._fenced(connection, 'f-unknown', claimed['generation'])),
                         'session_busy')
        self.db._execute_write(lambda conn: conn.execute(
            "UPDATE session_admissions SET status='terminal', outcome='completed' WHERE admission_id=?",
            (claimed['admission_id'],)))
        self.db._execute_write(lambda conn: conn.execute(
            "INSERT INTO worker_executions(execution_id,session_id,kind,owner_epoch,generation,status,adoption_digest) "
            "VALUES('w1',?,'compute',?,?,'running','d')", (SID, self.epoch, claimed['generation'])))
        self.assertEqual(self._reason(await self._fenced(connection, 'f-worker', claimed['generation'])),
                         'session_busy')
        self.db._execute_write(lambda conn: conn.execute("UPDATE worker_executions SET status='terminal'"))
        self.authority.executing[SID] = claimed['generation']
        self.assertEqual(self._reason(await self._fenced(connection, 'f-executing', claimed['generation'])),
                         'session_busy')
        self.authority.executing.pop(SID)
        accepted = await self._fenced(connection, 'f-idle-again', claimed['generation'])
        self.assertEqual(accepted['result']['status'], 'queued')
        fenced_rows = [r for r in self._rows() if r['request_id'].startswith('f-')]
        self.assertEqual([r['request_id'] for r in fenced_rows], ['f-idle-again'])

    async def test_stale_generation_is_refused_with_current_generation(self):
        connection = self._connection()
        generation = (await self._attach(connection))['execution_generation']
        self._other('advance')
        claim_session_input(self.db, epoch=self.epoch, session_id=SID)  # generation + 1, then settle it
        self.db._execute_write(lambda conn: conn.execute(
            "UPDATE session_admissions SET status='terminal', outcome='completed' WHERE request_id='advance'"))
        reply = await self._fenced(connection, 'f-stale', generation)
        self.assertEqual(self._reason(reply), 'stale_generation')
        self.assertEqual(reply['error']['data']['execution_generation'], generation + 1)
        self.assertEqual(self._rows()[-1]['request_id'], 'advance')

    # replay / conflict / restart -------------------------------------------------------------
    async def test_exact_replay_after_ack_loss_returns_same_admission_even_when_busy_and_after_restart(self):
        connection = self._connection()
        generation = (await self._attach(connection))['execution_generation']
        first = (await self._fenced(connection, 'mission-1:assignment-7', generation))['result']
        claim_session_input(self.db, epoch=self.epoch, session_id=SID)  # now running: busy for NEW work
        replay = (await self._fenced(connection, 'mission-1:assignment-7', generation))['result']
        self.assertEqual(replay['admission_id'], first['admission_id'])
        self.assertEqual(len(self._rows()), 1)
        # Owner restart: a new epoch/authority over the same durable store answers the same receipt.
        epoch = begin_runtime_epoch(self.db, instance_id='current')
        self.epoch = epoch
        restarted = self._authority(epoch)
        connection2 = self._connection(authority=restarted)
        await self._attach(connection2)
        again = (await self._fenced(connection2, 'mission-1:assignment-7', generation))['result']
        self.assertEqual(again['admission_id'], first['admission_id'])
        self.assertEqual(len(self._rows()), 1)
        found = find_session_admission(self.db, principal_id='human', session_id=SID,
                                       request_id='mission-1:assignment-7')
        self.assertEqual(found['admission_id'], first['admission_id'])

    async def test_same_request_with_other_fence_body_or_no_fence_is_a_conflict(self):
        connection = self._connection()
        generation = (await self._attach(connection))['execution_generation']
        await self._fenced(connection, 'r', generation)
        self.assertEqual(self._reason(await self._fenced(connection, 'r', generation + 1)), 'admission_conflict')
        self.assertEqual(self._reason(await self._fenced(connection, 'r', generation, text='altered')),
                         'admission_conflict')
        plain = await self._rpc(connection, 'prompt.submit', session_id=SID, input_id='r', text='review exact artifact')
        self.assertEqual(self._reason(plain), 'admission_conflict')
        self.assertEqual(len(self._rows()), 1)

    async def test_malformed_fences_are_rejected_without_rows(self):
        connection = self._connection()
        await self._attach(connection)
        for index, fence in enumerate(({'expected_generation': True}, {'expected_generation': '0'},
                                       {'expected_generation': -1}, {'expected_generation': 0.0}, {},
                                       {'expected_generation': 0, 'extra': 1}, [0], None, 0)):
            reply = await self._rpc(connection, 'prompt.submit', session_id=SID, input_id=f'bad-{index}', text='x',
                                    idle_fence=fence)
            # An explicit ``null`` fence is refused too (fail closed), never read as a legacy admission.
            self.assertEqual(self._reason(reply), 'invalid_params', fence)
        self.assertEqual(self._rows(), [])

    # authority gates ---------------------------------------------------------------------------
    async def test_unsubscribed_readonly_or_foreign_profile_callers_cannot_submit_fenced(self):
        stranger = self._connection()
        self.assertEqual(self._reason(await self._fenced(stranger, 'no-attach', 0)), 'permission_denied')
        reader = self._connection({**HUMAN, 'capabilities': ['session:read']})
        await self._attach(reader)
        self.assertIn(self._reason(await self._fenced(reader, 'read-only', 0)), {'permission_denied'})
        other_subject = self._connection(DASHBOARD)  # not the local session's user, not operator
        self.assertEqual(self._reason(await self._rpc(other_subject, 'session.resume', session_id=SID,
                                                      metadata_only=True)), 'permission_denied')
        foreign = self._connection({**HUMAN, 'profile_id': 'other'})
        self.assertIn(self._reason(await self._rpc(foreign, 'session.resume', session_id=SID, metadata_only=True)),
                      {'profile_mismatch', 'permission_denied'})
        self.assertEqual(self._rows(), [])

    async def test_non_local_route_and_kanban_producers_cannot_use_the_fence(self):
        actor = SessionActor('human', 'owned', frozenset({'session:submit'}), 't')
        request = Submission('api-1', SessionRef('owned', 'api-route'),
                             {'text': 'x', 'idle_fence': {'expected_generation': 0}}, 'queue')
        with self.assertRaises(RuntimeStoreError) as refused:
            await self.authority.submit(actor, request)
        self.assertEqual(refused.exception.reason, 'unsupported_control')
        request = Submission('kb-1', SessionRef('owned', SID), {'text': 'x', 'idle_fence': {'expected_generation': 0}},
                             'queue')
        with self.assertRaises(RuntimeStoreError) as refused:
            await self.authority.submit(actor, request, _kanban_card={'card': 'c'})
        self.assertEqual(refused.exception.reason, 'unsupported_control')
        self.assertEqual(self._rows('api-route') + self._rows(), [])

    async def test_draining_retiring_and_restart_wait_refuse_fenced_admission(self):
        connection = self._connection()
        await self._attach(connection)
        self.runner._draining = True
        self.assertEqual(self._reason(await self._fenced(connection, 'drain', 0)), 'runtime_draining')
        self.runner._draining = False
        self.authority.retiring = True
        self.assertEqual(self._reason(await self._fenced(connection, 'retire', 0)), 'runtime_draining')
        self.authority.retiring = False
        # Even an operator socket inside a restart's after-turn wait (queue_only) is refused.
        from gateway import drain_control
        original = drain_control.restart_wait_open
        drain_control.restart_wait_open = lambda runner: True
        try:
            self.runner._draining = True
            request = Submission('wait', SessionRef('owned', SID), {'text': 'x', 'idle_fence': {'expected_generation': 0}},
                                 'queue')
            actor = SessionActor('human', 'owned', frozenset({'session:submit'}), 't')
            with self.assertRaises(RuntimeStoreError) as refused:
                await self.authority.submit(actor, request, queue_while_restarting=True)
            self.assertEqual(refused.exception.reason, 'runtime_draining')
        finally:
            drain_control.restart_wait_open = original
            self.runner._draining = False
        self.assertEqual(self._rows(), [])

    # races in the real SQLite admission transaction --------------------------------------------
    def _fenced_store_admit(self, request_id, generation, hook=None):
        guard = self.authority._idle_admission_guard(SID, generation)
        def guarded(conn):
            guard(conn)
            if hook is not None:
                hook()
        payload = {'text': 'review', 'idle_fence_v1': {'expected_generation': generation}}
        return admit_session_input(self.db, epoch=self.epoch, principal_id='human', session_id=SID,
                                   request_id=request_id, payload=payload,
                                   _authorize_write=self.authority._admission_gate(guarded))

    async def test_barrier_two_different_fenced_requests_cannot_both_pass(self):
        barrier = threading.Barrier(2)
        outcomes = {}
        def run(request_id):
            barrier.wait()
            try:
                outcomes[request_id] = self._fenced_store_admit(request_id, 0)['admission_id']
            except RuntimeStoreError as exc:
                outcomes[request_id] = exc.reason
        threads = [threading.Thread(target=run, args=(name,)) for name in ('mission-A:asg-1', 'mission-B:asg-2')]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        self.assertEqual(sorted(v == 'session_busy' for v in outcomes.values()), [False, True], outcomes)
        self.assertEqual(len(self._rows()), 1)
        print('COUNTERS barrier', json.dumps({'admitted': 1, 'refused_busy': 1, 'rows': len(self._rows())}))

    async def test_competing_arrival_inside_fence_window_commits_only_after_the_fenced_insert(self):
        checked, finished = threading.Event(), {}
        def hold():  # inside the fenced write transaction, after the idle checks passed
            checked.set()
            time.sleep(0.4)  # health: allow HX013 -- holds the fenced write open while the competitor's write blocks on SQLite's lock; nothing signals a blocked writer
        def fenced():
            finished['fenced'] = self._fenced_store_admit('fenced', 0, hook=hold)
        def competitor():
            checked.wait(10)
            finished['other'] = self._other('arrived-during-window')
        threads = [threading.Thread(target=fenced), threading.Thread(target=competitor)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        rows = self._rows()
        self.assertEqual([r['request_id'] for r in rows], ['fenced', 'arrived-during-window'])
        # The competitor queued BEHIND the fenced admission; a later fenced request now sees it busy.
        with self.assertRaises(RuntimeStoreError) as refused:
            self._fenced_store_admit('late-fenced', 0)
        self.assertEqual(refused.exception.reason, 'session_busy')
        self.assertEqual(len(self._rows()), 2)

    async def test_competing_arrival_before_the_fenced_insert_refuses_it(self):
        connection = self._connection()
        generation = (await self._attach(connection))['execution_generation']  # observed idle
        self._other('arrived-after-observation')
        self.assertEqual(self._reason(await self._fenced(connection, 'too-late', generation)), 'session_busy')
        self.assertEqual([r['request_id'] for r in self._rows()], ['arrived-after-observation'])

    async def test_concurrent_authority_fenced_submits_admit_exactly_one(self):
        connection = self._connection()
        generation = (await self._attach(connection))['execution_generation']
        replies = await asyncio.gather(*(self._fenced(connection, f'm{n}:a{n}', generation) for n in range(4)))
        admitted = [r for r in replies if 'result' in r]
        self.assertEqual(len(admitted), 1, replies)
        self.assertEqual(sorted(self._reason(r) for r in replies if 'error' in r), ['session_busy'] * 3)
        self.assertEqual(len(self._rows()), 1)


if __name__ == '__main__':
    unittest.main()
