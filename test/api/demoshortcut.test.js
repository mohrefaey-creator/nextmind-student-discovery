// DEMO ONLY: a student under 18 can skip the parent step when (and only when) the server is started with DEMO_SHORTCUTS.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startApp, BASE, startSession } from './helpers.js';

const A1 = 'user-student-a1';
const URL = `${BASE}/students/${A1}/demo/guardian-authorization`;
const ME = '/api/v1/identity-stub/me';

async function with_app(opts, fn) {
  const app = await startApp(opts);
  try {
    await fn(app);
  } finally {
    await app.close();
  }
}

test('off by default: the shortcut is refused, nothing changes, and the screens are not told to offer it', () =>
  with_app({}, async (app) => {
    const s = await app.as(A1);
    assert.equal((await s.get(ME)).body.demo_shortcuts, false);
    const r = await s.post(URL);
    assert.equal(r.status, 403);
    assert.equal(r.body.reason, 'demo_shortcuts_disabled');
    assert.equal(Object.values(app.store.db.consent_records).filter((c) => c.demo_shortcut).length, 0);
    assert.ok(app.store.db.audit.some((e) => e.action === 'security.access_denied' && e.meta.reason === 'demo_shortcuts_disabled'), 'the attempt is recorded');
  }));

test('on: the student still has to give their own assent, then the shortcut stands in for the parent, and everything unlocks', () =>
  with_app({ demoShortcuts: true }, async (app) => {
    const s = await app.as(A1);
    assert.equal((await s.get(ME)).body.demo_shortcuts, true);
    assert.equal((await startSession(s, 'interest_exploratory')).status, 403, 'locked before anything');

    assert.equal((await s.post(`${BASE}/students/${A1}/consent`, { scope: 'assessment_processing', granted: true })).status, 200);
    assert.equal((await startSession(s, 'interest_exploratory')).status, 403, 'the student assent alone is not enough for a minor');

    const r = await s.post(URL);
    assert.equal(r.status, 200);
    assert.equal(r.body.changed, true);
    const sc = r.body.consent.scopes.assessment_processing;
    assert.equal(sc.active, true);
    assert.equal(sc.parties.guardian.state, 'granted');
    assert.equal(sc.parties.guardian.demo_shortcut, true, 'the consent state says this was the shortcut');
    assert.equal(sc.parties.student.demo_shortcut, false);
    assert.equal((await startSession(s, 'interest_exploratory')).status, 201, 'the assessment can start');

    const rec = Object.values(app.store.db.consent_records).find((c) => c.demo_shortcut);
    assert.equal(rec.actor_role, 'guardian');
    assert.equal(rec.actor_id, A1, 'the record is honest about who acted: the student');
    assert.equal(rec.method, 'demo_shortcut');
    const audit = app.store.db.audit.find((e) => e.action === 'consent.demo_guardian_shortcut');
    assert.equal(audit.actor.id, A1);
    assert.equal(audit.meta.demo_shortcut, true);
    assert.ok(app.store.db.outbox.some((e) => e.event_type === 'discovery.consent.granted' && e.payload.party === 'guardian' && e.payload.student_id === A1));

    const again = await s.post(URL);
    assert.equal(again.body.changed, false, 'repeating it changes nothing');
  }));

test('a real guardian can still withdraw what the shortcut granted, and it locks again', () =>
  with_app({ demoShortcuts: true }, async (app) => {
    const s = await app.as(A1);
    await s.post(`${BASE}/students/${A1}/consent`, { scope: 'assessment_processing', granted: true });
    await s.post(URL);
    const g = await app.as('user-guardian-a1');
    const r = await g.post(`${BASE}/students/${A1}/consent`, { scope: 'assessment_processing', granted: false });
    assert.equal(r.status, 200);
    assert.equal(r.body.consent.scopes.assessment_processing.active, false);
    assert.equal(r.body.consent.scopes.assessment_processing.parties.guardian.demo_shortcut, false, 'the new record is the guardian\'s own');
    assert.equal((await startSession(s, 'interest_exploratory')).status, 403);
  }));

test('only a student for themselves, only a minor, never in synthetic-off mode, never during an incident', () =>
  with_app({ demoShortcuts: true }, async (app) => {
    // someone else's student, other roles
    assert.equal((await (await app.as('user-student-a2')).post(URL)).status, 403);
    assert.equal((await (await app.as('user-student-b1')).post(URL)).body.reason, 'not_available');
    for (const who of ['user-guardian-a1', 'user-counselor-a', 'user-tenant-admin-a', 'user-steward-1']) {
      const r = await (await app.as(who)).post(URL);
      assert.equal(r.status, 403, who);
    }
    assert.equal((await app.anon().post(URL)).status, 401);
    // an adult has no guardian step to skip
    const adult = await (await app.as('user-student-b1')).post(`${BASE}/students/user-student-b1/demo/guardian-authorization`);
    assert.equal(adult.status, 409);
    assert.equal(adult.body.code, 'guardian_not_required');
    assert.equal(Object.values(app.store.db.consent_records).filter((c) => c.demo_shortcut).length, 0);
    // incident: granting is suspended
    const sec = await app.as('user-security');
    await sec.post(`${BASE}/admin/kill-switch`, { enabled: true, reason: 'drill for the demo shortcut' });
    assert.equal((await (await app.as(A1)).post(URL)).status, 503);
  }));

test('the flag is ignored when synthetic mode is off', () =>
  with_app({ demoShortcuts: true, syntheticMode: false }, async (app) => {
    const s = await app.as(A1);
    assert.equal((await s.get(ME)).body.demo_shortcuts, false);
    assert.equal((await s.post(URL)).body.reason, 'demo_shortcuts_disabled');
  }));
