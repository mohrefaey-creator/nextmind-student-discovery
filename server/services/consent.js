import { randomUUID } from 'node:crypto';
import { CONSENT_SCOPES, POLICY } from '../config.js';
import { audit, emit } from '../audit.js';
import { authorize, consentState, guardianRequired } from '../policy.js';
import { AppError, badRequest, conflict, forbidden } from '../errors.js';
import { nextSeq, auditCounselorRead } from './common.js';

export function getConsent(ctx, studentId) {
  const { student, consent } = authorize(ctx, studentId, 'consent.read');
  auditCounselorRead(ctx, student, 'access.consent_read');
  return consent;
}

/** Sessions follow consent: suspended while processing consent is inactive, resumed when it returns. */
export function reconcileSessions(ctx, studentId) {
  const { db } = ctx;
  const active = consentState(db, studentId, ctx.now).scopes.assessment_processing.active;
  for (const s of Object.values(db.sessions)) {
    if (s.student_id !== studentId) continue;
    if (s.status === 'in_progress' && !active) s.status = 'suspended_consent';
    else if (s.status === 'suspended_consent' && active) s.status = 'in_progress';
  }
}

export function setConsent(ctx, studentId, body) {
  const { db, actor } = ctx;
  authorize(ctx, studentId, 'consent.write');
  const scope = body?.scope;
  if (typeof scope !== 'string' || !Object.hasOwn(CONSENT_SCOPES, scope)) throw badRequest('unknown_scope', 'Unknown consent scope.');
  if (typeof body.granted !== 'boolean') throw badRequest('invalid_body', '`granted` must be true or false.');
  // During an incident people can still withdraw (a data-subject right and the safe direction), but nothing new is granted.
  if (db.meta.kill_switch.enabled && body.granted) throw new AppError(503, 'module_suspended', 'Module suspended', 'Granting consent is unavailable while the module is suspended.');
  // Guardians authorise processing for a minor; every other scope belongs to the student.
  if (actor.role === 'guardian' && scope !== 'assessment_processing') {
    throw forbidden('guardian_scope_not_permitted', 'A guardian can authorise or withdraw only assessment processing.', { action: 'security.access_denied', tenant_id: actor.tenant_id, subject_ref: `student:${studentId}`, meta: { reason: 'guardian_scope_not_permitted', scope } });
  }
  const before = consentState(db, studentId, ctx.now);
  const current = before.scopes[scope].parties[actor.role];
  const nextState = body.granted ? 'granted' : 'withdrawn';
  if (current.state === nextState) return { changed: false, consent: before }; // idempotent

  const record = {
    id: randomUUID(),
    seq: nextSeq(db.consent_records),
    subject_id: studentId,
    tenant_id: db.users[studentId].tenant_id,
    actor_id: actor.id,
    actor_role: actor.role,
    scope,
    state: nextState,
    legal_basis_ref: POLICY.legal_basis_ref,
    policy_version: POLICY.policy_version,
    method: 'in_app_explicit_choice',
    evidence_ref: null,
    created_at: ctx.now.toISOString(),
  };
  db.consent_records[record.id] = record;

  if (!body.granted) {
    // Stop disallowed processing and sharing now; retention outcome is queued for a human/policy decision.
    for (const sh of Object.values(db.shares)) {
      if (sh.student_id === studentId && !sh.revoked_at && (scope === 'assessment_processing' || scope === 'guardian_summary_sharing')) {
        sh.revoked_at = ctx.now.toISOString();
        sh.revoked_reason = `consent_withdrawn:${scope}`;
      }
    }
    // One open retention decision per student and scope, however often the choice is toggled.
    const open = Object.values(db.retention_tasks).some((t) => t.student_id === studentId && t.scope === scope && t.state === 'queued_for_policy_decision');
    if (!open) {
      const taskId = randomUUID();
      db.retention_tasks[taskId] = { id: taskId, student_id: studentId, tenant_id: record.tenant_id, scope, state: 'queued_for_policy_decision', policy: 'PENDING-RETENTION-SCHEDULE', created_at: record.created_at };
    }
  }
  reconcileSessions(ctx, studentId);
  const after = consentState(db, studentId, ctx.now);
  audit(ctx, { action: body.granted ? 'consent.granted' : 'consent.withdrawn', tenant_id: record.tenant_id, subject_ref: `student:${studentId}`, before: before.scopes[scope], after: after.scopes[scope], meta: { scope, party: actor.role } });
  emit(ctx, body.granted ? 'discovery.consent.granted' : 'discovery.consent.withdrawn', record.id, { student_id: studentId, scope, party: actor.role }, record.tenant_id);
  return { changed: true, consent: after };
}

/**
 * DEMO ONLY. A student under 18 skips the parent step so every screen can be reviewed. It writes the same kind of
 * record a guardian's grant writes, so nothing downstream changes, but the record says who really acted
 * (the student) and that it was the demo shortcut; the audit log names the action. Off unless DEMO_SHORTCUTS=true,
 * and never while synthetic mode is off. The student's own assent is not touched: they still have to give it.
 */
export function demoGuardianAuthorization(ctx, studentId) {
  const { db, actor } = ctx;
  ctx.intent = 'consent.demo_guardian_shortcut';
  const deny = (reason, detail) =>
    forbidden(reason, detail, { action: 'security.access_denied', tenant_id: actor?.tenant_id ?? null, subject_ref: `student:${studentId}`, meta: { reason, intent: ctx.intent } });
  if (!ctx.config.demoShortcuts || !ctx.config.syntheticMode) throw deny('demo_shortcuts_disabled', 'The demo shortcut is turned off on this server.');
  if (actor?.role !== 'student') throw deny('role_not_permitted', 'Only the student can use the demo shortcut.');
  const { student } = authorize(ctx, studentId, 'consent.write');
  if (db.meta.kill_switch.enabled) throw new AppError(503, 'module_suspended', 'Module suspended', 'Granting consent is unavailable while the module is suspended.');
  if (!guardianRequired(student, ctx.now)) throw conflict('guardian_not_required', 'This student is an adult, so no guardian authorization is involved.');

  const scope = 'assessment_processing';
  const before = consentState(db, studentId, ctx.now);
  if (before.scopes[scope].parties.guardian.state === 'granted') return { changed: false, consent: before };
  const record = {
    id: randomUUID(),
    seq: nextSeq(db.consent_records),
    subject_id: studentId,
    tenant_id: student.tenant_id,
    actor_id: actor.id, // the student, honestly: no guardian acted
    actor_role: 'guardian', // the role the record stands in for
    scope,
    state: 'granted',
    legal_basis_ref: POLICY.legal_basis_ref,
    policy_version: POLICY.policy_version,
    method: 'demo_shortcut',
    demo_shortcut: true,
    evidence_ref: null,
    created_at: ctx.now.toISOString(),
  };
  db.consent_records[record.id] = record;
  reconcileSessions(ctx, studentId);
  const after = consentState(db, studentId, ctx.now);
  audit(ctx, { action: 'consent.demo_guardian_shortcut', tenant_id: student.tenant_id, subject_ref: `student:${studentId}`, before: before.scopes[scope], after: after.scopes[scope], meta: { scope, party: 'guardian', demo_shortcut: true } });
  emit(ctx, 'discovery.consent.granted', record.id, { student_id: studentId, scope, party: 'guardian' }, record.tenant_id);
  return { changed: true, consent: after };
}
