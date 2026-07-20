// pstonn-watchdog — an independent dead-man's switch for p.stonn.
//
// Every run polls p.stonn's /status endpoint. A healthy poll refreshes a cached
// (encrypted) copy of the notify roster. If p.stonn is unreachable or its work
// loop is stalled for long enough, this tells the affected users — from the
// cached roster, since p.stonn itself is the thing that's down — to set their
// permit directly with the council, and pings the operator sooner.
//
// It runs on GitHub Actions (off the p.stonn VPS on purpose) and keeps its state
// in the repo between runs. No secrets live in the code; everything comes from
// the workflow env (GitHub Secrets).

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import nodemailer from 'nodemailer';

const env = process.env;
const need = (k) => {
  const v = env[k];
  if (!v) throw new Error(`missing required env ${k}`);
  return v;
};

// The council portal users are sent to so they can sort their permit themselves.
const COUNCIL_PORTAL = 'https://parkingpermits.stonnington.vic.gov.au/';

const STATUS_URL = need('STATUS_URL'); // e.g. https://p.example.org/status
const STATUS_TOKEN = need('STATUS_TOKEN');
const ROSTER_KEY = Buffer.from(need('ROSTER_KEY'), 'hex'); // 32 bytes (64 hex chars)
if (ROSTER_KEY.length !== 32) throw new Error('ROSTER_KEY must be 32 bytes (64 hex chars)');

// A short outage rarely matters: an un-applied permit still gets the default ~1h
// of parking, and an already-applied plate stays on the council record even if
// p.stonn is down. So alarm users only after a sustained outage, but ping the
// operator sooner.
const USER_THRESHOLD_MIN = Number(env.DOWN_THRESHOLD_MIN || 45);
const OPERATOR_THRESHOLD_MIN = Number(env.OPERATOR_ALERT_MIN || 10);

const NTFY_BASE = (env.NTFY_BASE || '').replace(/\/+$/, '');
const ADMIN_EMAIL = env.ADMIN_EMAIL || '';
const ADMIN_NTFY_TOPIC = env.ADMIN_NTFY_TOPIC || '';

const STATE_DIR = 'state';
const STATE_FILE = `${STATE_DIR}/state.json`;
const ROSTER_FILE = `${STATE_DIR}/roster.enc`;
const HEARTBEAT_FILE = `${STATE_DIR}/last-check`; // one write/day, keeps the schedule alive

// ---- SES email (SMTP) ----
const mailer = env.SES_HOST
  ? nodemailer.createTransport({
      host: env.SES_HOST,
      port: Number(env.SES_PORT || 587),
      secure: Number(env.SES_PORT) === 465,
      auth: { user: need('SES_USER'), pass: need('SES_PASS') },
    })
  : null;

async function sendEmail(to, subject, text) {
  if (!mailer) return;
  await mailer.sendMail({ from: need('MAIL_FROM'), to, subject, text });
}

async function sendNtfy(topic, title, body, priority = 'default') {
  if (!NTFY_BASE || !topic) return;
  const headers = { Title: title, Priority: priority };
  if (env.NTFY_TOKEN) headers.Authorization = `Bearer ${env.NTFY_TOKEN}`;
  const res = await fetch(`${NTFY_BASE}/${topic}`, { method: 'POST', headers, body });
  if (!res.ok) throw new Error(`ntfy ${topic}: ${res.status}`);
}

// ---- encrypted roster cache (repo is public, so it must be encrypted) ----
function writeRoster(roster) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', ROSTER_KEY, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(roster), 'utf8'), cipher.final()]);
  writeFileSync(ROSTER_FILE, Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64') + '\n');
}
function readRoster() {
  if (!existsSync(ROSTER_FILE)) return [];
  const buf = Buffer.from(readFileSync(ROSTER_FILE, 'utf8').trim(), 'base64');
  const d = createDecipheriv('aes-256-gcm', ROSTER_KEY, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return JSON.parse(Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8'));
}
// Only rewrite the cache when the roster actually changed: the random IV makes
// every encryption differ, which would otherwise commit on every run.
function refreshRoster(roster) {
  let current = [];
  try { current = readRoster(); } catch { /* first run / rotated key */ }
  if (JSON.stringify(current) !== JSON.stringify(roster)) writeRoster(roster);
}

// ---- state ----
function readState() {
  try { return JSON.parse(readFileSync(STATE_FILE, 'utf8')); }
  catch { return { down_since: null, notified: false, operator_notified: false }; }
}
function writeState(s) {
  writeFileSync(STATE_FILE, JSON.stringify(s, null, 2) + '\n');
}

// ---- messages ----
async function broadcastToUsers(subject, body, priority) {
  const roster = readRoster();
  let ok = 0;
  for (const r of roster) {
    try { if (r.email) { await sendEmail(r.email, subject, body); ok++; } }
    catch (e) { console.error('email', r.email, e.message); }
    try { if (r.ntfy) { await sendNtfy(r.ntfy, subject, body, priority); } }
    catch (e) { console.error('ntfy', r.ntfy, e.message); }
  }
  console.log(`notified ${ok}/${roster.length} users`);
  return roster.length;
}

async function notifyOperator(subject, body) {
  try { if (ADMIN_EMAIL) await sendEmail(ADMIN_EMAIL, `[p.stonn watchdog] ${subject}`, body); }
  catch (e) { console.error('operator email', e.message); }
  try { if (ADMIN_NTFY_TOPIC) await sendNtfy(ADMIN_NTFY_TOPIC, `[p.stonn watchdog] ${subject}`, body, 'high'); }
  catch (e) { console.error('operator ntfy', e.message); }
}

function outageBody(downMin) {
  return [
    `p.stonn has been unable to update visitor parking permits for about ${Math.round(downMin)} minutes.`,
    ``,
    `Your permit may not show the vehicle you scheduled. To be safe, set the vehicle on your`,
    `permit directly with the City of Stonnington:`,
    ``,
    `  ${COUNCIL_PORTAL}`,
    ``,
    `We'll let you know when p.stonn is back to normal. Sorry for the trouble.`,
  ].join('\n');
}

// ---- main ----
async function main() {
  mkdirSync(STATE_DIR, { recursive: true });
  const state = readState();
  const now = Date.now();

  // Keep the schedule from being auto-disabled after 60 idle days: touch a file
  // that changes at most once per day.
  const today = new Date(now).toISOString().slice(0, 10);
  writeFileSync(HEARTBEAT_FILE, today + '\n');

  let healthy = false;
  let roster = null;
  try {
    const res = await fetch(STATUS_URL, {
      headers: { Authorization: `Bearer ${STATUS_TOKEN}` },
      signal: AbortSignal.timeout(20000),
    });
    if (res.ok) {
      const status = await res.json();
      roster = status.roster || [];
      healthy = !status.scheduler?.stale; // reachable AND the work loop is running
    } else {
      console.error(`status ${res.status}`);
    }
  } catch (e) {
    console.error('poll failed:', e.message);
  }

  if (healthy) {
    if (roster) refreshRoster(roster);
    if (state.notified || state.operator_notified) {
      const downMin = state.down_since ? (now - state.down_since) / 60000 : 0;
      const msg = `p.stonn is updating permits again after about ${Math.round(downMin)} minutes. You don't need to do anything — your schedule has resumed.`;
      if (state.notified) await broadcastToUsers('p.stonn is back to normal', msg, 'default');
      if (state.operator_notified) await notifyOperator('Recovered', msg);
    }
    writeState({ down_since: null, notified: false, operator_notified: false });
    console.log('healthy');
    return;
  }

  // Unhealthy: unreachable, non-2xx, or the scheduler is stalled.
  if (!state.down_since) state.down_since = now;
  const downMin = (now - state.down_since) / 60000;
  console.log(`unhealthy for ${downMin.toFixed(1)} min`);

  if (!state.operator_notified && downMin >= OPERATOR_THRESHOLD_MIN) {
    await notifyOperator('p.stonn appears down',
      `p.stonn's /status has been unreachable or stalled for about ${Math.round(downMin)} minutes. Users will be alerted at ${USER_THRESHOLD_MIN} min.`);
    state.operator_notified = true;
  }
  if (!state.notified && downMin >= USER_THRESHOLD_MIN) {
    const n = await broadcastToUsers('p.stonn may not be updating your parking permit', outageBody(downMin), 'high');
    await notifyOperator('Users alerted', `Sent the outage notice to ${n} users.`);
    state.notified = true;
  }
  writeState(state);
}

main().catch((e) => { console.error(e); process.exit(1); });
