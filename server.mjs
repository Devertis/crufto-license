// Crufto license service.
//
// Flow: Stripe fires `checkout.session.completed` -> we verify the signature,
// mint an Ed25519-signed license key, store it, and email it to the buyer.
// The thank-you page on the site fetches the key by Checkout Session id so the
// buyer sees it immediately. No Stripe API key is needed here (webhook
// verification uses only the webhook signing secret), and the signing private
// key never leaves this process.

import http from 'node:http';
import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import Stripe from 'stripe';
import nodemailer from 'nodemailer';

// ---- config -----------------------------------------------------------------

const PORT = parseInt(process.env.PORT || '8080', 10);
const DATA_DIR = process.env.DATA_DIR || '/data';
const STORE_FILE = path.join(DATA_DIR, 'licenses.json');
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || 'https://crufto.com';
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const PRODUCT = process.env.PRODUCT || 'cleaner';
const PRODUCT_LABEL = process.env.PRODUCT_LABEL || 'Crufto Cleaner';

// The Ed25519 signing key is a PKCS8 PEM, supplied as base64 of the PEM. Some
// env backends (e.g. Coolify behind a proxy) silently drop long values, so the
// key may be split into short numbered chunks that are concatenated here:
//   LICENSE_SIGNING_KEY_B64_0, LICENSE_SIGNING_KEY_B64_1, ...   (in order)
// Also accepted: the whole thing in LICENSE_SIGNING_KEY_B64, or a raw/escaped
// PEM in LICENSE_SIGNING_KEY.
function loadSigningKey() {
  let pem = '';
  let b64 = '';
  for (let i = 0; ; i++) {
    const part = process.env[`LICENSE_SIGNING_KEY_B64_${i}`];
    if (part === undefined) break;
    b64 += part.trim();
  }
  if (!b64) b64 = (process.env.LICENSE_SIGNING_KEY_B64 || '').trim();
  if (b64) {
    pem = Buffer.from(b64, 'base64').toString('utf8');
  } else {
    pem = process.env.LICENSE_SIGNING_KEY || '';
    if (pem && !pem.includes('\n') && pem.includes('\\n')) pem = pem.replace(/\\n/g, '\n');
  }
  if (!pem) return null;
  try {
    return crypto.createPrivateKey(pem);
  } catch (err) {
    console.error('[fatal] signing key is not a valid private key:', err.message);
    return null;
  }
}
const SIGNING_KEY = loadSigningKey();

// A Stripe instance is needed only for webhooks.constructEvent, which makes no
// network call, so a placeholder key is fine and no live key lives here.
const stripe = new Stripe(process.env.STRIPE_API_KEY || 'sk_placeholder_unused', {
  apiVersion: '2024-11-20.acacia',
});

// SMTP is optional: without it, licenses are still minted and stored (and shown
// on the thank-you page), just not emailed.
function buildMailer() {
  const host = process.env.SMTP_HOST;
  if (!host) return null;
  const port = parseInt(process.env.SMTP_PORT || '587', 10);
  return nodemailer.createTransport({
    host,
    port,
    secure: process.env.SMTP_SECURE === 'true' || port === 465,
    auth: process.env.SMTP_USER
      ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
      : undefined,
  });
}
const mailer = buildMailer();
const MAIL_FROM = process.env.MAIL_FROM || 'Crufto <no-reply@crufto.com>';
const MAIL_REPLY_TO = process.env.MAIL_REPLY_TO || '';

// ---- license minting --------------------------------------------------------

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// A license key is `base64url(payloadJSON).base64url(ed25519sig)`. The app
// verifies the signature over the exact payload bytes, so no canonical JSON
// form is required on either side.
function mintLicense({ order, email, name }) {
  const payload = { v: 1, p: PRODUCT, o: order, e: email, t: Math.floor(Date.now() / 1000) };
  if (name) payload.n = name;
  const payloadBytes = Buffer.from(JSON.stringify(payload), 'utf8');
  const sig = crypto.sign(null, payloadBytes, SIGNING_KEY);
  return b64url(payloadBytes) + '.' + b64url(sig);
}

// ---- tiny JSON store --------------------------------------------------------

let store = {}; // sessionId -> record

async function loadStore() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    store = JSON.parse(await fs.readFile(STORE_FILE, 'utf8'));
  } catch (err) {
    if (err.code !== 'ENOENT') console.error('[warn] could not read store:', err.message);
    store = {};
  }
}

async function persistStore() {
  const tmp = STORE_FILE + '.tmp';
  await fs.writeFile(tmp, JSON.stringify(store, null, 2));
  await fs.rename(tmp, STORE_FILE); // atomic replace
}

// ---- email ------------------------------------------------------------------

async function emailLicense(record) {
  if (!mailer) {
    console.log(`[mail] SMTP not configured; license for ${record.email} stored but not emailed`);
    return;
  }
  const subject = `Your ${PRODUCT_LABEL} license`;
  const text =
`Thanks for buying ${PRODUCT_LABEL}.

Your license key:

${record.license}

To activate: open ${PRODUCT_LABEL}, choose ${PRODUCT_LABEL} > Enter License from
the menu, and paste the key above. It unlocks cleaning on all your Macs — no
account, no internet needed.

Keep this email; it's your receipt and proof of license.

— Crufto`;
  const html =
`<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.55;color:#1a1a1a">
<p>Thanks for buying <strong>${PRODUCT_LABEL}</strong>.</p>
<p>Your license key:</p>
<pre style="background:#f5f5f4;border:1px solid #e5e5e3;border-radius:8px;padding:14px;white-space:pre-wrap;word-break:break-all;font-size:13px">${record.license}</pre>
<p>To activate: open ${PRODUCT_LABEL}, choose <strong>${PRODUCT_LABEL} &rsaquo; Enter License</strong> from the menu, and paste the key above. It unlocks cleaning on all your Macs — no account, no internet needed.</p>
<p>Keep this email; it's your receipt and proof of license.</p>
<p>— Crufto</p>
</div>`;
  await mailer.sendMail({
    from: MAIL_FROM,
    to: record.email,
    subject,
    text,
    html,
    ...(MAIL_REPLY_TO ? { replyTo: MAIL_REPLY_TO } : {}),
  });
  console.log(`[mail] license emailed to ${record.email}`);
}

// ---- http helpers -----------------------------------------------------------

function send(res, status, body, headers = {}) {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, { 'content-type': typeof body === 'string' ? 'text/plain' : 'application/json', ...headers });
  res.end(payload);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ---- handlers ---------------------------------------------------------------

async function handleWebhook(req, res) {
  const raw = await readRawBody(req);
  let event;
  try {
    event = stripe.webhooks.constructEvent(raw, req.headers['stripe-signature'], WEBHOOK_SECRET);
  } catch (err) {
    console.error('[webhook] signature verification failed:', err.message);
    return send(res, 400, `Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const s = event.data.object;
    if (s.payment_status !== 'paid') {
      console.log(`[webhook] session ${s.id} not paid (${s.payment_status}); ignoring`);
      return send(res, 200, { received: true });
    }
    if (store[s.id]) {
      console.log(`[webhook] session ${s.id} already processed; skipping`);
      return send(res, 200, { received: true });
    }
    const email = (s.customer_details && s.customer_details.email) || s.customer_email || '';
    const name = (s.customer_details && s.customer_details.name) || '';
    if (!email) {
      console.error(`[webhook] session ${s.id} has no email; cannot mint`);
      return send(res, 200, { received: true });
    }
    const record = {
      session: s.id,
      order: s.payment_intent || s.id,
      email,
      name,
      product: PRODUCT,
      license: mintLicense({ order: s.payment_intent || s.id, email, name }),
      created: new Date().toISOString(),
    };
    store[s.id] = record;
    try {
      await persistStore();
    } catch (err) {
      console.error('[webhook] failed to persist store:', err.message);
    }
    console.log(`[webhook] minted license for ${email} (session ${s.id})`);
    try {
      await emailLicense(record);
    } catch (err) {
      console.error(`[webhook] email failed for ${email}:`, err.message);
    }
  }
  return send(res, 200, { received: true });
}

function cors(headers = {}) {
  return {
    'access-control-allow-origin': ALLOW_ORIGIN,
    'access-control-allow-methods': 'GET, OPTIONS',
    'access-control-allow-headers': 'content-type',
    ...headers,
  };
}

function handleLicenseLookup(req, res, url) {
  const sessionId = url.searchParams.get('session_id') || '';
  if (!sessionId.startsWith('cs_')) {
    return send(res, 400, { ok: false, error: 'missing session_id' }, cors());
  }
  const record = store[sessionId];
  if (!record) {
    // The webhook may not have arrived yet; the page should retry briefly.
    return send(res, 404, { ok: false, error: 'not_ready' }, cors());
  }
  return send(res, 200, {
    ok: true,
    license: record.license,
    email: record.email,
    product: record.product,
  }, cors());
}

// ---- server -----------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (req.method === 'OPTIONS') return send(res, 204, '', cors());
    if (req.method === 'GET' && url.pathname === '/healthz') return send(res, 200, 'ok');
    if (req.method === 'POST' && url.pathname === '/v1/stripe/webhook') return await handleWebhook(req, res);
    if (req.method === 'GET' && url.pathname === '/v1/license') return handleLicenseLookup(req, res, url);

    return send(res, 404, { ok: false, error: 'not_found' });
  } catch (err) {
    console.error('[error]', err);
    return send(res, 500, { ok: false, error: 'internal' });
  }
});

async function main() {
  if (!SIGNING_KEY) console.error('[startup] WARNING: LICENSE_SIGNING_KEY not set — cannot mint licenses');
  if (!WEBHOOK_SECRET) console.error('[startup] WARNING: STRIPE_WEBHOOK_SECRET not set — webhooks will be rejected');
  if (!mailer) console.error('[startup] WARNING: SMTP not configured — licenses will be stored but not emailed');
  await loadStore();
  server.listen(PORT, () => console.log(`[startup] crufto-license listening on :${PORT} (origin ${ALLOW_ORIGIN})`));
}

main();
