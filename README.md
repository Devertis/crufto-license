# crufto-license

Tiny license service for Crufto products. It turns a paid Stripe checkout into a
signed, offline-verifiable license key and emails it to the buyer.

## How it works

1. A customer pays through the Crufto Cleaner Stripe Payment Link.
2. Stripe sends a `checkout.session.completed` webhook to `/v1/stripe/webhook`.
3. The service verifies the webhook signature, then mints an **Ed25519-signed
   license key** and stores it, keyed by the Checkout Session id.
4. It emails the key to the buyer (if SMTP is configured).
5. The site's thank-you page reads `/v1/license?session_id=...` and shows the key
   immediately.

The app verifies keys **offline** with an embedded Ed25519 public key (Apple
CryptoKit). No activation server, no phone-home, works with no internet.

### License key format

`base64url(payloadJSON) . base64url(ed25519Signature)`

The signature is over the exact payload bytes, so no canonical JSON form is
needed. Payload: `{ "v":1, "p":"cleaner", "o":<order>, "e":<email>, "t":<issued unix>, "n":<name?> }`.

## Endpoints

- `POST /v1/stripe/webhook` — Stripe webhook receiver (signature-verified).
- `GET  /v1/license?session_id=cs_...` — returns `{ ok, license, email, product }`
  for the thank-you page (CORS-limited to `ALLOW_ORIGIN`). 404 `not_ready`
  until the webhook has arrived.
- `GET  /healthz` — health check.

## Keys

The signing **private key** lives only here, as the `LICENSE_SIGNING_KEY` env var
(PKCS8 PEM). The matching **public key** is compiled into the app. No Stripe API
key is needed — webhook verification uses only `STRIPE_WEBHOOK_SECRET`.

Generate a pair (keep the private key out of git):

```sh
node -e 'const c=require("crypto");const {publicKey,privateKey}=c.generateKeyPairSync("ed25519");\
process.stdout.write(privateKey.export({type:"pkcs8",format:"pem"}));\
const der=publicKey.export({type:"spki",format:"der"});\
console.error("PUBLIC_RAW_B64="+der.subarray(der.length-32).toString("base64"))'
```

## Configuration

See `.env.example`. Set these as secrets in Coolify. Mount a persistent volume at
`DATA_DIR` (default `/data`) so minted licenses survive redeploys.

## Run locally

```sh
npm ci
LICENSE_SIGNING_KEY="$(cat key.pem)" STRIPE_WEBHOOK_SECRET=whsec_... DATA_DIR=./data npm start
```
