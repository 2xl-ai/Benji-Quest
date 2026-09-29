Benji's Quest latest consolidated build. Deploy with npx wrangler deploy.

## Secrets

All credentials are Wrangler secrets and are never stored in source.

| Secret | Purpose |
|---|---|
| `PARENT_PIN_HASH` | Unlocks Parent HQ (1-hour session) |
| `FAMILY_PASSCODE_HASH` | Unlocks the app on a device (30-day session) |
| `SESSION_SECRET` | Signs session cookies; rotating it logs out every device |

```sh
node scripts/hash-pin.mjs                         # run once per secret; prints a pbkdf2-sha256$... hash
npx wrangler secret put PARENT_PIN_HASH           # paste the parent PIN hash
npx wrangler secret put FAMILY_PASSCODE_HASH      # paste the family passcode hash
openssl rand -base64 32 | npx wrangler secret put SESSION_SECRET
```

For local development, copy `.dev.vars.example` to `.dev.vars` and fill in the same values (escape each `$` in the hashes as `\$`).

## Troubleshooting

The API only ever returns `{"error":"Server error"}` for unexpected failures. The real reason (for example a missing secret) is in the Worker logs: run `npx wrangler tail` and retry the request.

## Security notes

- Security headers for static files live in `public/_headers`. The Content-Security-Policy forbids inline scripts, so page code belongs in `public/app.js`, and buttons use `data-act` attributes instead of `onclick`.
- Every state-changing `/api` request must be same-origin JSON (CSRF guard in `src/worker.js`).
