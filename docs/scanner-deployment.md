# Vortex Scanner deployment gate

This PR implements an operator-allowlisted **real HTTPS response-header inspection**, not a full vulnerability/CVE scanner, pentest, or active exploit engine. Do not advertise CVE detection or unrestricted target scanning.

## Merge is not deployment

Before exposing the scanner to customers:

1. Run \`backend/migrations/20261030_scanner_quotas.sql\` using the existing migration runner.
2. Set \`VORTEX_SCAN_ALLOWED_HOSTS\` to **exact operator-verified domains** (comma-separated), e.g. \`example.org,www.example.org\`. Default is deny-all. Only configure assets you own or have written permission to scan. Never enable arbitrary public hostnames.
3. Deploy the included Cloudflare Pages Functions routes (`functions/v1/scans.js`, `functions/v1/scanner/checkout.js`, and `functions/stripe/webhook.js`). Configure **Cloudflare Pages secrets** `VORTEX_BACKEND_BASE_URL=https://your-backend-host` and `VORTEX_PROXY_SHARED_SECRET` (random 32+ characters). Configure the same `VORTEX_PROXY_SHARED_SECRET` on the Rust backend. The proxy forwards validated Cloudflare client IPs, allowing the backend to enforce per-client quotas. Restrict the backend origin to trustworthy proxies where possible. Do not point the backend URL to the public site's own domain (would recurse).
4. Configure \`VORTEX_SCANNER_STRIPE_PRICE_ID\` for the **actual USD 70/month recurring Stripe price** and \`VORTEX_SCANNER_CHECKOUT_URL\` to its matching official Stripe Payment Link URL. Set \`STRIPE_SECRET_KEY\` (for retrieving checkout line items), \`STRIPE_WEBHOOK_SECRET\`, and \`DATABASE_URL\`. Create the webhook subscription for \`checkout.session.completed\`, \`invoice.payment_succeeded\`, \`invoice.payment_failed\`, \`customer.subscription.deleted\`.
5. Configure `RESEND_API_KEY` and an approved `FROM_EMAIL` sender address so Stripe-paid customers receive their scanner API keys. Verify on a Stripe test account that payment creates a \`customers.plan='scanner_100_monthly'\` subscription with a functioning API key. Verify expiration, failed payments, renewal, cancellation, duplicate webhooks and delivery of the key before taking real payments.
6. Verify proxy identity: the Pages Function sets `X-Vortex-Client-IP` from Cloudflare's `CF-Connecting-IP` and signs its trusted origin with a shared secret header. Rust rejects a forwarded identity without a matching shared secret; otherwise it uses the direct connection IP. The backend must be deployed behind TLS. Never expose the shared secret to the browser.
7. Explicitly test a permitted domain, a forbidden domain, HTTP and IP literal rejections, redirect behavior, public 4th request (HTTP 429), paid 101st request (429), monthly reset and multi-request concurrency.

## Security scope

- Only exact allowlisted hostnames are scanned; the input must be \`https://hostname\` (no path or port).
- No redirects, no request body, no exploit payloads. Checks are HSTS, CSP, X-Content-Type-Options and Referrer-Policy presence.
- The scan runner uses short timeouts. A genuine exposed service should also have worker isolation, DNS/IP egress filtering, network-layer guardrails and per-customer asset authorization before broadening this check to arbitrary user-claimed domains.
- Billing quotas use an atomic PostgreSQL \`INSERT ... ON CONFLICT ... WHERE used < limit RETURNING used\` operation.
- Public quota is three requests per network peer IP, lifetime. IPs are stored as HMAC-SHA256 identifiers (keyed by `VORTEX_PROXY_SHARED_SECRET`), not raw IPs. Paid quota is one hundred requests per subscriber per UTC calendar month. Failed external fetches currently count against quota.
- Subscription API keys are sent only in HTTPS Authorization headers, never stored by the frontend.
- Do not deploy publicly until the above gates pass. A green Rust CI is **not** proof that Stripe, routing or domain ownership verification works.
