# Vortex Scanner deployment gate

This PR implements an operator-allowlisted **real HTTPS response-header inspection**, not a full vulnerability/CVE scanner, pentest, or active exploit engine. Do not advertise CVE detection or unrestricted target scanning.

## Merge is not deployment

Before exposing the scanner to customers:

1. Run \`backend/migrations/20261030_scanner_quotas.sql\` using the existing migration runner.
2. Set \`VORTEX_SCAN_ALLOWED_HOSTS\` to **exact operator-verified domains** (comma-separated), e.g. \`example.org,www.example.org\`. Default is deny-all. Only configure assets you own or have written permission to scan. Never enable arbitrary public hostnames.
3. Expose backend paths \`POST /v1/scans\`, \`GET /v1/scanner/checkout\`, \`POST /stripe/webhook\` from the website via a *same-origin* reverse proxy. Do not send API credentials to a different origin.
4. Configure \`VORTEX_SCANNER_STRIPE_PRICE_ID\` for the **actual USD 70/month recurring Stripe price** and \`VORTEX_SCANNER_CHECKOUT_URL\` to its matching official Stripe Payment Link URL. Set \`STRIPE_SECRET_KEY\` (for retrieving checkout line items), \`STRIPE_WEBHOOK_SECRET\`, and \`DATABASE_URL\`. Create the webhook subscription for \`checkout.session.completed\`, \`invoice.payment_succeeded\`, \`invoice.payment_failed\`, \`customer.subscription.deleted\`.
5. Verify on a Stripe test account that payment creates a \`customers.plan='scanner_100_monthly'\` subscription with a functioning API key. Verify expiration, failed payments, renewal, cancellation, duplicate webhooks and delivery of the key before taking real payments.
6. On the API reverse proxy, preserve true network peer identity for quota accounting. This implementation uses \`request.peer_addr()\`, not client-supplied \`X-Forwarded-For\` headers. A shared proxy IP can otherwise pool public scans; set up trusted proxy identity handling before public launch.
7. Explicitly test a permitted domain, a forbidden domain, HTTP and IP literal rejections, redirect behavior, public 4th request (HTTP 429), paid 101st request (429), monthly reset and multi-request concurrency.

## Security scope

- Only exact allowlisted hostnames are scanned; the input must be \`https://hostname\` (no path or port).
- No redirects, no request body, no exploit payloads. Checks are HSTS, CSP, X-Content-Type-Options and Referrer-Policy presence.
- The scan runner uses short timeouts. A genuine exposed service should also have worker isolation, DNS/IP egress filtering, network-layer guardrails and per-customer asset authorization before broadening this check to arbitrary user-claimed domains.
- Billing quotas use an atomic PostgreSQL \`INSERT ... ON CONFLICT ... WHERE used < limit RETURNING used\` operation.
- Public quota is three requests per network peer IP, lifetime. Paid quota is one hundred requests per subscriber per UTC calendar month. Failed external fetches currently count against quota.
- Subscription API keys are sent only in HTTPS Authorization headers, never stored by the frontend.
- Do not deploy publicly until the above gates pass. A green Rust CI is **not** proof that Stripe, routing or domain ownership verification works.
