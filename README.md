# webaudit

Quick, dependency-free website audit from the terminal or from Node.
One command, ~2 seconds, and you know whether a site has the basics right:
HTTPS and HSTS, security headers, response time, and the SEO/social tags
that decide how a page looks in search results and shared links.

```
$ npx webaudit example.com

INFO  Auditing example.com …
INFO  ▸ resolving example.com …
INFO  ▸ example.com → 93.184.216.34
INFO  ▸ TLS handshake · GET /
PASS  Reachable — HTTP 200
PASS  Served over HTTPS
FOUND No HSTS header — browsers may still try plain HTTP first.
PASS  Server responded in 142 ms
FOUND No Content-Security-Policy — one injected script owns the page.
PASS  X-Content-Type-Options set
...

4 findings — details above.
```

## What it checks

- **Transport** — HTTPS, HSTS, redirect chain (each hop validated)
- **Speed** — time to first byte, response compression
- **Security headers** — Content-Security-Policy, `X-Content-Type-Options`,
  clickjacking protection (`X-Frame-Options` / `frame-ancestors`),
  `Referrer-Policy`, stack leaks via `X-Powered-By`
- **HTML basics** — `<title>` length, meta description, mobile viewport,
  Open Graph tags, `lang` attribute, canonical URL

Zero runtime dependencies — only Node built-ins (`fetch`, `node:dns`,
`node:net`). Node 18.17+.

## CLI

```bash
npx webaudit example.com          # human-readable, colored on a TTY
npx webaudit example.com --json   # newline-delimited JSON, one check per line
```

Exit codes: `0` audit ran (findings or not), `1` the site could not be
audited, `2` bad usage.

## Library

Results stream as an async generator, so you can render them live
(a terminal UI, an SSE/NDJSON endpoint, a progress log):

```ts
import { parseAuditUrl, runAudit } from 'webaudit'

const url = parseAuditUrl('example.com') // adds https://, validates shape

for await (const line of runAudit(url)) {
  // line: { status: 'PASS' | 'FOUND' | 'INFO' | 'FAIL', text: string }
  console.log(line.status, line.text)
}
```

Options:

```ts
runAudit(url, {
  userAgent: 'mybot/1.0 (+https://example.com)',
  timeoutMs: 10_000, // per request
  maxRedirects: 3, // each hop is re-validated
  maxBodyBytes: 300_000, // how much HTML to read
})
```

## SSRF stance

webaudit is built to be exposed to untrusted input (it powers a public
audit form). Before every request — including every redirect hop — it:

- allows only `http:`/`https:` on default ports, no credentials in the URL
- resolves the hostname and rejects private, loopback, link-local, CGNAT,
  reserved and multicast ranges (IPv4 and IPv6, including IPv4-mapped)
- rejects `localhost`, `*.local`, `*.internal` and friends

The DNS resolve-then-fetch gap (TOCTOU) is accepted for this threat model.
If an attacker controls the DNS of the audited domain and your network
perimeter matters, run it in an egress-restricted environment.

## Who made this

Built by [Studio Toronto](https://studiotoronto.ca) — this engine powers the
live audit terminal at [studiotoronto.ca/scan](https://studiotoronto.ca/scan).

MIT © Studio Toronto
