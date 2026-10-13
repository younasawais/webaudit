import { lookup } from 'node:dns/promises'
import { isIP } from 'node:net'

// webaudit — a quick, dependency-free website audit.
// Fetches one public URL and streams checks (HTTPS/HSTS, response time,
// security headers, meta/SEO basics) as PASS / FOUND / INFO / FAIL lines.
//
// SSRF stance: only http(s) on default ports, the hostname must not resolve
// to a private/reserved address, and redirects are re-validated hop by hop.
// The resolved-then-fetch gap (DNS TOCTOU) is accepted for this tool's
// threat model; do not rely on it as your only guard in hostile settings.

export type AuditStatus = 'PASS' | 'FOUND' | 'INFO' | 'FAIL'

export type AuditLine = {
  status: AuditStatus
  text: string
}

export type AuditOptions = {
  /** User-agent header sent with the request. */
  userAgent?: string
  /** Per-request timeout in milliseconds. Default 10 000. */
  timeoutMs?: number
  /** How many redirects to follow (each hop is re-validated). Default 3. */
  maxRedirects?: number
  /** How much of the response body to read, in bytes. Default 300 000. */
  maxBodyBytes?: number
}

const DEFAULTS: Required<AuditOptions> = {
  userAgent: 'webaudit/0.1 (+https://github.com/younasawais/webaudit)',
  timeoutMs: 10_000,
  maxRedirects: 3,
  maxBodyBytes: 300_000,
}

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return true
  const [a, b] = parts
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  )
}

function isPrivateIPv6(ip: string): boolean {
  const low = ip.toLowerCase()
  // IPv4-mapped (::ffff:1.2.3.4) — judge the embedded v4 address.
  const v4 = low.match(/(\d+\.\d+\.\d+\.\d+)$/)
  if (v4) return isPrivateIPv4(v4[1])
  return (
    low === '::' ||
    low === '::1' ||
    low.startsWith('fe8') ||
    low.startsWith('fe9') ||
    low.startsWith('fea') ||
    low.startsWith('feb') ||
    low.startsWith('fc') ||
    low.startsWith('fd') ||
    low.startsWith('ff') ||
    low.startsWith('64:ff9b') ||
    low.startsWith('2001:db8')
  )
}

/** True when the IP is private, reserved, loopback or otherwise not publicly routable. */
export function isPrivateIp(ip: string): boolean {
  return isIP(ip) === 4 ? isPrivateIPv4(ip) : isPrivateIPv6(ip)
}

// Throws with a user-readable message when the URL may not be fetched.
// Returns the resolved addresses so the audit log can show them.
async function assertPublicTarget(url: URL): Promise<string[]> {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Only http and https URLs can be audited.')
  }
  if (url.port && url.port !== '80' && url.port !== '443') {
    throw new Error('Only default ports (80/443) can be audited.')
  }
  if (url.username || url.password) {
    throw new Error('URLs with credentials are not allowed.')
  }
  const host = url.hostname.replace(/^\[|\]$/g, '')
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    throw new Error('That host is not publicly reachable.')
  }
  if (isIP(host)) {
    if (isPrivateIp(host)) throw new Error('That address is not publicly reachable.')
    return [host]
  }
  let addrs
  try {
    addrs = await lookup(host, { all: true, verbatim: true })
  } catch {
    throw new Error(`Could not resolve ${host} — is the domain live?`)
  }
  if (addrs.length === 0 || addrs.some((a) => isPrivateIp(a.address))) {
    throw new Error('That address is not publicly reachable.')
  }
  return addrs.map((a) => a.address)
}

type FetchedPage = {
  finalUrl: URL
  status: number
  headers: Headers
  html: string
  ttfbMs: number
  redirects: number
}

// Fetches with manual redirects so every hop goes through the SSRF guard.
// An async generator: yields progress lines as it works, and returns the
// fetched page as its final value.
async function* fetchPage(start: URL, opts: Required<AuditOptions>): AsyncGenerator<AuditLine, FetchedPage> {
  let url = start
  let redirects = 0
  for (;;) {
    yield { status: 'INFO', text: `▸ resolving ${url.hostname} …` }
    const addrs = await assertPublicTarget(url)
    yield {
      status: 'INFO',
      text: `▸ ${url.hostname} → ${addrs[0]}${addrs.length > 1 ? ` (+${addrs.length - 1} more)` : ''}`,
    }
    yield {
      status: 'INFO',
      text: `▸ ${url.protocol === 'https:' ? 'TLS handshake · ' : ''}GET ${url.pathname || '/'}`,
    }
    const began = Date.now()
    const res = await fetch(url, {
      redirect: 'manual',
      signal: AbortSignal.timeout(opts.timeoutMs),
      headers: {
        'user-agent': opts.userAgent,
        accept: 'text/html,application/xhtml+xml',
      },
    })
    const ttfbMs = Date.now() - began
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location')
      res.body?.cancel()
      if (!loc) throw new Error(`Redirect (${res.status}) without a Location header.`)
      if (++redirects > opts.maxRedirects) throw new Error('Too many redirects.')
      url = new URL(loc, url)
      yield { status: 'INFO', text: `▸ ${res.status} redirect → ${url.host}${url.pathname}` }
      continue
    }
    yield {
      status: 'INFO',
      text: `▸ first byte in ${ttfbMs} ms · ${[...res.headers.keys()].length} response headers`,
    }
    let html = ''
    if (res.body) {
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let size = 0
      while (size < opts.maxBodyBytes) {
        const { done, value } = await reader.read()
        if (done) break
        size += value.byteLength
        html += decoder.decode(value, { stream: true })
      }
      reader.cancel().catch(() => {})
      yield { status: 'INFO', text: `▸ read ${Math.max(1, Math.round(size / 1024))} KB of response body` }
    }
    return { finalUrl: url, status: res.status, headers: res.headers, html, ttfbMs, redirects }
  }
}

function hasMeta(html: string, re: RegExp): boolean {
  return re.test(html)
}

/** Normalises user input ("example.com") into a URL, preferring https. */
export function parseAuditUrl(input: string): URL {
  const trimmed = input.trim().slice(0, 500)
  if (!trimmed) throw new Error('Type a URL first.')
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  let url: URL
  try {
    url = new URL(withScheme)
  } catch {
    throw new Error('That does not look like a valid URL.')
  }
  if (!url.hostname.includes('.') && !isIP(url.hostname)) {
    throw new Error('That does not look like a public website address.')
  }
  return url
}

/** Runs the audit, yielding one line at a time so callers can stream them. */
export async function* runAudit(target: URL, options: AuditOptions = {}): AsyncGenerator<AuditLine> {
  const opts = { ...DEFAULTS, ...options }
  yield { status: 'INFO', text: `Auditing ${target.hostname} …` }

  let page: FetchedPage
  try {
    const it = fetchPage(target, opts)
    for (;;) {
      const r = await it.next()
      if (r.done) {
        page = r.value
        break
      }
      yield r.value
    }
  } catch (err) {
    yield { status: 'FAIL', text: err instanceof Error ? err.message : 'Could not reach that URL.' }
    return
  }

  const h = page.headers

  if (page.status >= 400) {
    yield { status: 'FOUND', text: `The page answered with HTTP ${page.status}.` }
  } else {
    yield { status: 'PASS', text: `Reachable — HTTP ${page.status}${page.redirects ? ` after ${page.redirects} redirect${page.redirects > 1 ? 's' : ''}` : ''}` }
  }

  // HTTPS + HSTS
  yield { status: 'INFO', text: '▸ checking transport security' }
  if (page.finalUrl.protocol !== 'https:') {
    yield { status: 'FOUND', text: 'Site is served over plain HTTP — no encryption.' }
  } else {
    yield { status: 'PASS', text: 'Served over HTTPS' }
    if (!h.get('strict-transport-security')) {
      yield { status: 'FOUND', text: 'No HSTS header — browsers may still try plain HTTP first.' }
    } else {
      yield { status: 'PASS', text: 'HSTS enabled' }
    }
  }

  // Response time
  if (page.ttfbMs <= 800) {
    yield { status: 'PASS', text: `Server responded in ${page.ttfbMs} ms` }
  } else if (page.ttfbMs <= 2000) {
    yield { status: 'FOUND', text: `Slow first response: ${page.ttfbMs} ms (aim for under 800 ms).` }
  } else {
    yield { status: 'FOUND', text: `Very slow first response: ${page.ttfbMs} ms — visitors feel this.` }
  }

  // Security headers
  yield { status: 'INFO', text: '▸ probing security headers' }
  if (!h.get('content-security-policy')) {
    yield { status: 'FOUND', text: 'No Content-Security-Policy — one injected script owns the page.' }
  } else {
    yield { status: 'PASS', text: 'Content-Security-Policy set' }
  }
  if (!h.get('x-content-type-options')) {
    yield { status: 'FOUND', text: 'Missing X-Content-Type-Options: nosniff.' }
  } else {
    yield { status: 'PASS', text: 'X-Content-Type-Options set' }
  }
  const csp = h.get('content-security-policy') ?? ''
  if (!h.get('x-frame-options') && !csp.includes('frame-ancestors')) {
    yield { status: 'FOUND', text: 'No clickjacking protection (X-Frame-Options / frame-ancestors).' }
  } else {
    yield { status: 'PASS', text: 'Clickjacking protection in place' }
  }
  if (!h.get('referrer-policy')) {
    yield { status: 'FOUND', text: 'No Referrer-Policy — full URLs leak to other sites.' }
  } else {
    yield { status: 'PASS', text: 'Referrer-Policy set' }
  }
  const poweredBy = h.get('x-powered-by')
  if (poweredBy) {
    yield { status: 'FOUND', text: `X-Powered-By advertises your stack: "${poweredBy}".` }
  }

  // HTML basics (only when we actually got HTML)
  const html = page.html
  const looksLikeHtml = /<html[\s>]/i.test(html) || /<title[\s>]/i.test(html)
  if (looksLikeHtml) {
    yield { status: 'INFO', text: '▸ parsing HTML · SEO + social checks' }
    const title = html.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1]?.trim() ?? ''
    if (!title) {
      yield { status: 'FOUND', text: 'No <title> — bad for search results and browser tabs.' }
    } else if (title.length < 10 || title.length > 70) {
      yield { status: 'FOUND', text: `Page title is ${title.length} characters (10–70 works best in search).` }
    } else {
      yield { status: 'PASS', text: `Title: “${title.slice(0, 60)}”` }
    }
    if (!hasMeta(html, /<meta[^>]+name=["']description["']/i)) {
      yield { status: 'FOUND', text: 'No meta description — Google writes its own snippet for you.' }
    } else {
      yield { status: 'PASS', text: 'Meta description present' }
    }
    if (!hasMeta(html, /<meta[^>]+name=["']viewport["']/i)) {
      yield { status: 'FOUND', text: 'No viewport meta tag — the site is not mobile-ready.' }
    } else {
      yield { status: 'PASS', text: 'Mobile viewport configured' }
    }
    if (!hasMeta(html, /<meta[^>]+property=["']og:/i)) {
      yield { status: 'FOUND', text: 'No Open Graph tags — shared links show up bare.' }
    } else {
      yield { status: 'PASS', text: 'Open Graph tags present' }
    }
    if (!hasMeta(html, /<html[^>]+lang=/i)) {
      yield { status: 'FOUND', text: 'No lang attribute on <html> — hurts accessibility and SEO.' }
    } else {
      yield { status: 'PASS', text: 'Language declared' }
    }
    if (!hasMeta(html, /<link[^>]+rel=["'][^"']*canonical/i)) {
      yield { status: 'FOUND', text: 'No canonical link — duplicate-content risk.' }
    } else {
      yield { status: 'PASS', text: 'Canonical URL set' }
    }
  } else {
    yield { status: 'INFO', text: 'Response was not an HTML page, skipped the content checks.' }
  }

  const enc = h.get('content-encoding')
  if (enc && /br|gzip|zstd/.test(enc)) {
    yield { status: 'PASS', text: `Compression on (${enc})` }
  }
}
