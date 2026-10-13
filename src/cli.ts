#!/usr/bin/env node
import { parseAuditUrl, runAudit, type AuditLine, type AuditStatus } from './index.js'

const HELP = `webaudit — quick website audit from the terminal

Usage:
  webaudit <url>            audit a site (scheme optional, https assumed)
  webaudit <url> --json     newline-delimited JSON, one object per line
  webaudit --help           this text

Checks: HTTPS + HSTS, response time, security headers
(CSP, nosniff, clickjacking, referrer policy, X-Powered-By),
and HTML basics (title, description, viewport, Open Graph,
lang, canonical, compression).

Exit codes: 0 audited (even with findings) · 1 could not audit · 2 bad usage
`

const useColor = process.stdout.isTTY && !process.env.NO_COLOR
const COLORS: Record<AuditStatus, string> = {
  PASS: '\u001b[32m', // green
  FOUND: '\u001b[33m', // yellow
  FAIL: '\u001b[31m', // red
  INFO: '\u001b[2m', // dim
}
const RESET = '\u001b[0m'

function printLine(line: AuditLine): void {
  if (!useColor) {
    console.log(`${line.status.padEnd(5)} ${line.text}`)
    return
  }
  const c = COLORS[line.status]
  console.log(`${c}${line.status.padEnd(5)}${RESET} ${line.status === 'INFO' ? `${COLORS.INFO}${line.text}${RESET}` : line.text}`)
}

async function main(): Promise<number> {
  const args = process.argv.slice(2)
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(HELP)
    return 0
  }
  const json = args.includes('--json')
  const input = args.find((a) => !a.startsWith('-'))
  if (!input) {
    process.stderr.write(HELP)
    return 2
  }

  let url: URL
  try {
    url = parseAuditUrl(input)
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Invalid URL.'
    if (json) console.log(JSON.stringify({ status: 'FAIL', text: msg }))
    else console.error(msg)
    return 2
  }

  let failed = false
  let findings = 0
  for await (const line of runAudit(url)) {
    if (line.status === 'FAIL') failed = true
    if (line.status === 'FOUND') findings++
    if (json) console.log(JSON.stringify(line))
    else printLine(line)
  }
  if (!json && !failed) {
    console.log(findings ? `\n${findings} finding${findings > 1 ? 's' : ''} — details above.` : '\nAll checks passed.')
  }
  return failed ? 1 : 0
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(err instanceof Error ? err.message : String(err))
    process.exit(1)
  },
)
