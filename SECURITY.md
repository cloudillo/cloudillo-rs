# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately:

- **E-mail:** `security@cloudillo.org`
- **GitHub:** private vulnerability reporting ("Report a vulnerability" under the
  repository's *Security* tab) on `cloudillo/cloudillo-rs` or `cloudillo/cloudillo`.

**Do not** open a public issue, pull request or discussion for a suspected vulnerability.

Please include: the affected component and version (or image digest / commit hash), steps to
reproduce or a proof of concept, the impact you expect, whether you believe it is being
exploited, and how you want to be credited. English or Hungarian is fine.

## Scope

In scope: the Cloudillo server (`cloudillo-rs`, all crates and adapters), the web client
(`cloudillo`), the official container image `cloudillo/cloudillo` (including the binaries it
ships), the federation protocol as implemented by the server, and the build and release chain.

Vulnerabilities in a dependency are in scope when they affect Cloudillo; we report them to the
component's maintainer and share our fix.

Out of scope: the configuration of a particular deployment (report it to its operator),
denial-of-service tests and social engineering against instances you do not own, and the
marketing website.

## Safe harbour

If you research in good faith, follow this policy, avoid privacy violations, data destruction
and service degradation, use only accounts and instances you own or are authorised to test,
and give us reasonable time to fix before disclosure, we will not pursue or support legal
action against you for that research. Stop and report as soon as you reach personal data or
another user's data; do not keep, copy or disclose it.

## Response timeline

| Step | Commitment |
|---|---|
| Acknowledge receipt | within 2 working days |
| Initial assessment (confirmed or not, CVSS severity, affected versions) | within 7 days of the acknowledgement |
| Status updates | at least every 14 days until the fix is released |

Fix deadlines, counted from confirmation (severity by CVSS v3.1 base score):

| Severity | Deadline |
|---|---|
| Exploited in the wild | workaround within 72 hours, fix within 7 days |
| Critical (9.0–10.0) | 7 days |
| High (7.0–8.9) | 30 days |
| Medium (4.0–6.9) | 90 days |
| Low (0.1–3.9) | next planned release |

## Coordinated disclosure

Please keep details private until the advisory is published or 90 days after confirmation,
whichever comes first. If a vulnerability is being exploited, we publish as soon as a fix or
workaround is available. Advisories are published as GitHub security advisories on the
affected repository together with the fixing release, with credit to the reporter if wanted.
Vulnerabilities of medium or higher severity get a CVE ID. No bug bounty is offered.

## Supported versions

Cloudillo is in alpha. Security fixes are released as a new image of the latest version; only
the latest release is supported. Security updates are free of charge.
