# Security Policy

## Scope

Sift is a **defensive** security tool — a browser-based, offline investigation aid for threat hunters and IR analysts. It is designed to be safe to run on an analyst workstation against potentially sensitive log data.

The trust model:

- Sift runs entirely in the browser. No server component.
- No external network calls at runtime. The dist HTML file is self-contained.
- All log data stays in the browser tab — never transmitted anywhere.
- Source is open and auditable at [github.com/rvicenciojr/Sift-ThreatHuntingInvestigator](https://github.com/rvicenciojr/Sift-ThreatHuntingInvestigator).

## Reporting a vulnerability

If you find a security issue — particularly anything that would cause data to leave the browser, allow code injection from CSV content, or compromise the air-gapped trust model — please report it privately.

**Contact:** open a [GitHub Security Advisory](https://github.com/rvicenciojr/Sift-ThreatHuntingInvestigator/security/advisories/new) on the repository.

Please do **not** open a public issue for vulnerabilities. Reasonable disclosure timelines are appreciated — this is a solo-maintained project, so response time may vary, but security issues are prioritised.

## What is in scope

- XSS or code injection via malicious CSV cell content rendered into the DOM
- Anything that causes Sift to make an outbound network request
- Path traversal or arbitrary file read via the file load flow
- Bypass of the offline / air-gapped trust model
- Cross-tab data leakage between investigations

## What is not in scope

- Browser bugs unrelated to Sift's code
- Issues that require an attacker to already have local code execution on the workstation
- "The CSV contained malicious content and was rendered as text" — yes, that's the job. Sift shows you the content of your logs.
- Missing features that would improve security posture (those are feature requests — file an issue)

## Hardening notes

If you are deploying Sift in a particularly sensitive environment:

- Serve it from a known-good location (signed internal artefact store, not a public download)
- Verify the dist file against the source in the repo before use
- Run it in a profile or container isolated from your normal browsing
