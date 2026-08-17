# Security Policy

## Scope & intended use

`qwen_3.8_harness` is **offensive-security research tooling**. It is intended
only for use against systems you own or are explicitly authorized to test.
Misuse against systems without authorization may be illegal — you are solely
responsible for how you use it. The bundled model is uncensored; the safety
properties of this project come from the **sandbox and the approval gate**, not
from the model.

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities in this
project's own code (e.g. the gateway, the sandbox templates, or the monitor
dashboard's auth).

Instead, report privately via one of:

- **GitHub Private Vulnerability Reporting** — the "Report a vulnerability"
  button under this repository's **Security** tab (preferred), or
- a direct message to the maintainer.

Please include: affected component, a description, reproduction steps or a PoC,
and the impact. You'll get an acknowledgement as soon as possible; please allow
a reasonable window for a fix before any public disclosure.

## Handling secrets

This repository must never contain real credentials. Runtime secrets and state
are git-ignored (`monitor/config.yaml`, `monitor/events.db`, `gateway/state/`,
logs, model weights). If you believe a secret was committed, **rotate it
immediately** — rotation, not deletion, is the fix, because git history
preserves removed files.
