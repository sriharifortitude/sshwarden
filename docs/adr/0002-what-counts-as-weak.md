# 2. What counts as a weak algorithm

Status: accepted

## Context

Hardening guides disagree. ssh-audit, for example, flags the NIST elliptic curves, hmac-sha1,
umac-64 and diffie-hellman-group14-sha256, all of which are in OpenSSH's own default lists.
Flagging them would put findings on every untouched server, and a finding nobody can act on
safely trains people to ignore the tool.

## Decision

Report only algorithms that are broken or removed upstream. OpenSSH 9.x's default lists
contain none of them, so an untouched configuration gets no algorithm finding. Defaults read
from an older sshd with `--defaults` can contain them (OpenSSH 6 enabled CBC ciphers by
default), and then they are reported at "(default)", because on that server they are on:

| Kind | Reported | Why |
|---|---|---|
| Ciphers | 3DES, Blowfish, CAST128, RC4, any CBC mode, `none` | 64-bit blocks (Sweet32), RC4 biases, CBC plaintext recovery in SSH |
| MACs | MD5, SHA-1-96, RIPEMD-160, UMAC-32, `none` | broken hash or short tag |
| Key exchange | group1-sha1, group14-sha1, group-exchange-sha1, GSS SHA-1 | 1024-bit group or SHA-1 |
| Signatures | ssh-dss, ssh-rsa (SHA-1) | DSA removed in OpenSSH 10; SHA-1 signatures off by default since 8.8 |

The Terrapin attack (CVE-2023-48795) depends on the server's version, which a configuration
file does not reveal, so it is checked only when `--openssh-version` says the server
predates 9.6.

## Consequences

- An untouched OpenSSH 9.x configuration has no algorithm findings.
- Someone who wants ssh-audit's stricter policy should run ssh-audit against the server.
  This tool is about what a configuration file changes.
