# sshwarden

[![CI](https://github.com/sriharifortitude/sshwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/sshwarden/actions/workflows/ci.yml)

Audits an `sshd_config` the way sshd reads it: Include files in order, the first value of a
keyword wins, Match blocks override the global section, and algorithm lists are edits of a
default. It reports the line that is actually in force, and the lines that do nothing. Go,
standard library only, MIT.

## What it is for

Ubuntu and Debian put `Include /etc/ssh/sshd_config.d/*.conf` on the first line of
`sshd_config`. sshd keeps the first value it reads for each keyword, so anything in a drop-in
beats the main file, and cloud images ship a drop-in that turns password login on. The
hardening step everyone takes, appending `PasswordAuthentication no` to `sshd_config`, then
changes nothing, and a checker that greps the file says the server is hardened:

<!-- demo:start -->
```
$ sshwarden --root testdata/ubuntu testdata/ubuntu/etc/ssh/sshd_config
testdata/ubuntu/etc/ssh/sshd_config:13  SSH010 low      X11Forwarding yes exposes the client's display to a compromised server; enable it only where needed
testdata/ubuntu/etc/ssh/sshd_config:20  SSH020 medium   PasswordAuthentication no has no effect: sshd uses the first value it reads, yes, from testdata/ubuntu/etc/ssh/sshd_config.d/50-cloud-init.conf:1
testdata/ubuntu/etc/ssh/sshd_config.d/50-cloud-init.conf:1  SSH002 medium   PasswordAuthentication is yes: passwords can be guessed, phished and reused; prefer keys or certificates
2 file(s) read; 2 medium, 1 low

$ sshwarden testdata/legacy/sshd_config
testdata/legacy/sshd_config:2  SSH041 info     Protocol was removed from OpenSSH and is ignored
testdata/legacy/sshd_config:4  SSH008 high     HostKey /etc/ssh/ssh_host_dsa_key is a DSA key: 1024-bit, removed from OpenSSH 10
testdata/legacy/sshd_config:7  SSH004 medium   Ciphers enables aes256-cbc: CBC mode in SSH is open to plaintext-recovery attacks
testdata/legacy/sshd_config:7  SSH004 high     Ciphers enables 3des-cbc: 64-bit block cipher (Sweet32)
testdata/legacy/sshd_config:8  SSH005 high     MACs enables hmac-md5: MD5
testdata/legacy/sshd_config:9  SSH006 high     KexAlgorithms enables diffie-hellman-group1-sha1: 1024-bit group (Logjam-era) and SHA-1
testdata/legacy/sshd_config:10  SSH007 medium   PubkeyAcceptedAlgorithms enables ssh-rsa: RSA with SHA-1 signatures, disabled by default since OpenSSH 8.8
testdata/legacy/sshd_config:10  SSH041 info     PubkeyAcceptedKeyTypes is an old name for PubkeyAcceptedAlgorithms
testdata/legacy/sshd_config:14  SSH041 info     ChallengeResponseAuthentication is an old name for KbdInteractiveAuthentication
testdata/legacy/sshd_config:15  SSH013 medium   StrictModes no accepts world-writable home directories and key files
testdata/legacy/sshd_config:16  SSH015 low      MaxAuthTries 10 allows more guesses per connection than the default of 6
testdata/legacy/sshd_config:19  SSH001 high     PermitRootLogin yes lets root log in by any enabled method, passwords included; use prohibit-password, forced-commands-only or no [Match Address 10.0.0.0/8]
testdata/legacy/sshd_config:20  SSH002 medium   PasswordAuthentication is yes: passwords can be guessed, phished and reused; prefer keys or certificates [Match Address 10.0.0.0/8]
testdata/legacy/sshd_config:21  SSH042 high     Ciphers is not allowed inside a Match block (line 18 of testdata/legacy/sshd_config); sshd refuses to start
testdata/legacy/sshd_config:24  SSH042 high     PermitUserEnvironment is not allowed inside a Match block (line 23 of testdata/legacy/sshd_config); sshd refuses to start
1 file(s) read; 7 high, 4 medium, 1 low, 3 info
```
<!-- demo:end -->

In the first example the line an administrator added (line 20) is reported as having no
effect, with the drop-in line that beats it. In the second, a Match block re-enables root
login for one network, and two lines would stop sshd from starting at all.

## Usage

```bash
go install github.com/sriharifortitude/sshwarden/cmd/sshwarden@v0.1.0

sshwarden /etc/ssh/sshd_config
sshwarden --root /mnt/backup /mnt/backup/etc/ssh/sshd_config     # a copy of another machine's /etc
sudo sshd -T | sshwarden -                                        # audit the server's own resolved settings
sshwarden --effective /etc/ssh/sshd_config                        # what is in force, and which line set it
sshwarden --defaults <(sudo sshd -T -f /dev/null) sshd_config     # the installed sshd's defaults, not 9.6's
sshwarden --openssh-version 9.3 sshd_config                       # also check for Terrapin (CVE-2023-48795)
```

Exit codes: 0 nothing at or above `--fail-on` (default medium), 1 at least one finding is,
2 a usage error or an unreadable file. `--json` gives the files read and the findings.

## How it reads a configuration

- **Include** patterns are expanded in sorted order. Absolute paths are taken under
  `--root`; relative ones under `/etc/ssh` (under `--root`), or next to the main file when
  there is no `--root`. Nesting stops at 16 levels, as in sshd, and a file that includes
  itself is reported.
- **The first value wins** for every keyword except those that accumulate (Port, HostKey,
  ListenAddress, AllowUsers, DenyUsers, AllowGroups, DenyGroups, AcceptEnv, Subsystem and a
  few more). A later, different value is reported as SSH020 with the line that wins.
  `ChallengeResponseAuthentication` is the same setting as `KbdInteractiveAuthentication`,
  so whichever comes first wins for both.
- **Match blocks** override the global section for the connections they match. A Match block
  opened in an included file ends with that file. Keywords sshd refuses inside Match are
  reported, because sshd will not start.
- **Algorithm lists** starting with `+`, `-` (wildcards allowed) or `^` are applied to the
  default list.
- **Defaults** are upstream OpenSSH 9.6's, the version in Ubuntu 24.04 LTS. With
  `--defaults` they come from the real sshd instead.

[ADR 1](docs/adr/0001-model-sshds-reading-not-the-file.md) explains why the tool is built
around this, and how it is tested against a real sshd.

## Checks

| ID | Severity | What it finds |
|---|---|---|
| SSH001 | high | `PermitRootLogin yes` |
| SSH002 | medium | password login possible: `PasswordAuthentication yes` (the default), or keyboard-interactive with `UsePAM yes`; not reported when `AuthenticationMethods` rules passwords out |
| SSH003 | critical | `PermitEmptyPasswords yes` |
| SSH004-SSH007 | critical to medium | broken ciphers, MACs, key exchange or signature algorithms enabled ([ADR 2](docs/adr/0002-what-counts-as-weak.md) has the list and why it is short) |
| SSH008 | high | a DSA host key |
| SSH009 | medium | Terrapin: chacha20-poly1305, or CBC with an EtM MAC, on a server older than 9.6 (needs `--openssh-version`) |
| SSH010 | low | `X11Forwarding yes` |
| SSH011 | medium / low | `GatewayPorts yes` or `clientspecified`; `PermitTunnel` on |
| SSH012 | medium | `PermitUserEnvironment` other than `no` |
| SSH013 | medium | `StrictModes no` |
| SSH014 | medium | host-based authentication; `IgnoreRhosts no` |
| SSH015 | low | `MaxAuthTries` above 6; `LoginGraceTime` 0 or over ten minutes |
| SSH016 | low | `LogLevel` QUIET, FATAL or ERROR, which do not log logins |
| SSH020 | medium | a value sshd ignores because the keyword was set earlier |
| SSH040 / SSH042 / SSH043 | high | lines that stop sshd from starting: unknown keyword, missing value, unterminated quote, a keyword not allowed in Match, an Include cycle or too deep |
| SSH041 | info | a removed keyword (Protocol, UsePrivilegeSeparation, ...) or an old alias |

Every rule that applies inside Match runs on each Match block too, and a block is reported
only where it sets the weak value itself, labelled with its criteria.

## Tested

```bash
go test ./...                       # 47 tests and a fuzz target
./scripts/differential.sh           # against a real sshd; needs openssh-server and sudo
```

**Against a real sshd: written, not yet run.** `scripts/differential.sh` runs `sshd -T` on
four fixtures (OpenSSH's stock file, the Ubuntu layout, a hardened file, and one written to
exercise `+`/`-`/`^` lists, wildcard removal, an alias losing to its first spelling and a time
value) and requires every value `sshwarden --effective` prints to equal sshd's. It also
requires `sshd -t` to reject a fixture exactly when sshwarden predicts sshd will not start.
There is no sshd on the Windows machine this was built on, so the script runs for the first
time in CI. Until it passes there, treat the list of keywords allowed inside Match, and the
form of each value in `--effective`, as my reading of sshd_config(5) and not as verified.

**Real files.** The `sshd_config` that OpenSSH 10.3 ships (as bundled with Git for Windows)
gives exactly one finding: password authentication is on by default. The Ubuntu fixture is
laid out like the file Ubuntu 22.04 and 24.04 install, reconstructed from memory rather than
copied from an installed system.

**Mutation testing.** I broke the code in 54 places on purpose. On the first run, 4 mutants
survived and 5 did not compile, which I rewrote so they do. One survivor marked a redundant
check, which I deleted. The other three were test gaps. An Include cycle was caught only by
the nesting limit, which happens to give the same severity, so no test checked that the
cycle was named. `LogLevel ERROR` had no test. And `--effective` printing
`without-password` was only tested with input already spelled that way. A later mutant
showed a design mistake rather than a test gap: weak algorithms in the default list were
never reported, which hides real ones when the defaults come from an old sshd. That is
fixed, and has a test. All 52 mutants of the current code are caught.

**Hostile input.** Files are capped at 1 MiB, included files at 256, nesting at 16. A fuzz
target runs the parser and the effective-configuration code. 1 MiB files of 40,000 repeated
keywords, 15,000 Match blocks, 50,000 wildcard patterns in one `Ciphers -` line, or 90,000
users on one `AllowUsers` line each take under a second.

**Not tested:** against sshd (above); Match criteria against a particular connection (use
`sshd -T -C user=...,addr=...`); vendor builds whose defaults differ from upstream (use
`--defaults`); Windows' OpenSSH server, which reads `%ProgramData%\ssh\sshd_config` and adds
its own keywords.

## Limits

- **A configuration, not a server.** It does not connect, see host keys' sizes or know the
  installed version unless told. ssh-audit inspects a running server.
- **Match blocks one at a time.** Each block is judged against the global section; where two
  blocks match the same connection, sshd uses the first, and this tool does not decide which
  connections overlap.
- **A short list of weak algorithms on purpose.** See ADR 2: NIST curves, hmac-sha1 and
  umac-64 are OpenSSH defaults and are not reported.
- **Home-directory includes** (`Include ~/...`) are reported and not followed.

## Licence

MIT.
