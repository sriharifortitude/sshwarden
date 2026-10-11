# 1. Model sshd's reading, not the file

Status: accepted

## Context

Most sshd_config checkers grep: find `PasswordAuthentication`, read its value. sshd does
not read a file that way, and the differences are where real configurations go wrong:

- **The first value wins.** "Unless noted otherwise, for each keyword, the first obtained
  value will be used" (sshd_config(5)). Ubuntu and Debian ship `Include
  /etc/ssh/sshd_config.d/*.conf` as the first line of sshd_config, so a drop-in such as
  cloud-init's `50-cloud-init.conf` decides `PasswordAuthentication` before the main file
  is read. A `PasswordAuthentication no` appended to sshd_config, the usual hardening
  step, then does nothing, and a grep reports the server as hardened.
- **Match blocks override the global section** for the connections they match, even
  though they come later in the file.
- **Algorithm lists are edits of a default**: `+` appends, `-` removes (with wildcards), `^`
  puts first. `Ciphers +3des-cbc` contains no list of ciphers at all.
- **Some keywords accumulate** (Port, HostKey, AllowUsers, ...), some are aliases
  (ChallengeResponseAuthentication is KbdInteractiveAuthentication), and some are refused
  inside Match, which stops sshd from starting.

## Decision

Build the effective configuration first, then judge it. Includes are followed in sorted
glob order, with `--root` to audit a copy of another machine's /etc. A Match block opened in
an included file ends with that file, and an Include inside a Match block stays in it. The
first value of each single-valued keyword wins within its scope, and a later different
value is a finding of its own (SSH020) that names the line that won. Algorithm lists are
evaluated against the default, which comes from OpenSSH 9.6 or, with `--defaults`, from a
real `sshd -T -f /dev/null`.

Each rule runs on the global section and on each Match block. A finding in a block is
reported only where the block itself sets the value, so a block does not repeat the global
findings.

## How it is checked

My reading of the manual is only a hypothesis, so CI tests it against the real thing.
`scripts/differential.sh` installs openssh-server and runs `sshd -T` on four fixtures,
comparing every value `sshwarden --effective` prints. It also checks that `sshd -t`
rejects exactly the fixtures where sshwarden says sshd will refuse to start. There is no
sshd on the machine this was written on, so the first time this runs is the first CI run.

## Consequences

- The tool reports the line that is in force, not the line a reader would look at, and
  says which line overrides which.
- Match blocks are judged one at a time against the global section. When a connection
  matches two blocks, sshd uses the first block's value; this tool does not evaluate
  Match criteria against a connection, so it cannot say which blocks overlap. `sshd -T -C
  user=...,addr=...` answers that for one connection.
