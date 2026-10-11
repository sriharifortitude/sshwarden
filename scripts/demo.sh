#!/usr/bin/env bash
# Prints the README's example: each command, then what it prints. Run from anywhere.
set -u
cd "$(dirname "$0")/.."
bin=${SSHWARDEN:-./bin/sshwarden}
echo "\$ sshwarden --root testdata/ubuntu testdata/ubuntu/etc/ssh/sshd_config"
"$bin" --root testdata/ubuntu testdata/ubuntu/etc/ssh/sshd_config | tr -d '\r'
echo
echo "\$ sshwarden testdata/legacy/sshd_config"
"$bin" testdata/legacy/sshd_config | tr -d '\r'
