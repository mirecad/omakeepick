#!/usr/bin/env bash
# Regenerates the KDBX fixtures from fixture.xml with KeePassXC (writes KDBX 3.1, AES-KDF).
# The KDBX 4 / Argon2 variants are derived from these inside the tests.
set -euo pipefail
cd "$(dirname "$0")"
rm -f password.kdbx password-keyfile.kdbx password-keyfile.keyx keyfile-only.kdbx raw.key
pw="test-password"
printf '%s\n%s\n' "$pw" "$pw" | keepassxc-cli import -q -p -t 100 fixture.xml password.kdbx
printf '%s\n%s\n' "$pw" "$pw" | keepassxc-cli import -q -p -t 100 --set-key-file password-keyfile.keyx fixture.xml password-keyfile.kdbx
head -c 64 /dev/urandom > raw.key
keepassxc-cli import -q -t 100 --set-key-file raw.key fixture.xml keyfile-only.kdbx </dev/null
