#!/bin/sh
# Smoke-test an installed native package without touching a user's repository.
set -eu

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT HUP INT TERM
git init -q "$root/repository"
printf 'synthetic repository\n' > "$root/repository/sample.txt"
git -C "$root/repository" add sample.txt
git -C "$root/repository" -c user.name=Test -c user.email=test@example.invalid commit -qm test
refhound --version
refhound scan "$root/repository" --offline --quick --no-store --format json -o "$root/scan.json"
python3 -c 'import json, sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$root/scan.json"
