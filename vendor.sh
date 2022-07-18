#!/bin/bash

die() {
    printf '[!] Error: %s\n' "$*"
    exit 1
} >&2

git show-ref --verify --quiet refs/heads/vendor && { git branch -D vendor || die 'git branch -D'; echo '[+] Old vendor branch deleted.'; }
git checkout -b vendor || die 'git checkout'
echo '[+] Vendor branch created.'

cargo vendor -- third_party || die 'cargo vendor'
echo '[+] Cargo dependencies vendored.'

mkdir -p .cargo || die mkdir
cat >>.cargo/config.toml <<-EOF || die cat
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "third_party"
EOF
echo '[+] .cargo/config.toml created.'

git add -f third_party/ .cargo/ || die 'git add'
echo '[+] Configuration & dependencies added.'

git commit -m 'vendor dependencies'
echo '[+] Vendoring committed to vendor branch, please inspect before bundling.'
