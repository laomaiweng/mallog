#!/bin/bash --
# download, extract and set up the frida libs
# env vars configured in .cargo/config.toml expect us

frida_version=15.1.17

frida_releases="https://github.com/frida/frida/releases/download/$frida_version"

frida_devkit() {
    echo "frida-$1-devkit-$frida_version-linux-x86_64.tar.xz"
}


die() {
    printf "error: %s\n" "$*"
} >&2

base="${0%/*}"
devkits="$base"/devkits

# these dirs are passed by cargo/rustc to ld as "-L" directories
# we'll symlink the frida static libs in there so that ld finds them
mkdir -p "$base"/target/{debug,release}/deps || die mkdir

# download, extract and symlink the devkits
mkdir -p "$devkits" || die mkdir
for lib in core gum; do
    tarball=$(frida_devkit "$lib")
    if [[ ! -f "$devkits/$tarball" ]]; then
        wget -c -O "$devkits/$tarball" "$frida_releases/$tarball" || die wget
    fi
    tar -C "$devkits" -xvf "$devkits/$tarball" || die tar
    for d in debug release; do
        ln -sf ../../../devkits/libfrida-"$lib".a "$base/target/$d/deps" || die ln
    done
done
