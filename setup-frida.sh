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
target="$base"/target

# these dirs are passed by cargo/rustc to ld as "-L" directories
# we'll symlink the frida static libs in there so that ld finds them
mkdir -p "$target"/{debug,release}/deps || die mkdir
echo "Signature: 8a477f597d28d172789f06886806bc55" >"$target"/CACHEDIR.TAG  # play nice with backup systems

# download, extract and symlink the devkits
mkdir -p "$devkits" || die mkdir
echo "Signature: 8a477f597d28d172789f06886806bc55" >"$devkits"/CACHEDIR.TAG  # play nice with backup systems
for lib in core gum; do
    tarball=$(frida_devkit "$lib")
    if [[ ! -f "$devkits/$tarball" ]]; then
        wget -c -O "$devkits/$tarball" "$frida_releases/$tarball" || die wget
    fi
    tar -C "$devkits" -xvf "$devkits/$tarball" || die tar
    for d in debug release; do
        ln -sf ../../../devkits/libfrida-"$lib".a "$target/$d/deps" || die ln
    done
done
