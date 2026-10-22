#!/bin/sh
set -eu

usage() {
    printf 'Usage: install.sh [--root PATH] [--bin PATH]\n'
    printf 'Install the latest stable RevKit release for Linux x86-64.\n'
}

root=
bin_path=${REVKIT_BIN:-${HOME:?HOME is not set}/.local/bin/revkit}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                usage >&2
                exit 2
            fi
            root=$2
            shift 2
            ;;
        --bin)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                usage >&2
                exit 2
            fi
            bin_path=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "$(uname -s)" in
    Linux) ;;
    *) printf 'RevKit supports Linux x86-64 only.\n' >&2; exit 2 ;;
esac
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) printf 'RevKit supports x86-64 only.\n' >&2; exit 2 ;;
esac

if [ ! -r /etc/os-release ]; then
    printf 'Cannot read /etc/os-release.\n' >&2
    exit 2
fi
# shellcheck disable=SC1091
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
    *" debian "*|*" ubuntu "*) ;;
    *) printf 'RevKit requires a Debian-family APT system.\n' >&2; exit 2 ;;
esac

if ! command -v sha256sum >/dev/null 2>&1; then
    printf 'sha256sum is required to verify the release.\n' >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    printf 'curl is required to download the verified release.\n' >&2
    exit 1
fi

case "$bin_path" in
    /*) ;;
    *) bin_path=$(pwd -P)/$bin_path ;;
esac
bin_dir=${bin_path%/*}
if [ "$bin_dir" = "$bin_path" ]; then
    bin_dir=.
fi
mkdir -p "$bin_dir"
if [ -L "$bin_dir" ] || [ ! -d "$bin_dir" ]; then
    printf 'Refusing to install into a symlink or non-directory: %s\n' "$bin_dir" >&2
    exit 1
fi
if [ -L "$bin_path" ] || { [ -e "$bin_path" ] && [ ! -f "$bin_path" ]; }; then
    printf 'Refusing to replace a symlink or non-file: %s\n' "$bin_path" >&2
    exit 1
fi

umask 077
tmp_binary=$(mktemp "$bin_dir/.revkit-download.XXXXXXXX")
tmp_sums=$(mktemp "$bin_dir/.revkit-sums.XXXXXXXX")
cleanup() {
    rm -f "$tmp_binary" "$tmp_sums"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

release_url=https://github.com/Voldigoade/revkit/releases/latest/download
download() {
    url=$1
    output=$2
    effective=$(curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 -w '%{url_effective}' "$url" -o "$output")
    case "$effective" in
        https://github.com/*|https://release-assets.githubusercontent.com/*|https://objects.githubusercontent.com/*|https://github-releases.githubusercontent.com/*) ;;
        *) printf 'Download redirected to an untrusted host.\n' >&2; exit 1 ;;
    esac
}

download "$release_url/SHA256SUMS" "$tmp_sums"
download "$release_url/revkit-linux-amd64" "$tmp_binary"

sum_lines=$(awk '$2 == "revkit-linux-amd64" || $2 == "*revkit-linux-amd64" { print $1 }' "$tmp_sums")
if [ "$(printf '%s\n' "$sum_lines" | awk 'NF { count++ } END { print count+0 }')" -ne 1 ]; then
    printf 'SHA256SUMS must contain exactly one revkit-linux-amd64 entry.\n' >&2
    exit 1
fi
case "$sum_lines" in
    *[!0123456789abcdefABCDEF]*|'') printf 'Invalid SHA-256 entry.\n' >&2; exit 1 ;;
esac
if [ "${#sum_lines}" -ne 64 ]; then
    printf 'Invalid SHA-256 length.\n' >&2
    exit 1
fi
printf '%s  %s\n' "$sum_lines" "$tmp_binary" | sha256sum --check --status - || {
    printf 'RevKit release checksum verification failed.\n' >&2
    exit 1
}

chmod 0755 "$tmp_binary"
mv -f "$tmp_binary" "$bin_path"
cleanup
trap - EXIT HUP INT TERM
if [ -n "$root" ]; then
    exec "$bin_path" --root "$root" install
fi
exec "$bin_path" install
