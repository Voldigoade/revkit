#!/bin/sh
set -eu

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/revkit-install-test.XXXXXXXX")
cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

fake_bin=$test_root/fake-bin
home=$test_root/home
mkdir -p "$fake_bin" "$home"
binary_fixture=$test_root/revkit-linux-amd64
sums_fixture=$test_root/SHA256SUMS
cat > "$binary_fixture" <<'SCRIPT'
#!/bin/sh
printf '%s\n' "$@" > "$REVKIT_TEST_LOG"
SCRIPT
chmod 0755 "$binary_fixture"
digest=$(sha256sum "$binary_fixture" | awk '{print $1}')
printf '%s  revkit-linux-amd64\n' "$digest" > "$sums_fixture"

cat > "$fake_bin/curl" <<'SCRIPT'
#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) output=$2; shift 2 ;;
        -w) shift 2 ;;
        http*) url=$1; shift ;;
        *) shift ;;
    esac
done
case "$url" in
    */SHA256SUMS) cp "$REVKIT_TEST_SUMS" "$output" ;;
    */revkit-linux-amd64)
        if [ "${REVKIT_TEST_BAD:-0}" = 1 ]; then
            printf 'tampered binary\n' > "$output"
        else
            cp "$REVKIT_TEST_BINARY" "$output"
        fi
        ;;
    *) exit 2 ;;
esac
printf '%s' "$url"
SCRIPT
chmod 0755 "$fake_bin/curl"

export HOME="$home"
export REVKIT_TEST_LOG="$test_root/invocation.log"
export REVKIT_TEST_BINARY="$binary_fixture"
export REVKIT_TEST_SUMS="$sums_fixture"
PATH=$fake_bin:$PATH
export PATH

root=$test_root/RevKit\ With\ Spaces
bin_path=$home/.local/bin/revkit
"$repo/install.sh" --root "$root" --bin "$bin_path"
expected=$(printf '%s\n' '--root' "$root" install)
actual=$(cat "$REVKIT_TEST_LOG")
[ "$actual" = "$expected" ] || { printf 'unexpected RevKit invocation:\n%s\n' "$actual" >&2; exit 1; }
if find "$home/.local/bin" -name '.revkit-sums.*' -print | grep . >/dev/null; then
    printf 'installer left a temporary checksum file behind\n' >&2
    exit 1
fi

installed=$(cat "$bin_path")
if REVKIT_TEST_BAD=1 "$repo/install.sh" --root "$root" --bin "$bin_path"; then
    printf 'installer accepted a checksum mismatch\n' >&2
    exit 1
fi
if [ "$(cat "$bin_path")" != "$installed" ]; then
    printf 'installer replaced the existing binary after checksum failure\n' >&2
    exit 1
fi

printf 'install bootstrap checks passed\n'
