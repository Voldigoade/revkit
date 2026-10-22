#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
if grep -F -- '--notes' "$repo_root/scripts/create-release.sh"; then
	echo "release script must generate notes instead of using static notes" >&2
	exit 1
fi
if grep -F 'v0.2.0' "$repo_root/.github/workflows/release.yml" "$repo_root/scripts/create-release.sh"; then
	echo "release workflow contains a stale version-specific note" >&2
	exit 1
fi
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
mkdir -p "$temporary/bin"
cat > "$temporary/bin/gh" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$GH_ARGUMENTS"
EOF
chmod +x "$temporary/bin/gh"

if GH_ARGUMENTS="$temporary/arguments" PATH="$temporary/bin:$PATH" \
	sh "$repo_root/scripts/create-release.sh" v0.2.1 dist/revkit-linux-amd64 dist/SHA256SUMS; then
	:
else
	echo "release-note generation command failed" >&2
	exit 1
fi

cat > "$temporary/expected" <<'EOF'
release
create
v0.2.1
dist/revkit-linux-amd64
dist/SHA256SUMS
--title
v0.2.1
--generate-notes
EOF
if ! cmp -s "$temporary/expected" "$temporary/arguments"; then
	echo "release creation did not pass the current tag and generated-notes option" >&2
	diff -u "$temporary/expected" "$temporary/arguments" >&2 || true
	exit 1
fi

echo "release-note generation checks passed"
