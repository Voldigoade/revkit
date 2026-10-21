#!/usr/bin/env bash
set -Eeuo pipefail

source_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
root="${HOME:?HOME is not set}/Desktop/RevKit"
dry_run=0

usage() {
  printf 'Usage: %s [--root PATH] [--dry-run]\n' "${0##*/}"
}

while (($#)); do
  case "$1" in
    --root)
      (($# >= 2)) || { usage >&2; exit 2; }
      root=$2
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
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

case "$root" in
  '~') root=$HOME ;;
  '~/'*) root="$HOME/${root#\~/}" ;;
  '~'*) printf 'Named-user paths are not supported: %s\n' "$root" >&2; exit 2 ;;
  /*) ;;
  *) root="$PWD/$root" ;;
esac
root=$(realpath -m -- "$root")

if [[ ! -r /etc/os-release ]]; then
  printf 'Cannot identify this operating system.\n' >&2
  exit 2
fi
# shellcheck disable=SC1091
source /etc/os-release
os_id=${ID,,}
if [[ "$os_id" != debian && "$os_id" != ubuntu ]]; then
  printf 'RevKit supports Debian and Ubuntu only.\n' >&2
  exit 2
fi
if [[ $(uname -m) != x86_64 ]]; then
  printf 'RevKit v0.1.0 supports x86-64 only.\n' >&2
  exit 2
fi

if ! command -v go >/dev/null 2>&1; then
  if ((dry_run)); then
    printf 'Go is required to build RevKit; dry-run made no changes.\n' >&2
    exit 1
  fi
  if [[ ! -x /usr/bin/apt-get ]]; then
    printf 'Go is required. Install Go 1.18 or newer, then run this script again.\n' >&2
    exit 1
  fi
  if ((EUID == 0)); then
    apt-get update
    apt-get install -y golang-go
  else
    command -v sudo >/dev/null 2>&1 || { printf 'Go is missing; install golang-go with sudo.\n' >&2; exit 1; }
    sudo apt-get update
    sudo apt-get install -y golang-go
  fi
fi

go_version=$(go version | awk '{print $3}')
go_version=${go_version#go}
go_major=${go_version%%.*}
go_rest=${go_version#*.}
go_minor=${go_rest%%.*}
if [[ ! $go_major =~ ^[0-9]+$ || ! $go_minor =~ ^[0-9]+$ ]] || ((go_major < 1 || (go_major == 1 && go_minor < 18))); then
  printf 'Go 1.18 or newer is required; found %s.\n' "$go_version" >&2
  exit 1
fi

if ((dry_run)); then
  tmp_binary=$(mktemp "${TMPDIR:-/tmp}/revkit-dry-run.XXXXXXXX")
  trap 'rm -f -- "$tmp_binary"' EXIT
  (cd -- "$source_dir" && GOTOOLCHAIN=local go build -trimpath -ldflags "-X main.version=v0.1.0" -o "$tmp_binary" ./cmd/revkit)
  "$tmp_binary" --root "$root" install --dry-run
  exit 0
fi

for path in \
  "$root" "$root/bin" \
  "$root/tools" "$root/tools/gui" "$root/tools/cli" \
  "$root/workspace" "$root/workspace/samples" "$root/workspace/reports" "$root/workspace/notes" \
  "$root/dashboard"; do
  if [[ -L "$path" || ( -e "$path" && ! -d "$path" ) ]]; then
    printf 'Refusing to use a symlink or non-directory in the installation root: %s\n' "$path" >&2
    exit 1
  fi
done

mkdir -p -- "$root/bin"
tmp_binary=$(mktemp "$root/bin/.revkit.XXXXXXXX")
trap 'rm -f -- "$tmp_binary"' EXIT
(cd -- "$source_dir" && GOTOOLCHAIN=local go build -trimpath -ldflags "-X main.version=v0.1.0" -o "$tmp_binary" ./cmd/revkit)
chmod 0755 "$tmp_binary"
if [[ -f "$root/bin/revkit" ]] && cmp -s -- "$tmp_binary" "$root/bin/revkit"; then
  rm -f -- "$tmp_binary"
else
  mv -f -- "$tmp_binary" "$root/bin/revkit"
fi

local_bin="$HOME/.local/bin"
mkdir -p -- "$local_bin"
link="$local_bin/revkit"
if [[ -L "$link" ]]; then
  existing=$(realpath -m -- "$link")
  if [[ "$existing" != "$root/bin/revkit" ]]; then
    printf 'Refusing to replace the existing revkit link: %s\n' "$link" >&2
    exit 1
  fi
elif [[ -e "$link" ]]; then
  printf 'Refusing to replace the existing file: %s\n' "$link" >&2
  exit 1
else
  ln -s -- "$root/bin/revkit" "$link"
fi

path_has() {
  local wanted=$1 entry
  local -a entries
  IFS=: read -r -a entries <<< "${PATH:-}"
  for entry in "${entries[@]}"; do
    [[ "$entry" == "$wanted" ]] && return 0
  done
  return 1
}

profile="$HOME/.profile"
if ! path_has "$local_bin" && ! grep -Fq '# >>> RevKit PATH >>>' "$profile" 2>/dev/null; then
  {
    printf '\n# >>> RevKit PATH >>>\n'
    printf 'case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) PATH="$HOME/.local/bin:$PATH" ;; esac\n'
    printf 'export PATH\n'
    printf '# <<< RevKit PATH <<<\n'
  } >> "$profile"
fi
if ! path_has "$local_bin"; then
  PATH="$local_bin:$PATH"
  export PATH
fi

"$root/bin/revkit" --root "$root" install
