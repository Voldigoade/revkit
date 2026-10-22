#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
	echo "usage: create-release.sh TAG BINARY CHECKSUMS" >&2
	exit 2
fi

tag=$1
binary=$2
checksums=$3
exec gh release create "$tag" "$binary" "$checksums" --title "$tag" --generate-notes
