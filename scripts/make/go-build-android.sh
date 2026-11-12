#!/bin/sh

# AdGuard-Home-GoGoGo-Core Dedicated Android ARM64 Build Script
#
# Default Profile (Profile B — 100% Pure DNS Firewall):
#   GOOS=linux GOARCH=arm64 GOARM64=v8.2 CGO_ENABLED=0
#   -tags="android_slim,nosni,netgo,osusergo"
#   -trimpath -buildvcs=false -ldflags="-s -w -buildid= ..."

verbose="${VERBOSE:-0}"
readonly verbose

if [ "$verbose" -gt '1' ]; then
	env
	set -x
	v_flags='-v=1'
	x_flags='-x=1'
elif [ "$verbose" -gt '0' ]; then
	set -x
	v_flags='-v=1'
	x_flags='-x=0'
else
	set +x
	v_flags='-v=0'
	x_flags='-x=0'
fi
readonly x_flags v_flags

set -e -f -u

go="${GO:-go}"
readonly go

channel="${CHANNEL:-release}"
readonly channel

case "$channel" in
'development' | 'edge' | 'beta' | 'release' | 'candidate')
	;;
*)
	echo "invalid channel '$channel'" 1>&2
	exit 1
	;;
esac

version="${VERSION:-}"
if [ "$version" = 'v0.0.0' ] || [ "$version" = '' ]; then
	version="$(sh ./scripts/make/version.sh)"
fi
readonly version

committime="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}"
readonly committime

version_pkg='github.com/AdguardTeam/AdGuardHome/internal/version'
readonly version_pkg

ldflags="-s -w -buildid="
ldflags="${ldflags} -X ${version_pkg}.version=${version}"
ldflags="${ldflags} -X ${version_pkg}.channel=${channel}"
ldflags="${ldflags} -X ${version_pkg}.committime=${committime}"
readonly ldflags

out="${OUT:-AdGuardHome}"
readonly out

GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-arm64}"
CGO_ENABLED='0'
export GOOS GOARCH CGO_ENABLED

if [ "$GOARCH" = 'arm64' ]; then
	GOARM64="${GOARM64:-v8.2}"
	export GOARM64
fi

build_tags="${BUILD_TAGS:-android_slim,nosni,netgo,osusergo}"
readonly build_tags

"$go" build \
	-trimpath \
	-buildvcs=false \
	-tags="$build_tags" \
	--ldflags="$ldflags" \
	-o="$out" \
	"$v_flags" \
	"$x_flags" \
	.

bytes="$(wc -c < "$out" | tr -d ' ')"
printf 'Built %s (%s/%s, tags=%s): %s bytes\n' \
	"$out" "$GOOS" "$GOARCH" "$build_tags" "$bytes"
