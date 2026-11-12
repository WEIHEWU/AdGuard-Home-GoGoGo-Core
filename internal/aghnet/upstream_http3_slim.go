//go:build android_slim

package aghnet

import "github.com/AdguardTeam/dnsproxy/upstream"

// UpstreamHTTPVersions always returns HTTP/1.1 + HTTP/2 in Android slim builds
// where HTTP/3 (QUIC) is excluded.
func UpstreamHTTPVersions(_ bool) (v []upstream.HTTPVersion) {
	return upstream.DefaultHTTPVersions
}
