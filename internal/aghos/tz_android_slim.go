//go:build android_slim

package aghos

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"strings"
	"time"
)

// androidTZDataPaths lists standard Android Bionic tzdata container paths from
// newest APEX layout (Android 10–16) to legacy system partition fallback.
var androidTZDataPaths = []string{
	"/apex/com.android.tzdata/etc/tz/tzdata",
	"/apex/com.android.runtime/etc/tz/tzdata",
	"/system/usr/share/zoneinfo/tzdata",
}

// InitAndroidTZ initializes [time.Local] on Android without embedding Go's
// 408 KB _ "time/tzdata" database by reading the device's active timezone and
// parsing the system APEX tzdata container.
func InitAndroidTZ() {
	if _, err := os.Stat("/etc/localtime"); err == nil {
		// Standard Linux environment (e.g., container verification) already has
		// zoneinfo configured.
		return
	}

	tzName := strings.TrimSpace(os.Getenv("TZ"))
	if tzName == "" {
		if out, err := exec.Command("/system/bin/getprop", "persist.sys.timezone").Output(); err == nil {
			tzName = strings.TrimSpace(string(out))
		}
	}
	if tzName == "" || tzName == "UTC" || tzName == "GMT" {
		return
	}

	for _, p := range androidTZDataPaths {
		loc, err := loadLocationFromAndroidTZData(p, tzName)
		if err == nil && loc != nil {
			time.Local = loc
			return
		}
	}
}

// loadLocationFromAndroidTZData extracts a single TZif payload for tzName from
// an Android Bionic concatenated tzdata file and parses it via stdlib.
func loadLocationFromAndroidTZData(tzdataPath, tzName string) (loc *time.Location, err error) {
	const (
		headerSize = 24
		entrySize  = 52
		nameField  = 40
	)

	data, err := os.ReadFile(tzdataPath)
	if err != nil || len(data) < headerSize || !bytes.HasPrefix(data, []byte("tzdata")) {
		return nil, os.ErrNotExist
	}

	indexOff := binary.BigEndian.Uint32(data[12:16])
	dataOff := binary.BigEndian.Uint32(data[16:20])
	if indexOff < headerSize || dataOff <= indexOff || int(dataOff) > len(data) {
		return nil, os.ErrInvalid
	}

	for pos := indexOff; pos+entrySize <= dataOff; pos += entrySize {
		rawName := data[pos : pos+nameField]
		if nul := bytes.IndexByte(rawName, 0); nul >= 0 {
			rawName = rawName[:nul]
		}
		if string(rawName) != tzName {
			continue
		}

		relOff := binary.BigEndian.Uint32(data[pos+40 : pos+44])
		length := binary.BigEndian.Uint32(data[pos+44 : pos+48])
		start := uint64(dataOff) + uint64(relOff)
		end := start + uint64(length)
		if length == 0 || end > uint64(len(data)) {
			return nil, os.ErrInvalid
		}

		return time.LoadLocationFromTZData(tzName, data[start:end])
	}

	return nil, os.ErrNotExist
}
