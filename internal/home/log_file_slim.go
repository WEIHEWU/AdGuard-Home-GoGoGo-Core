//go:build android_slim

package home

import (
	"os"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/golibs/log"
)

func setFileLogger(_ *logSettings, logFilePath string) (err error) {
	// #nosec G304 -- Log path is explicitly configured by administrator.
	f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, aghos.DefaultPermFile)
	if err != nil {
		return err
	}

	log.SetOutput(f)

	return nil
}
