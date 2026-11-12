//go:build !android_slim

package home

import (
	"github.com/AdguardTeam/golibs/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

func setFileLogger(ls *logSettings, logFilePath string) (err error) {
	log.SetOutput(&lumberjack.Logger{
		Filename:   logFilePath,
		Compress:   ls.compress,
		LocalTime:  ls.localTime,
		MaxBackups: ls.maxBackups,
		MaxSize:    ls.maxSize,
		MaxAge:     ls.maxAge,
	})

	return nil
}
