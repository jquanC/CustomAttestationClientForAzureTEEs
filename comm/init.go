package comm

import "log/slog"

var logLvl slog.Level

func init() {
	// logLvl = slog.LevelDebug
	logLvl = slog.LevelInfo
}
