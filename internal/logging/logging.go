package logging

import (
	"fmt"
	"log/syslog"
	"strings"

	"github.com/rs/zerolog"
)

var (
	Logger zerolog.Logger

	// level prefix as defined in man 3 sd-daemon
	SD_EMERG   = fmt.Sprintf("<%d>", syslog.LOG_EMERG)
	SD_CRIT    = fmt.Sprintf("<%d>", syslog.LOG_CRIT)
	SD_ERR     = fmt.Sprintf("<%d>", syslog.LOG_ERR)
	SD_WARNING = fmt.Sprintf("<%d>", syslog.LOG_WARNING)
	SD_INFO    = fmt.Sprintf("<%d>", syslog.LOG_INFO)
	SD_DEBUG   = fmt.Sprintf("<%d>", syslog.LOG_DEBUG)
)

func Setup(cfg *Config, dev bool) {
	var l zerolog.Logger
	if cfg.UseSystemd {
		output := zerolog.NewConsoleWriter(
			func(w *zerolog.ConsoleWriter) {
				w.NoColor = true
				w.FormatTimestamp = func(i interface{}) string {
					return ""
				}
				w.FormatLevel = systemdLevelPrefix
			},
		)
		l = zerolog.New(output)
	} else if dev {
		output := zerolog.NewConsoleWriter()
		l = zerolog.New(output)
	}
	if cfg.Level == "" {
		l = l.Level(zerolog.InfoLevel)
	} else {
		l = l.Level(toZerologLvl(cfg.Level))
	}
	Logger = l.With().Timestamp().Logger()
}

func Trace() *zerolog.Event {
	return Logger.Trace()
}
func Debug() *zerolog.Event {
	return Logger.Debug()
}
func Info() *zerolog.Event {
	return Logger.Info()
}
func Warn() *zerolog.Event {
	return Logger.Warn()
}
func Error() *zerolog.Event {
	return Logger.Error()
}
func Fatal() *zerolog.Event {
	return Logger.Fatal()
}

func systemdLevelPrefix(i interface{}) string {
	var l string
	if ll, ok := i.(string); ok {
		switch ll {
		case "trace":
			l = SD_DEBUG
		case "debug":
			l = SD_DEBUG
		case "info":
			l = SD_INFO
		case "warn":
			l = SD_WARNING
		case "error":
			l = SD_ERR
		case "fatal":
			l = SD_CRIT
		case "panic":
			l = SD_EMERG
		default:
			l = ""
		}
	} else {
		if i == nil {
			l = ""
		} else {
			l = strings.ToUpper(fmt.Sprintf("%s", i))[0:3]
		}
	}
	return l
}

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	// Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	output := zerolog.NewConsoleWriter()
	Logger = zerolog.New(output).With().Timestamp().Logger()
}

// func consoleDefaultFormatTimestamp(timeFormat string, noColor bool) Formatter {
// 	if timeFormat == "" {
// 		timeFormat = consoleDefaultTimeFormat
// 	}
// 	return func(i interface{}) string {
// 		t := "<nil>"
// 		switch tt := i.(type) {
// 		case string:
// 			ts, err := time.Parse(TimeFieldFormat, tt)
// 			if err != nil {
// 				t = tt
// 			} else {
// 				t = ts.Format(timeFormat)
// 			}
// 		case json.Number:
// 			i, err := tt.Int64()
// 			if err != nil {
// 				t = tt.String()
// 			} else {
// 				var sec, nsec int64 = i, 0
// 				switch TimeFieldFormat {
// 				case TimeFormatUnixMs:
// 					nsec = int64(time.Duration(i) * time.Millisecond)
// 					sec = 0
// 				case TimeFormatUnixMicro:
// 					nsec = int64(time.Duration(i) * time.Microsecond)
// 					sec = 0
// 				}
// 				ts := time.Unix(sec, nsec).UTC()
// 				t = ts.Format(timeFormat)
// 			}
// 		}
// 		return colorize(t, colorDarkGray, noColor)
// 	}
// }
