package logger

import (
	"io"
	"os"

	"kapcom.adobe.com/config"
	"kapcom.adobe.com/constants"

	"github.com/onsi/ginkgo"
	"gopkg.in/inconshreveable/log15.v2"
)

func init() {
	// process the environment
	//config.Parser().ParseArgs([]string{})

	var logFmt log15.Format
	if config.ColorizeLogs() {
		logFmt = log15.TerminalFormat()
	} else if config.Testing() {
		logFmt = log15.LogfmtFormat()
	} else {
		logFmt = log15.JsonFormat()
	}

	var writer io.Writer
	if config.Testing() {
		writer = ginkgo.GinkgoWriter
	} else {
		writer = os.Stdout
	}

	/*
		Log stack traces for LvlCrit, LvlError, and LvlWarn
		to help us debug issues in the wild

		const (
			LvlCrit Lvl = iota
			LvlError
			LvlWarn
			LvlInfo
			LvlDebug
		)
	*/
	stackHandler := log15.StreamHandler(writer, logFmt)
	stackHandler = log15.CallerStackHandler("%+v", stackHandler)
	// put filter last because it will be run first
	stackHandler = log15.FilterHandler(func(r *log15.Record) bool {
		return r.Lvl <= log15.LvlWarn
	}, stackHandler)

	infoHandler := log15.StreamHandler(writer, logFmt)
	if config.DebugLogs() {
		infoHandler = log15.FilterHandler(func(r *log15.Record) bool {
			return r.Lvl >= log15.LvlInfo
		}, infoHandler)
	} else {
		infoHandler = log15.FilterHandler(func(r *log15.Record) bool {
			return r.Lvl == log15.LvlInfo
		}, infoHandler)
	}

	log15.Root().SetHandler(log15.MultiHandler(stackHandler, infoHandler))
}

func New(kvps ...interface{}) log15.Logger {
	kvps2 := append([]interface{}{"v", constants.ProgramVersion}, kvps...)
	return log15.Root().New(kvps2...)
}
