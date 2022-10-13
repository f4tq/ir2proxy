package xds

import (
	"fmt"

	"gopkg.in/inconshreveable/log15.v2"
)

type log15GrpcLogger struct {
	logger    log15.Logger
	verbosity int
}

func (recv *log15GrpcLogger) Info(args ...interface{}) {
	recv.logger.Info(fmt.Sprint(args...))
}

func (recv *log15GrpcLogger) Infoln(args ...interface{}) {
	recv.logger.Info(fmt.Sprint(args...))
}

func (recv *log15GrpcLogger) Infof(format string, args ...interface{}) {
	recv.logger.Info(fmt.Sprintf(format, args...))
}

func (recv *log15GrpcLogger) Warning(args ...interface{}) {
	recv.logger.Warn(fmt.Sprint(args...))
}

func (recv *log15GrpcLogger) Warningln(args ...interface{}) {
	recv.logger.Warn(fmt.Sprint(args...))
}

func (recv *log15GrpcLogger) Warningf(format string, args ...interface{}) {
	recv.logger.Warn(fmt.Sprintf(format, args...))
}

func (recv *log15GrpcLogger) Error(args ...interface{}) {
	recv.logger.Error(fmt.Sprint(args...))
}

func (recv *log15GrpcLogger) Errorln(args ...interface{}) {
	recv.logger.Error(fmt.Sprint(args...))
}

func (recv *log15GrpcLogger) Errorf(format string, args ...interface{}) {
	recv.logger.Error(fmt.Sprintf(format, args...))
}

func (recv *log15GrpcLogger) Fatal(args ...interface{}) {
	recv.logger.Crit(fmt.Sprint(args...))
}

func (recv *log15GrpcLogger) Fatalln(args ...interface{}) {
	recv.logger.Crit(fmt.Sprint(args...))
}

func (recv *log15GrpcLogger) Fatalf(format string, args ...interface{}) {
	recv.logger.Crit(fmt.Sprintf(format, args...))
}

func (recv *log15GrpcLogger) V(level int) bool {
	return level <= recv.verbosity
}
