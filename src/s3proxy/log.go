package main

import (
	"io"
	"io/ioutil"
	"log"
	"os"
)

var InfoLogger *log.Logger
var ErrorLogger *log.Logger

const LogInfoPrefix = "INFO  "
const LogErrorPrefix = "ERROR "

func makeLogger(output io.Writer, prefix string) *log.Logger {
	return log.New(output, prefix, log.LstdFlags|log.Lshortfile)
}

func init() {
	InfoLogger = makeLogger(ioutil.Discard, LogInfoPrefix)
	ErrorLogger = makeLogger(os.Stderr, LogErrorPrefix)
}

func enableDebugMode(enable bool) {
	var w = ioutil.Discard

	if enable {
		w = os.Stdout
	}

	InfoLogger = makeLogger(w, LogInfoPrefix)
}
