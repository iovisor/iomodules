// vim: set ts=8:sts=8:sw=8:noet

package main

import (
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/iovisor/iomodules/hive"
)

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM)
	signal.Notify(c, os.Interrupt)
	s := hive.NewServer()
	go func() {
		<-c
		s.Close()
		os.Exit(1)
	}()
	http.ListenAndServe(":5000", s.Handler())
}
