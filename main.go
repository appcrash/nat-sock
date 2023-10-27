package main

import (
	"flag"
	"stun/hole"
)

// flagOpType: ctrl ctrled http
var (
	flagNic          = flag.String("i", "", "which nic allowed")
	flagOpType       = flag.String("op", "", "operation type")
	flagSignalServer = flag.String("signal", "", "signal server address")
	flagRoom         = flag.String("room", "", "room name")
	flagPort         = flag.Int("port", 0, "listen port")
	flagStunServer   = flag.String("stun", "", "stun or turn server")
)

// usage:
// -op ctrl -room roomName
// -op ctrled -room roomName
// http listenPort

func main() {
	flag.Parse()

	if len(*flagOpType) == 0 {
		panic("need more argument")
		return
	}

	switch *flagOpType {
	case "http":
		hole.StartHttp(int64(*flagPort))
	case "ctrl":
		hole.StartCtrl(*flagNic, *flagSignalServer, *flagStunServer,"ctrl", *flagRoom)
	case "ctrled":
		hole.StartCtrl(*flagNic, *flagSignalServer, *flagStunServer,"ctrled", *flagRoom)
	}

}
