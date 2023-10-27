package hole

import (
	"fmt"
	"github.com/gorilla/websocket"
	"net/http"
)

type pairInfo struct {
	CtrlAddress   []string `json:"ctrl_address"`
	CtrledAddress []string `json:"ctrled_address"`

	ctrlConn   *websocket.Conn
	ctrledConn *websocket.Conn
	waiterNb   int
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

var allRooms = make(map[string]*pairInfo)

func (pi *pairInfo) addAddr(role string, addresses []string) {
	switch role {
	case "ctrl":
		for _, addr := range addresses {
			pi.CtrlAddress = append(pi.CtrlAddress, addr)
		}

	case "ctrled":
		for _, addr := range addresses {
			pi.CtrledAddress = append(pi.CtrledAddress, addr)
		}
	default:
		logger.Errorf("unknown role:%v", role)
	}
}

func (pi *pairInfo) setConn(role string, conn *websocket.Conn) {
	switch role {
	case "ctrl":
		pi.ctrlConn = conn
	case "ctrled":
		pi.ctrledConn = conn
	default:
		logger.Errorf("unknown role:%v", role)
	}
}

func (pi *pairInfo) bothConnected() bool {
	return len(pi.CtrlAddress) > 0 && len(pi.CtrledAddress) > 0
}

// url: /room?room=???&addr=???&role=???
func enterRoom(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	logger.Infof("param is %v", params)

	var pi *pairInfo
	role := params.Get("role")
	if len(role) == 0 {
		logger.Error("error: no role")
		return
	}

	addresses := params["addr"]
	if len(addresses) == 0 {
		logger.Error("error: no addresses")
		w.WriteHeader(404)
		return
	}

	roomName := params.Get("room")
	if len(roomName) == 0 {
		logger.Error("error: no room")
		return
	}

	logger.Infof("set addresses based on role %v", role)
	if oldPairInfo, ok := allRooms[roomName]; ok {
		pi = oldPairInfo
	} else {
		pi = new(pairInfo)
		allRooms[roomName] = pi
	}
	pi.addAddr(role, addresses)
	logger.Infof("set room pair info to %v", pi)

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Infof("upgraded with err: %v\n", err)
		conn.Close()
		pi.setConn(role, nil)
		return
	} else {
		pi.setConn(role, conn)
	}

	go func() {
		// when websocket connection shutdown, set pair info's state
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				logger.Infof("room %v of %v connection is closed", roomName, role)
				pi.setConn(role, nil)
				return
			}
		}
	}()

	if !pi.bothConnected() {
		return
	}

	// one-shot notification to peers and remove room pair info
	if pi.ctrlConn != nil {
		logger.Infof("notify ctrl of room %v with %v", roomName, pi)
		pi.ctrlConn.WriteJSON(pi)
		pi.ctrlConn.Close()
	}
	if pi.ctrledConn != nil {
		logger.Infof("notify ctrled of room %v with %v", roomName, pi)
		pi.ctrledConn.WriteJSON(pi)
		pi.ctrledConn.Close()
	}
	delete(allRooms, roomName)
}

func StartHttp(port int64) {
	addr := fmt.Sprintf(":%v", port)
	logger.Infof("start signal http server at %v", addr)
	http.HandleFunc("/room", enterRoom)
	http.ListenAndServe(addr, nil)
}
