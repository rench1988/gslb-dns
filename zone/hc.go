package zone

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	hcInterval = 5 * time.Second
)

type hcUnit struct {
	addr     string
	htype    string
	hostport string
	port     int
	statue   int

	stop chan struct{}
}

type hcs map[string]*hcUnit

var (
	hcMutex sync.RWMutex

	healths hcs
)

var errNotsupported error = errors.New("health check type not supported")

func NewHcs() hcs {
	ponce.Do(func() {
		ps = make(Plats)
	})

	return healths
}

func (h hcs) Exists(addr string, ctype string, port int) bool {
	key := fmt.Sprintf("%s:%d", addr, port)

	hcMutex.RLock()
	defer hcMutex.RUnlock()

	_, ok := h[key]
	if ok {
		return true
	}

	return false
}

func (h hcs) IsHealthy(addr string, port int) bool {
	key := fmt.Sprintf("%s:%d", addr, port)

	hcMutex.RLock()
	defer hcMutex.RUnlock()

	u, ok := h[key]
	if !ok {
		return true
	}

	if u.statue == 1 {
		return true
	}

	return false
}

func (h hcs) Add(addr string, ctype string, port int) error {
	if ctype != "tcp" { //暂时只支持tcp
		return errNotsupported
	}

	hp := fmt.Sprintf("%s:%d", addr, port)

	//key := fmt.Sprintf("%s-%s", hp, ctype)

	//Add与Del是在同一个协程串行执行的
	hcMutex.Lock()
	h[hp] = &hcUnit{addr: addr, htype: ctype, hostport: hp, port: port, statue: 1}
	hcMutex.Unlock()

	go h[hp].run()

	return nil
}

func (h hcs) Del(key string) {
	//key := fmt.Sprintf("%s:%d-%s", addr, port, ctype)

	hcMutex.Lock()
	delete(h, key)
	hcMutex.Unlock()
}

func (u *hcUnit) run() {
	var stop bool

	for {
		select {
		case <-u.stop:
			stop = true
		}

		if stop {
			return
		}

		u.tcpCheck()

		time.Sleep(hcInterval)
	}
}

func (u *hcUnit) tcpCheck() {
	timeout := hcInterval

	c, err := net.DialTimeout("tcp", u.hostport, timeout)
	if err != nil {
		hcMutex.Lock()
		u.statue = 0
		hcMutex.Unlock()
	}

	c.Close()
}
