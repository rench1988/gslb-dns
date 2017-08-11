package zone

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/rench1988/gslb-dns/log"
)

type Plats map[string]Areas

type Areas map[string]*Area

type Area struct {
	IPV4nodes []*node `json:"A"`
	IPV6nodes []*node `json:"AAAA"`
}

type node struct {
	Addr   string `json:"ip"`
	Weight int    `json:"weight"`
	Hc     *hc    `json:"hc"`
}

type hc struct {
	Type string `json:"type"`
	Port int    `json:"port"`
}

var (
	ponce sync.Once

	ps Plats
)

func NewPlats() Plats {
	ponce.Do(func() {
		ps = make(Plats)
	})

	return ps
}

func (ps Plats) AddPlatInfo(platName string, platFile string) error {
	file, err := os.Open(platFile)
	if err != nil {
		log.Printf("Failed to open nodes file: %s\n", err)
		return err
	}

	areas := make(Areas)

	decoder := json.NewDecoder(file)

	err = decoder.Decode(areas)
	if err != nil {
		log.Printf("Failed to parse config data: %s\n", err)
		return err
	}

	ps[platName] = areas

	return nil
}
