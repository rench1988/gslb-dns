package zone

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"sync"

	"github.com/miekg/dns"

	"github.com/rench1988/gslb-dns/log"
)

type Plats map[string]Areas

type Areas map[string]*Area

type Area struct {
	IPV4nodes []*node `json:"A"`
	IPV6nodes []*node `json:"AAAA"`

	Records map[uint16]Records

	ipv4Weight int
	ipv6Weight int
}

type node struct {
	Addr   string `json:"ip"`
	Weight int    `json:"weight"`
	Hc     *hc    `json:"hc"`

	status int //down or up
}

type hc struct {
	Type string `json:"type"`
	Port int    `json:"port"`
}

var (
	ponce sync.Once

	ps Plats

	pMutex sync.RWMutex
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

	for _, area := range areas {
		/*
			area.Records = make(map[uint16]Records)

			area.Records[dns.TypeA] = make(Records, len(area.IPV4nodes))
			area.Records[dns.TypeAAAA] = make(Records, len(area.IPV6nodes))
		*/
		for _, v4node := range area.IPV4nodes {
			area.ipv4Weight += v4node.Weight
		}
		for _, v6node := range area.IPV6nodes {
			area.ipv6Weight += v6node.Weight
		}

		sort.Slice(area.IPV4nodes, func(i, j int) bool { return area.IPV4nodes[i].Weight > area.IPV4nodes[j].Weight })
		sort.Slice(area.IPV6nodes, func(i, j int) bool { return area.IPV6nodes[i].Weight > area.IPV6nodes[j].Weight })
	}

	pMutex.Lock()
	ps[platName] = areas
	pMutex.Unlock()

	return nil
}

func (ps Plats) DeletePlatInfo(platName string) {
	pMutex.Lock()
	delete(ps, platName)
	pMutex.Unlock()
}

func (ps Plats) GetPlatAreaInfo(platName string, areaName string) *Area {
	pMutex.RLock()
	defer pMutex.RUnlock()
	p := ps[platName]
	if p == nil {
		return nil
	}

	area := p[areaName]

	return area
}

var lastHostPortPair map[string]bool

func (ps Plats) HealthCheck(changed bool) {
	if !changed {
		return
	}

	healths := NewHcs()

	tmp := make(map[string]bool)

	for _, plat := range ps {

		for _, area := range plat {

			ipv4s := area.IPV4nodes
			ipv6s := area.IPV6nodes

			for i := 0; i < len(ipv4s); i++ {
				v4node := ipv4s[i]

				if v4node.Hc == nil {
					continue
				}

				if healths.Exists(v4node.Addr, v4node.Hc.Type, v4node.Hc.Port) {
					continue
				}

				healths.Add(v4node.Addr, v4node.Hc.Type, v4node.Hc.Port)

				key := fmt.Sprintf("%s:%d-%s", v4node.Addr, v4node.Hc.Port, v4node.Hc.Type)
				tmp[key] = true
			}

			for i := 0; i < len(ipv6s); i++ {
				v6node := ipv6s[i]

				if v6node.Hc == nil {
					continue
				}

				if healths.Exists(v6node.Addr, v6node.Hc.Type, v6node.Hc.Port) {
					continue
				}

				healths.Add(v6node.Addr, v6node.Hc.Type, v6node.Hc.Port)

				key := fmt.Sprintf("%s:%d-%s", v6node.Addr, v6node.Hc.Port, v6node.Hc.Type)
				tmp[key] = true
			}
		}
	}

	if lastHostPortPair == nil {
		lastHostPortPair = tmp
		return
	}

	for pre := range lastHostPortPair {
		if _, ok := tmp[pre]; !ok {
			healths.Del(pre)
		}
	}

	lastHostPortPair = tmp
}

func (ps Plats) SearchPlatNode(platName string, areaName string, qtype uint16, max int) (res []string) {
	area := ps.GetPlatAreaInfo(platName, areaName)
	if area == nil {
		return nil
	}

	hcs := NewHcs()

	var (
		sum   int
		nodes []*node
	)
	if qtype == dns.TypeA {
		sum = area.ipv4Weight
		nodes = area.IPV4nodes
	} else {
		sum = area.ipv6Weight
		nodes = area.IPV6nodes
	}

	if max > len(nodes) {
		max = len(nodes)
	}

	if sum == 0 {
		for i := range nodes {
			if nodes[i].Hc == nil || hcs.IsHealthy(nodes[i].Addr, nodes[i].Hc.Port) {
				res = append(res, nodes[i].Addr)
			}
		}

		return res 
	}

	for si := 0; si < max; si++ {
		n := rand.Intn(sum + 1)
		s := 0

		for i := range nodes {
			s += int(nodes[i].Weight)
			if s >= n {
				sum -= nodes[i].Weight

				if nodes[i].Hc == nil || hcs.IsHealthy(nodes[i].Addr, nodes[i].Hc.Port) {
					res = append(res, nodes[i].Addr)
				}

				nodes = append(nodes[:i], nodes[i+1:]...)
				break
			}
		}
	}

	return res
}
