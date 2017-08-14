package zone

import (
	"math/rand"
	"net"

	"github.com/miekg/dns"
)

type Record struct {
	RR     dns.RR
	Weight int
}

type Label struct {
	Label    string
	MaxHosts int
	Ttl      int
	Platform string
	Records  map[uint16]Records
	Weight   map[uint16]int
}

type labels map[string]*Label

type Records []Record

func (s Records) Len() int      { return len(s) }
func (s Records) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

type RecordsByWeight struct{ Records }

func (s RecordsByWeight) Less(i, j int) bool { return s.Records[i].Weight > s.Records[j].Weight }

func (l *Label) firstRR(dnsType uint16) dns.RR {
	return l.Records[dnsType][0].RR
}

func (label *Label) Picker(qtype uint16, max int, area string) Records {

	if qtype == dns.TypeANY {
		var result []Record
		for rtype := range label.Records {

			rtypeRecords := label.Picker(rtype, max, area)

			tmpResult := make(Records, len(result)+len(rtypeRecords))

			copy(tmpResult, result)
			copy(tmpResult[len(result):], rtypeRecords)
			result = tmpResult
		}

		return result
	}

	if labelRR := label.Records[qtype]; labelRR != nil {

		// not "balanced", just return all
		if label.Weight[qtype] == 0 {
			return labelRR
		}

		if qtype == dns.TypeCNAME || qtype == dns.TypeMF {
			max = 1
		}

		rrCount := len(labelRR)
		if max > rrCount {
			max = rrCount
		}

		servers := make([]Record, len(labelRR))
		copy(servers, labelRR)
		result := make([]Record, max)
		sum := label.Weight[qtype]

		for si := 0; si < max; si++ {
			n := rand.Intn(sum + 1)
			s := 0

			for i := range servers {
				s += int(servers[i].Weight)
				if s >= n {
					sum -= servers[i].Weight
					result[si] = servers[i]

					// remove the server from the list
					servers = append(servers[:i], servers[i+1:]...)
					break
				}
			}
		}

		return result
	}

	if qtype == dns.TypeA || qtype == dns.TypeAAAA {
		ps := NewPlats()

		res := ps.SearchPlatNode(label.Platform, area, qtype, max)
		if len(res) == 0 {
			return nil
		}

		var h dns.RR_Header
		h.Class = dns.ClassINET
		h.Rrtype = qtype
		h.Name = label.Label + "." + label.Platform + "."

		//result := make([]Record, len(res))
		var result []Record

		for i := 0; i < len(res); i++ {
			record := new(Record)
			switch qtype {
			case dns.TypeA:
				if x := net.ParseIP(res[i]); x != nil {
					record.RR = &dns.A{Hdr: h, A: x}
					break
				}
			case dns.TypeAAAA:
				if x := net.ParseIP(res[i]); x != nil {
					record.RR = &dns.AAAA{Hdr: h, AAAA: x}
					break
				}
			}

			if record.RR != nil {
				result = append(result, *record)
			}
		}

		return result
	}

	return nil
}
