package zone

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/rench1988/gslb-dns/log"

	"github.com/miekg/dns"
	"github.com/rench1988/gslb-dns/qlog"
	"github.com/rench1988/gslb-dns/util"
)

var qLogger qlog.QLogger

var (
	zonce sync.Once

	zs Zones
)

type ZoneOptions struct {
	Serial   int
	Ttl      int
	MaxHosts int
	Contact  string
}

type Zone struct {
	Origin     string
	Labels     labels
	LabelCount int
	Options    ZoneOptions

	Platform string

	sync.RWMutex
}

type Zones map[string]*Zone

type qTypes []uint16

func NewZones() Zones {
	zonce.Do(func() {
		zs = make(Zones)
	})

	return zs
}

func (zs Zones) SetupGslbZone() {
	zoneName := "gslb-dns"
	Zone := newZone(zoneName)
	label := new(Label)
	label.Records = make(map[uint16]Records)
	label.Weight = make(map[uint16]int)
	Zone.Labels[""] = label
	setupSOA(Zone)
	zs.AddDNSHandler(zoneName, Zone)
}

func (zs Zones) SetupRootZone() {
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
	})
}

func (zs Zones) AddDNSHandler(zoneName string, z *Zone) {
	zs[zoneName] = z
	dns.HandleFunc(zoneName, func(w dns.ResponseWriter, r *dns.Msg) {
		serve(w, r, z)
	})
}

func (zs Zones) AddZoneInfo(platName string, zoneFile string) (z *Zone, err error) {
	fh, err := os.Open(zoneFile)
	if err != nil {
		log.Printf("Could not read '%s': %s", zoneFile, err)
		return nil, err
	}

	zone := newZone(platName)

	fi, err := fh.Stat()
	if err != nil {
		log.Printf("Could not stat '%s': %s", zoneFile, err)
	} else {
		zone.Options.Serial = int(fi.ModTime().Unix())
	}

	var objmap map[string]interface{}
	decoder := json.NewDecoder(fh)
	if err = decoder.Decode(&objmap); err != nil {
		return nil, err
	}

	var data map[string]interface{}

	for k, v := range objmap {
		switch k {
		case "ttl":
			zone.Options.Ttl = util.ValueToInt(v)
		case "serial":
			zone.Options.Serial = util.ValueToInt(v)
		case "contact":
			zone.Options.Contact = v.(string)
		case "max_hosts":
			zone.Options.MaxHosts = util.ValueToInt(v)
		case "data":
			data = v.(map[string]interface{})
		}
	}

	setupZoneData(data, zone)

	return zone, nil
}

func setupZoneData(data map[string]interface{}, Zone *Zone) {
	recordTypes := map[string]uint16{
		"a":     dns.TypeA,
		"aaaa":  dns.TypeAAAA,
		"alias": dns.TypeMF,
		"cname": dns.TypeCNAME,
		"mx":    dns.TypeMX,
		"ns":    dns.TypeNS,
		"txt":   dns.TypeTXT,
		"spf":   dns.TypeSPF,
		"srv":   dns.TypeSRV,
		"ptr":   dns.TypePTR,
	}

	for dk, dvInter := range data {
		dv := dvInter.(map[string]interface{})

		label := Zone.AddLabel(dk)

		for rType, rdata := range dv {
			switch rType {
			case "max_hosts":
				label.MaxHosts = util.ValueToInt(rdata)
				continue
			case "ttl":
				label.Ttl = util.ValueToInt(rdata)
				continue
			}

			dnsType, ok := recordTypes[rType]
			if !ok {
				log.Printf("Unsupported record type '%s'\n", rType)
				continue
			}

			if rdata == nil {
				continue
			}

			records := make(map[string][]interface{})

			switch rdata.(type) {
			case map[string]interface{}:
				// Handle NS map syntax, map[ns2.example.net:<nil> ns1.example.net:<nil>]
				tmp := make([]interface{}, 0)
				for rdataK, rdataV := range rdata.(map[string]interface{}) {
					if rdataV == nil {
						rdataV = ""
					}
					tmp = append(tmp, []string{rdataK, rdataV.(string)})
				}
				records[rType] = tmp
			case string:
				// CNAME and alias
				tmp := make([]interface{}, 1)
				tmp[0] = rdata.(string)
				records[rType] = tmp
			default:
				records[rType] = rdata.([]interface{})
			}

			label.Records[dnsType] = make(Records, len(records[rType]))

			for i := 0; i < len(records[rType]); i++ {
				record := new(Record)

				var h dns.RR_Header
				h.Class = dns.ClassINET
				h.Rrtype = dnsType

				// We add the TTL as a last pass because we might not have
				// processed it yet when we process the record data.

				switch len(label.Label) {
				case 0:
					h.Name = Zone.Origin + "."
				default:
					h.Name = label.Label + "." + Zone.Origin + "."
				}

				switch dnsType {
				case dns.TypeA, dns.TypeAAAA, dns.TypePTR:

					str, weight := getWeight(records[rType][i].([]interface{}))
					ip := str
					record.Weight = weight

					switch dnsType {
					case dns.TypePTR:
						record.RR = &dns.PTR{Hdr: h, Ptr: ip}
						break
					case dns.TypeA:
						if x := net.ParseIP(ip); x != nil {
							record.RR = &dns.A{Hdr: h, A: x}
							break
						}
						panic(fmt.Errorf("Bad A record %s for %s", ip, dk))
					case dns.TypeAAAA:
						if x := net.ParseIP(ip); x != nil {
							record.RR = &dns.AAAA{Hdr: h, AAAA: x}
							break
						}
						panic(fmt.Errorf("Bad AAAA record %s for %s", ip, dk))
					}

				case dns.TypeMX:
					rec := records[rType][i].(map[string]interface{})
					pref := uint16(0)
					mx := rec["mx"].(string)
					if !strings.HasSuffix(mx, ".") {
						mx = mx + "."
					}
					if rec["weight"] != nil {
						record.Weight = util.ValueToInt(rec["weight"])
					}
					if rec["preference"] != nil {
						pref = uint16(util.ValueToInt(rec["preference"]))
					}
					record.RR = &dns.MX{
						Hdr:        h,
						Mx:         mx,
						Preference: pref}

				case dns.TypeSRV:
					rec := records[rType][i].(map[string]interface{})
					priority := uint16(0)
					srvWeight := uint16(0)
					port := uint16(0)
					target := rec["target"].(string)

					if !dns.IsFqdn(target) {
						target = target + "." + Zone.Origin
					}

					if rec["srv_weight"] != nil {
						srvWeight = uint16(util.ValueToInt(rec["srv_weight"]))
					}
					if rec["port"] != nil {
						port = uint16(util.ValueToInt(rec["port"]))
					}
					if rec["priority"] != nil {
						priority = uint16(util.ValueToInt(rec["priority"]))
					}
					record.RR = &dns.SRV{
						Hdr:      h,
						Priority: priority,
						Weight:   srvWeight,
						Port:     port,
						Target:   target}

				case dns.TypeCNAME:
					rec := records[rType][i]
					var target string
					var weight int
					switch rec.(type) {
					case string:
						target = rec.(string)
					case []interface{}:
						target, weight = getWeight(rec.([]interface{}))
					}
					if !dns.IsFqdn(target) {
						target = target + "." + Zone.Origin
					}
					record.Weight = weight
					record.RR = &dns.CNAME{Hdr: h, Target: dns.Fqdn(target)}

				case dns.TypeMF:
					rec := records[rType][i]
					// MF records (how we store aliases) are not FQDNs
					record.RR = &dns.MF{Hdr: h, Mf: rec.(string)}

				case dns.TypeNS:
					rec := records[rType][i]
					if h.Ttl < 86400 {
						h.Ttl = 86400
					}

					var ns string

					switch rec.(type) {
					case string:
						ns = rec.(string)
					case []string:
						recl := rec.([]string)
						ns = recl[0]
						if len(recl[1]) > 0 {
							log.Println("NS records with names syntax not supported")
						}
					default:
						log.Printf("Data: %T %#v\n", rec, rec)
						panic("Unrecognized NS format/syntax")
					}

					rr := &dns.NS{Hdr: h, Ns: dns.Fqdn(ns)}

					record.RR = rr

				case dns.TypeTXT:
					rec := records[rType][i]

					var txt string

					switch rec.(type) {
					case string:
						txt = rec.(string)
					case map[string]interface{}:

						recmap := rec.(map[string]interface{})

						if weight, ok := recmap["weight"]; ok {
							record.Weight = util.ValueToInt(weight)
						}
						if t, ok := recmap["txt"]; ok {
							txt = t.(string)
						}
					}
					if len(txt) > 0 {
						rr := &dns.TXT{Hdr: h, Txt: []string{txt}}
						record.RR = rr
					} else {
						log.Printf("Zero length txt record for '%s' in '%s'\n", label.Label, Zone.Origin)
						continue
					}
					// Initial SPF support added here, cribbed from the TypeTXT case definition - SPF records should be handled identically

				case dns.TypeSPF:
					rec := records[rType][i]

					var spf string

					switch rec.(type) {
					case string:
						spf = rec.(string)
					case map[string]interface{}:

						recmap := rec.(map[string]interface{})

						if weight, ok := recmap["weight"]; ok {
							record.Weight = util.ValueToInt(weight)
						}
						if t, ok := recmap["spf"]; ok {
							spf = t.(string)
						}
					}
					if len(spf) > 0 {
						rr := &dns.SPF{Hdr: h, Txt: []string{spf}}
						record.RR = rr
					} else {
						log.Printf("Zero length SPF record for '%s' in '%s'\n", label.Label, Zone.Origin)
						continue
					}

				default:
					log.Println("type:", rType)
					panic("Don't know how to handle this type")
				}

				if record.RR == nil {
					panic("record.RR is nil")
				}

				label.Weight[dnsType] += record.Weight
				label.Records[dnsType][i] = *record
			}
			if label.Weight[dnsType] > 0 {
				sort.Sort(RecordsByWeight{label.Records[dnsType]})
			}
		}
	}

	// loop over exisiting labels, create zone records for missing sub-domains
	// and set TTLs
	for k := range Zone.Labels {
		if strings.Contains(k, ".") {
			subLabels := strings.Split(k, ".")
			for i := 1; i < len(subLabels); i++ {
				subSubLabel := strings.Join(subLabels[i:], ".")
				if _, ok := Zone.Labels[subSubLabel]; !ok {
					Zone.AddLabel(subSubLabel)
				}
			}
		}
		if Zone.Labels[k].Ttl > 0 {
			for _, records := range Zone.Labels[k].Records {
				for _, r := range records {
					r.RR.Header().Ttl = uint32(Zone.Labels[k].Ttl)
				}
			}
		}
	}

	setupSOA(Zone)
}

func newZone(name string) *Zone {
	zone := new(Zone)
	zone.Labels = make(labels)
	zone.Origin = name
	zone.Platform = name
	zone.LabelCount = dns.CountLabel(zone.Origin)

	// defaults
	zone.Options.Ttl = 120
	zone.Options.MaxHosts = 2
	zone.Options.Contact = "hostmaster." + name

	return zone
}

func setupSOA(Zone *Zone) {
	label := Zone.Labels[""]

	primaryNs := "ns"

	if label == nil {
		log.Println(Zone.Origin, "doesn't have any 'root' records,",
			"you should probably add some NS records")
		label = Zone.AddLabel("")
	}

	if record, ok := label.Records[dns.TypeNS]; ok {
		primaryNs = record[0].RR.(*dns.NS).Ns
	}

	ttl := Zone.Options.Ttl * 10
	if ttl > 3600 {
		ttl = 3600
	}
	if ttl == 0 {
		ttl = 600
	}

	s := Zone.Origin + ". " + strconv.Itoa(ttl) + " IN SOA " +
		primaryNs + " " + Zone.Options.Contact + " " +
		strconv.Itoa(Zone.Options.Serial) +
		// refresh, retry, expire, minimum are all
		// meaningless with this implementation
		" 5400 5400 1209600 3600"

	rr, err := dns.NewRR(s)

	if err != nil {
		log.Println("SOA Error", err)
		panic("Could not setup SOA")
	}

	record := Record{RR: rr}

	label.Records[dns.TypeSOA] = make([]Record, 1)
	label.Records[dns.TypeSOA][0] = record
}

func SetupQLog(logger qlog.QLogger) {
	qLogger = logger
}

func getWeight(rec []interface{}) (string, int) {
	str := rec[0].(string)
	var weight int

	if len(rec) > 1 {
		switch rec[1].(type) {
		case string:
			var err error
			weight, err = strconv.Atoi(rec[1].(string))
			if err != nil {
				panic("Error converting weight to integer")
			}
		case float64:
			weight = int(rec[1].(float64))
		}
	}

	return str, weight
}

func (z *Zone) AddLabel(k string) *Label {
	k = strings.ToLower(k)
	z.Labels[k] = new(Label)
	label := z.Labels[k]
	label.Label = k
	label.Ttl = z.Options.Ttl
	label.MaxHosts = z.Options.MaxHosts

	label.Records = make(map[uint16]Records)
	label.Weight = make(map[uint16]int)

	return label
}

func (z *Zone) findLabels(s string, targets []string, qts qTypes) (*Label, uint16) {
	for _, target := range targets {
		var name string

		switch target {
		case "@":
			name = s
		default:
			if len(s) > 0 {
				name = s + "." + target
			} else {
				name = target
			}
		}

		if label, ok := z.Labels[name]; ok {
			var name string
			for _, qtype := range qts {
				switch qtype {
				case dns.TypeANY:
					// short-circuit mostly to avoid subtle bugs later
					// to be correct we should run through all the selectors and
					// pick types not already picked
					return z.Labels[s], qtype
				case dns.TypeMF:
					if label.Records[dns.TypeMF] != nil {
						name = label.firstRR(dns.TypeMF).(*dns.MF).Mf
						// TODO: need to avoid loops here somehow
						return z.findLabels(name, targets, qts)
					}
				default:
					// return the label if it has the right record
					if label.Records[qtype] != nil && len(label.Records[qtype]) > 0 {
						return label, qtype
					}
				}
			}
		}
	}

	return z.Labels[s], 0
}

func (z *Zone) SoaRR() dns.RR {
	return z.Labels[""].firstRR(dns.TypeSOA)
}
