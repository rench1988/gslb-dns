package zone

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rench1988/gslb-dns/log"
	"github.com/rench1988/gslb-dns/qlog"
)

func ListenAndServe(ip string) {
	prots := []string{"udp", "tcp"}

	for _, prot := range prots {
		go func(p string) {
			server := &dns.Server{Addr: ip, Net: p}

			log.Printf("Opening on %s %s", ip, p)
			if err := server.ListenAndServe(); err != nil {
				log.Fatalf("gslb-dns: failed to setup %s %s: %s", ip, p, err)
			}
			log.Fatalf("gslb-dns: ListenAndServe unexpectedly returned")
		}(prot)
	}
}

func serve(w dns.ResponseWriter, req *dns.Msg, z *Zone) {

	qname := req.Question[0].Name
	qtype := req.Question[0].Qtype

	var qle *qlog.Entry

	if qLogger != nil {
		qle = &qlog.Entry{
			Time:   time.Now().UnixNano(),
			Origin: z.Origin,
			Name:   qname,
			Qtype:  qtype,
		}
		defer qLogger.Write(qle)
	}

	log.Printf("[zone %s] incoming  %s %s (id %d) from %s\n", z.Origin, qname,
		dns.TypeToString[qtype], req.Id, w.RemoteAddr())

	log.Println("Got request", req)

	label := getQuestionName(z, req)

	// IP that's talking to us (not EDNS CLIENT SUBNET)
	var realIP net.IP

	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		realIP = make(net.IP, len(addr.IP))
		copy(realIP, addr.IP)
	} else if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		realIP = make(net.IP, len(addr.IP))
		copy(realIP, addr.IP)
	}
	if qle != nil {
		qle.RemoteAddr = realIP.String()
	}

	var ip net.IP // EDNS or real IP
	var edns *dns.EDNS0_SUBNET
	var opt_rr *dns.OPT

	for _, extra := range req.Extra {

		switch extra.(type) {
		case *dns.OPT:
			for _, o := range extra.(*dns.OPT).Option {
				opt_rr = extra.(*dns.OPT)
				switch e := o.(type) {
				case *dns.EDNS0_NSID:
					// do stuff with e.Nsid
				case *dns.EDNS0_SUBNET:
					log.Println("Got edns", e.Address, e.Family, e.SourceNetmask, e.SourceScope)
					if e.Address != nil {
						edns = e
						ip = e.Address

						if qle != nil {
							qle.HasECS = true
							qle.ClientAddr = fmt.Sprintf("%s/%d", ip, e.SourceNetmask)
						}
					}
				}
			}
		}
	}

	if len(ip) == 0 { // no edns subnet
		ip = realIP
		if qle != nil {
			qle.ClientAddr = fmt.Sprintf("%s/%d", ip, len(ip)*8)
		}
	}

	//下面这个要改成根据ip寻找对应区域的逻辑
	//targets, netmask := z.Options.Targeting.GetTargets(ip)
	targets := []string{"@"}

	/*
		if qle != nil {
			qle.Targets = targets
		}
	*/

	m := new(dns.Msg)

	if qle != nil {
		defer func() {
			qle.Rcode = m.Rcode
			qle.Answers = len(m.Answer)
		}()
	}

	m.SetReply(req)
	if e := m.IsEdns0(); e != nil {
		m.SetEdns0(4096, e.Do())
	}
	m.Authoritative = true

	// TODO: set scope to 0 if there are no alternate responses
	if edns != nil {
		if edns.Family != 0 {
			/*
				if netmask < 16 {
					netmask = 16
				}
				edns.SourceScope = uint8(netmask)
			*/
			m.Extra = append(m.Extra, opt_rr)
		}
	}

	labels, labelQtype := z.findLabels(label, targets, qTypes{dns.TypeMF, dns.TypeCNAME, qtype})
	if labelQtype == 0 {
		labelQtype = qtype
	}

	if labels == nil {
		/*这里加入平台负载均衡的逻辑*/

		firstLabel := (strings.Split(label, "."))[0]

		if qle != nil {
			qle.LabelName = firstLabel
		}

		// return NXDOMAIN
		m.SetRcode(req, dns.RcodeNameError)
		m.Authoritative = true

		m.Ns = []dns.RR{z.SoaRR()}

		w.WriteMsg(m)
		return
	}

	if servers := labels.Picker(labelQtype, labels.MaxHosts); servers != nil {
		var rrs []dns.RR
		for _, record := range servers {
			rr := dns.Copy(record.RR)
			rr.Header().Name = qname
			rrs = append(rrs, rr)
		}
		m.Answer = rrs
	}

	if len(m.Answer) == 0 {
		// Return a SOA so the NOERROR answer gets cached
		m.Ns = append(m.Ns, z.SoaRR())
	}

	log.Println(m)

	if qle != nil {
		qle.LabelName = labels.Label
		qle.Answers = len(m.Answer)
		qle.Rcode = m.Rcode
	}
	err := w.WriteMsg(m)
	if err != nil {
		// if Pack'ing fails the Write fails. Return SERVFAIL.
		log.Println("Error writing packet", m)
		dns.HandleFailed(w, req)
	}
	return
}

func getQuestionName(z *Zone, req *dns.Msg) string {
	lx := dns.SplitDomainName(req.Question[0].Name)
	ql := lx[0 : len(lx)-z.LabelCount]
	return strings.ToLower(strings.Join(ql, "."))
}
