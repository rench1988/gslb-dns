package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/rench1988/gslb-dns/log"
	"github.com/rench1988/gslb-dns/qlog"
	"github.com/rench1988/gslb-dns/zone"
)

const (
	version = "1.0.0"
)

var timeStarted = time.Now()

var (
	serverID string
	serverIP string
)

var (
	flagconfigfile  = flag.String("configfile", "gslb-dns.json", "filename of config file (in 'config' directory)")
	flagcheckconfig = flag.Bool("checkconfig", false, "check configuration and exit")
	//flagidentifier   = flag.String("identifier", "", "identifier (hostname, pop name or similar)")
	flaginter        = flag.String("interface", "*", "set the listener address")
	flagport         = flag.String("port", "53", "default port number")
	flaghttp         = flag.String("http", ":8053", "http listen address (:8053)")
	flaglog          = flag.Bool("log", false, "be more verbose")
	flagcpus         = flag.Int("cpus", 1, "Set the maximum number of CPUs to use")
	flagLogFile      = flag.String("logfile", "", "log to file")
	flagPrivateDebug = flag.Bool("privatedebug", false, "Make debugging queries accepted only on loopback")

	flagShowVersion = flag.Bool("version", false, "Show dnsconfig version")

	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	memprofile = flag.String("memprofile", "", "write memory profile to this file")
)

func logToFile(fn string) {
	file, err := os.OpenFile(fn, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Error writing log file: %v", err)
	}

	log.SetOutput(file)
}

func getInterfaces() []string {

	var inter []string
	uniq := make(map[string]bool)

	for _, host := range strings.Split(*flaginter, ",") {
		ip, port, err := net.SplitHostPort(host)
		if err != nil {
			switch {
			case strings.Contains(err.Error(), "missing port in address"):
				// 127.0.0.1
				ip = host
			case strings.Contains(err.Error(), "too many colons in address") &&
				// [a:b::c]
				strings.LastIndex(host, "]") == len(host)-1:
				ip = host[1 : len(host)-1]
				port = ""
			case strings.Contains(err.Error(), "too many colons in address"):
				// a:b::c
				ip = host
				port = ""
			default:
				log.Fatalf("Could not parse %s: %s\n", host, err)
			}
		}
		if len(port) == 0 {
			port = *flagport
		}
		host = net.JoinHostPort(ip, port)
		if uniq[host] {
			continue
		}
		uniq[host] = true

		if len(serverID) == 0 {
			serverID = ip
		}
		if len(serverIP) == 0 {
			serverIP = ip
		}
		inter = append(inter, host)

	}

	return inter
}

func init() {
	log.SetPrefix("glsb-dns ")
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	flag.Parse()

	if *memprofile != "" {
		runtime.MemProfileRate = 1024
	}

	if *flagShowVersion {
		fmt.Printf("glsb-dns %s (%s)\n", version, runtime.Version())
		os.Exit(0)
	}

	if len(*flagLogFile) > 0 {
		logToFile(*flagLogFile)
	}

	if *flagcheckconfig {
		err := readConf(*flagconfigfile)
		if err != nil {
			log.Println("Errors reading config", err)
			os.Exit(2)
		}

		zones := make(zone.Zones)
		plats := make(zone.Plats)

		zones.SetupGslbZone()

		for k, p := range conf.Platforms {
			_, err = zones.AddZoneInfo(k, p.Domains)
			if err != nil {
				log.Println("Errors reading zones", err)
				os.Exit(2)
			}

			err = plats.AddPlatInfo(k, p.Nodes)
			if err != nil {
				log.Println("Errors reading nodes", err)
				os.Exit(2)
			}
		}

		return
	}

	if *flagcpus == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	} else {
		runtime.GOMAXPROCS(*flagcpus)
	}

	log.Printf("Starting glsb-dns %s (%s)\n", version, runtime.Version())

	if *cpuprofile != "" {
		prof, err := os.Create(*cpuprofile)
		if err != nil {
			panic(err.Error())
		}

		pprof.StartCPUProfile(prof)
		defer func() {
			log.Println("closing file")
			prof.Close()
		}()
		defer func() {
			log.Println("stopping profile")
			pprof.StopCPUProfile()
		}()
	}

	// load gslb-dns.json config
	err := readConf(*flagconfigfile)
	if err != nil {
		log.Fatalln("failed to load gslb-dns config", err)
	}

	// load (and re-load) zone data
	go confWatcher(*flagconfigfile)

	if qlc := conf.QLog; len(qlc.Path) > 0 {
		ql, err := qlog.NewFileLogger(qlc.Path, qlc.MaxSize, qlc.Keep)
		if err != nil {
			log.Fatalf("Could not start file query logger: %s", err)
		}
		zone.SetupQLog(ql)
	}

	if *flaginter == "*" {
		addrs, _ := net.InterfaceAddrs()
		ips := make([]string, 0)
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if !(ip.IsLoopback() || ip.IsGlobalUnicast()) {
				continue
			}
			ips = append(ips, ip.String())
		}
		*flaginter = strings.Join(ips, ",")
	}

	inter := getInterfaces()

	Zones := zone.NewZones()
	Plats := zone.NewPlats()

	Zones.SetupRootZone()
	Zones.SetupGslbZone()

	go platsReader(Plats)
	go zonesReader(Zones)

	for _, host := range inter {
		go zone.ListenAndServe(host)
	}

	terminate := make(chan os.Signal)
	signal.Notify(terminate, os.Interrupt)

	<-terminate
	log.Printf("gslb-dns: signal received, stopping")

	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.WriteHeapProfile(f)
		f.Close()
	}
}
