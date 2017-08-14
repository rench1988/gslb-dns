package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rench1988/gslb-dns/log"
	"github.com/rench1988/gslb-dns/util"

	"github.com/rench1988/gslb-dns/zone"
	"gopkg.in/fsnotify.v1"
)

var lastReadConfig time.Time

var conf = new(gconf)

var confMutex sync.RWMutex

type readRecord struct {
	time time.Time
	hash string
}

var lastZoneRead = map[string]*readRecord{}
var lastPlatRead = map[string]*readRecord{}

type queryLog struct {
	Path    string `json:"path"`
	MaxSize int    `json:"maxsize"`
	Keep    int    `json:"keep"`
}

type platform struct {
	Domains string `json:"domainFile"`
	Nodes   string `json:"nodeFile"`
}

type gconf struct {
	QLog      queryLog             `json:"queryLog"`
	Platforms map[string]*platform `json:"platform"`
}

func readConf(fileName string) error {
	stat, err := os.Stat(fileName)
	if err != nil {
		log.Printf("Failed to find config file: %s\n", err)
		return err
	}

	if !stat.ModTime().After(lastReadConfig) {
		return err
	}

	lastReadConfig = time.Now()

	file, err := os.Open(fileName)
	if err != nil {
		log.Printf("Failed to open config file: %s\n", err)
		return err
	}

	log.Printf("Loading config: %s\n", fileName)

	cfg := new(gconf)

	decoder := json.NewDecoder(file)

	err = decoder.Decode(cfg)
	if err != nil {
		log.Printf("Failed to parse config data: %s\n", err)
		return err
	}

	confMutex.Lock()
	conf = cfg
	confMutex.Unlock()

	return nil
}

func getConf() *gconf {
	confMutex.Lock()
	defer confMutex.Unlock()

	return conf
}

func confWatcher(fileName string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Println(err)
		return
	}

	if err := watcher.Add(fileName); err != nil {
		log.Println(err)
		return
	}

	for {
		select {
		case ev := <-watcher.Events:
			if ev.Name == fileName {
				// Write = when the file is updated directly
				// Rename = when it's updated atomicly
				// Chmod = for `touch`
				if ev.Op&fsnotify.Write == fsnotify.Write ||
					ev.Op&fsnotify.Rename == fsnotify.Rename ||
					ev.Op&fsnotify.Chmod == fsnotify.Chmod {
					time.Sleep(200 * time.Millisecond)
					readConf(fileName)
				}
			}
		case err := <-watcher.Errors:
			log.Println("fsnotify error:", err)
		}
	}
}

func zonesReader(zs zone.Zones) {
	for {
		cf := getConf()
		zonesReadConf(cf, zs)
		time.Sleep(5 * time.Second)
	}
}

func zonesReadConf(cf *gconf, zs zone.Zones) {

	seenZones := map[string]bool{}

	for k, plat := range cf.Platforms {
		filename := plat.Domains

		file, err := os.Stat(filename)
		if err != nil {
			continue
		}

		if _, ok := lastZoneRead[k]; !ok || file.ModTime().After(lastZoneRead[k].time) {
			modTime := file.ModTime()

			if ok {
				log.Printf("Reloading %s\n", filename)
				lastZoneRead[k].time = modTime
			} else {
				log.Printf("Reading new file %s\n", filename)
				lastZoneRead[k] = &readRecord{time: modTime}
			}

			sha256 := util.Sha256File(filename)
			if lastZoneRead[k].hash == sha256 {
				continue
			}

			zone, err := zs.AddZoneInfo(k, filename)
			if err != nil {
				log.Printf("Error reading zone '%s': %s", k, err)
				continue
			}

			(lastZoneRead[k]).hash = sha256

			zs.AddDNSHandler(k, zone)
		}

		seenZones[k] = true
	}

	for zoneName, zone := range zs {
		if zoneName == "gslb-dns" {
			continue
		}
		if ok, _ := seenZones[zoneName]; ok {
			continue
		}
		log.Println("Removing zone", zone.Origin)
		delete(lastZoneRead, zoneName)
		dns.HandleRemove(zoneName)
		delete(zs, zoneName)
	}
}

func platsReader(ps zone.Plats) {
	for {
		cf := getConf()
		platsReadConf(cf, ps)
		time.Sleep(5 * time.Second)
	}
}

func platsReadConf(cf *gconf, ps zone.Plats) {
	seenPlats := map[string]bool{}

	changed := false

	for k, plat := range cf.Platforms {
		filename := plat.Nodes

		file, err := os.Stat(filename)
		if err != nil {
			continue
		}

		if _, ok := lastPlatRead[k]; !ok || file.ModTime().After(lastPlatRead[k].time) {
			modTime := file.ModTime()

			if ok {
				log.Printf("Reloading %s\n", filename)
				lastPlatRead[k].time = modTime
			} else {
				log.Printf("Reading new file %s\n", filename)
				lastPlatRead[k] = &readRecord{time: modTime}
			}

			sha256 := util.Sha256File(filename)
			if lastPlatRead[k].hash == sha256 {
				continue
			}

			err = ps.AddPlatInfo(k, filename)
			if err != nil {
				log.Printf("Error reading platform '%s': %s", k, err)
				continue
			}

			(lastPlatRead[k]).hash = sha256

			changed = true
		}

		seenPlats[k] = true
	}

	for platName, _ := range ps {
		if ok, _ := seenPlats[platName]; ok {
			continue
		}
		log.Println("Removing plat", platName)
		delete(lastPlatRead, platName)
		ps.DeletePlatInfo(platName)

		changed = true
	}

	ps.HealthCheck(changed)
}
