package util

import (
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"strconv"

	"github.com/rench1988/gslb-dns/log"
)

func ValueToBool(v interface{}) (rv bool) {
	switch v.(type) {
	case bool:
		rv = v.(bool)
	case string:
		str := v.(string)
		switch str {
		case "true":
			rv = true
		case "1":
			rv = true
		}
	case float64:
		if v.(float64) > 0 {
			rv = true
		}
	default:
		log.Println("Can't convert", v, "to bool")
		panic("Can't convert value")
	}
	return rv

}

func ValueToString(v interface{}) (rv string) {
	switch v.(type) {
	case string:
		rv = v.(string)
	case float64:
		rv = strconv.FormatFloat(v.(float64), 'f', -1, 64)
	default:
		log.Println("Can't convert", v, "to string")
		panic("Can't convert value")
	}
	return rv
}

func ValueToInt(v interface{}) (rv int) {
	switch v.(type) {
	case string:
		i, err := strconv.Atoi(v.(string))
		if err != nil {
			panic("Error converting weight to integer")
		}
		rv = i
	case float64:
		rv = int(v.(float64))
	default:
		log.Println("Can't convert", v, "to integer")
		panic("Can't convert value")
	}
	return rv
}

func Sha256File(fn string) string {
	if data, err := ioutil.ReadFile(fn); err != nil {
		return ""
	} else {
		hasher := sha256.New()
		hasher.Write(data)
		return hex.EncodeToString(hasher.Sum(nil))
	}
}
