package main

import (
	"flag"
        "github.com/bsycorp/inkfish"
	"log"
	"net/http"
)

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	configDir := flag.String("config", ".", "path to configuration files")
	caCert := flag.String("cacert", "ca.pem", "path to CA cert file (will also look in config dir)")
	caKey := flag.String("cakey", "ca.key.pem", "path to CA key file (will also look in config dir)")
	addr := flag.String("addr", ":8080", "proxy listen address")

	flag.Parse()

	proxy := inkfish.NewInkfish()
	err := inkfish.SetCAFromFiles(*caCert, *caKey)
	if err != nil {
		log.Fatal("error loading CA config: ", err)
	}
	err = proxy.LoadConfigFromDirectory(*configDir)
	if err != nil {
		log.Fatal("config error: ", err)
	}
	proxy.Proxy.Verbose = *verbose
	log.Fatal(http.ListenAndServe(*addr, proxy.Proxy))
}
