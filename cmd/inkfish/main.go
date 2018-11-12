package main

import (
	"flag"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/bsycorp/inkfish"
	"log"
	"net/http"
	"time"
)

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	configDir := flag.String("config", ".", "path to configuration files")
	caCert := flag.String("cacert", "ca.pem", "path to CA cert file")
	caKey := flag.String("cakey", "ca.key.pem", "path to CA key file")
	metadataFrom := flag.String("metadata", "aws", "default metadata provider (aws,none)")
	addr := flag.String("addr", ":8080", "proxy listen address")

	flag.Parse()

	proxy := inkfish.NewInkfish()
	err := inkfish.SetGlobalCAFromFiles(*caCert, *caKey)
	if err != nil {
		log.Fatal("error loading CA config: ", err)
	}
	err = proxy.LoadConfigFromDirectory(*configDir)
	if err != nil {
		log.Fatal("config error: ", err)
	}
	metadataCache := inkfish.NewMetadataCache()
	if *metadataFrom == "aws" {
		sess, err := session.NewSession()
		if err != nil {
			// SDK failed to load creds, most likely
			log.Fatal("failed to create aws session for metadata update: ", err)
		}
		go func() {
			for {
				inkfish.UpdateMetadataFromAWS(sess, metadataCache)
				time.Sleep(time.Duration(10*time.Second))
			}
		}()
	}
	proxy.Proxy.Verbose = *verbose
	log.Fatal(http.ListenAndServe(*addr, proxy.Proxy))
}
