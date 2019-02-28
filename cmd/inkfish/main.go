package main

import (
	"flag"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/bsycorp/inkfish"
	"github.com/syntaqx/go-metrics-datadog"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	// verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	configDir := flag.String("config", ".", "path to configuration files")
	caCert := flag.String("cacert", "ca.pem", "path to CA cert file")
	caKey := flag.String("cakey", "ca.key.pem", "path to CA key file")
	metadataFrom := flag.String("metadata", "aws", "default metadata provider (aws,none)")
	addr := flag.String("addr", ":8080", "proxy listen address")
	metrics := flag.String("metrics", "none", "metrics provider (none,datadog,prometheus)")

	flag.Parse()

	proxy := inkfish.NewInkfish(inkfish.NewCertSigner(&inkfish.StubCA))
	err := proxy.SetCAFromFiles(*caCert, *caKey)
	if err != nil {
		log.Fatal("error loading CA config: ", err)
	}
	err = proxy.LoadConfigFromDirectory(*configDir)
	if err != nil {
		log.Fatal("config error: ", err)
	}
	// Metadata
	metadataCache := inkfish.NewMetadataCache()
	if *metadataFrom == "aws" {
		log.Println("using AWS metadata provider")
		sess, err := session.NewSession()
		if err != nil {
			log.Fatal("failed to create aws session for metadata update: ", err)
		}
		// Do an inital metadata update before listening
		inkfish.UpdateMetadataFromAWS(sess, metadataCache)
		go func() {
			for {
				inkfish.UpdateMetadataFromAWS(sess, metadataCache)
				time.Sleep(time.Duration(10 * time.Second))
			}
		}()
	}
	proxy.MetadataProvider = metadataCache

	// Metrics
	if *metrics == "none" {
		log.Println("metrics disabled")
	} else if strings.HasPrefix(*metrics, "datadog") {
		reporter, err := datadog.NewReporter(
			nil,                 // Metrics registry, or nil for default
			"127.0.0.1:8125", // DogStatsD UDP address
			time.Second * 10,       // Update interval
			datadog.UsePercentiles([]float64{0.25, 0.99}),
		)
		if err != nil {
			log.Fatal(err)
		}
		reporter.Client.Namespace = "inkfish."
		//reporter.Client.Tags = append(reporter.Client.Tags, "us-east-1a")
		go reporter.Flush()
	} else {
		log.Fatal("unknown metrics provider: ", *metrics)
	}

	log.Fatal(http.ListenAndServe(*addr, proxy))
}
