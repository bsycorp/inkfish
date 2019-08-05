package main

import (
	"flag"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/bsycorp/inkfish"
	"github.com/syntaqx/go-metrics-datadog"
	"log"
	"net/http"
	"path"
	"strings"
	"time"
)

func main() {
	// verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	configDir := flag.String("config", ".", "path to configuration files")
	caCert := flag.String("cacert", "", "path to CA cert file")
	caKey := flag.String("cakey", "", "path to CA key file")
	metadataFrom := flag.String("metadata", "aws", "default metadata provider (aws,none)")
	addr := flag.String("addr", ":8080", "proxy listen address")
	metrics := flag.String("metrics", "none", "metrics provider (none,datadog,prometheus)")
	clientReadTimeout := flag.Int("client-read-timeout", 0, "client read timeout")
	clientWriteTimeout := flag.Int("client-write-timeout", 0, "client write timeout")
	clientIdleTimeout := flag.Int("client-idle-timeout", 300, "client idle timeout")
	metadataUpdateEvery := flag.Int("metadata-update-every", 10, "metadata update interval")
	insecureTestMode := flag.Bool("insecure-test-mode", false, "test mode (does not block)")

	flag.Parse()

	proxy := inkfish.NewInkfish(inkfish.NewCertSigner(&inkfish.StubCA))

	// Load CA cert and key.
	if *caCert == "" {
		*caCert = path.Join(*configDir, "ca.pem")
	}
	if *caKey == "" {
		*caKey = path.Join(*configDir, "ca.key.pem")
	}
	err := proxy.SetCAFromFiles(*caCert, *caKey)
	if err != nil {
		log.Fatal("error loading CA config: ", err)
	}
	err = proxy.LoadConfigFromDirectory(*configDir)
	if err != nil {
		log.Fatal("config error: ", err)
	}
	// Testmode
	if *insecureTestMode {
		log.Println("WARNING: PROXY IS IN TEST MODE, REQUESTS WILL NOT BE BLOCKED")
		proxy.InsecureTestMode = true
	}

	// Metadata
	log.Println("metadata update interval: ", metadataUpdateEvery)
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
				time.Sleep(time.Duration(*metadataUpdateEvery) * time.Second)
			}
		}()
	}
	proxy.MetadataProvider = metadataCache

	// Metrics
	if *metrics == "none" {
		log.Println("metrics disabled")
	} else if strings.HasPrefix(*metrics, "datadog") {
		dogStatsdAddr := "127.0.0.1:8125"
		bits := strings.Split(*metrics, ",")
		if len(bits) > 1 {
			dogStatsdAddr = bits[1]
		}
		reporter, err := datadog.NewReporter(
			proxy.Metrics.Registry, // Metrics registry, or nil for default
			dogStatsdAddr,          // DogStatsD UDP address
			time.Second*10,         // Update interval
			datadog.UsePercentiles([]float64{0.25, 0.99}),
		)
		if err != nil {
			log.Fatal(err)
		}
		reporter.Client.Namespace = "inkfish."
		//reporter.Client.Tags = append(reporter.Client.Tags, "us-east-1a")
		go reporter.Flush()
		log.Println("metrics to datadogstatsd at: ", dogStatsdAddr)
	} else {
		log.Fatal("unknown metrics provider: ", *metrics)
	}
	proxy.Metrics.StartCapture()

	log.Println("clientReadTimeout: ", *clientReadTimeout)
	log.Println("clientWriteTimeout: ", *clientWriteTimeout)
	log.Println("clientIdleTimeout: ", *clientIdleTimeout)

	srv := &http.Server{
		Addr:         *addr,
		ReadTimeout:  time.Duration(*clientReadTimeout) * time.Second,
		WriteTimeout: time.Duration(*clientWriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(*clientIdleTimeout) * time.Second,
		Handler:      proxy,
	}
	log.Fatal(srv.ListenAndServe())
}
