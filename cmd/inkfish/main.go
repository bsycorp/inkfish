package main

import (
	"context"
	"flag"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/bsycorp/inkfish"
	prometheusmetrics "github.com/deathowl/go-metrics-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/syntaqx/go-metrics-datadog"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
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
	drainTime := flag.Int64("drain-time", 30, "shutdown drain deadline (seconds)")
	connectPorts := flag.String("connect-ports", "443", "comma delimited list of valid CONNECT ports")

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

	go func() {
        for {
            log.Println("Reload proxy ACLs")
            proxy.ReloadAclsFromDirectory(*configDir)
            time.Sleep(60 * time.Second)
        }
    }()

	// Testmode
	if *insecureTestMode {
		log.Println("WARNING: PROXY IS IN TEST MODE, REQUESTS WILL NOT BE BLOCKED")
		proxy.InsecureTestMode = true
	}
	// Parse CONNECT ports
	portList := strings.Split(*connectPorts, ",")
	validConnectPorts := make([]int, 1)
	for _, p := range portList {
		val, err := strconv.Atoi(p)
		if err != nil {
			log.Fatal("invalid CONNECT port: ", p)
		}
		validConnectPorts = append(validConnectPorts, val)
	}
	proxy.ConnectPolicy = func(host string, port int) bool {
		for _, p := range validConnectPorts {
			if port == p {
				return true
			}
		}
		return false
	}

	// Metadata
	metadataCache := inkfish.NewMetadataCache()
	if *metadataFrom != "none" {
		log.Println("metadata update interval: ", *metadataUpdateEvery)
	}
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
	} else if strings.HasPrefix(*metrics, "prometheus") {
		prometheusClient := prometheusmetrics.NewPrometheusProvider(proxy.Metrics.Registry, "inkfish", "proxy", prometheus.DefaultRegisterer, 1*time.Second)
		go prometheusClient.UpdatePrometheusMetrics()
		proxy.PromHandler = promhttp.Handler()
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

	idleConnsClosed := make(chan struct{})

	go func() {
		sigint := make(chan os.Signal, 1)

		signal.Notify(sigint, os.Interrupt)
		signal.Notify(sigint, syscall.SIGTERM)

		<-sigint

		log.Println("caught shutdown signal, draining...")
		ctx, _ := context.WithTimeout(context.Background(), time.Second * time.Duration(*drainTime))
		if err := srv.Shutdown(ctx); err != nil {
			// Error from closing listeners, or context timeout:
			log.Printf("error: http Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	log.Println("listen address: ", *addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		// Error starting or closing listener:
		log.Printf("error: http ListenAndServe: %v", err)
	}

	<-idleConnsClosed
	log.Println("connections drained, shutdown complete")
}
