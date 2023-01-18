package main

import (
	_ "embed"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
)

//go:embed VERSION
var version string
var verbose bool
var AllowedIPNets []*net.IPNet

func env(envName, defaultValue string) string {
	value := os.Getenv(envName)
	if value == "" {
		value = defaultValue
	}
	return value
}

func main() {
	log.Printf("starting ip-auth-proxy %v", version)

	authorizedIPS := ""
	rawUpstreamURL := ""

	listenPort, err := strconv.Atoi(env("LISTEN_PORT", "8000"))
	if err != nil {
		log.Fatal(err)
	}

	flag.BoolVar(&verbose, "verbose",
		env("VERBOSE", "false") == "true", "be verbose")
	flag.StringVar(&authorizedIPS, "authorized-ips",
		env("AUTHORIZED_IPS", "127.0.0.1/32"), "ips authorized to access")
	flag.IntVar(&listenPort, "listen-port",
		listenPort, "port to listen on")
	flag.StringVar(&rawUpstreamURL, "upstream-url",
		env("UPSTREAM_URL", "http://127.0.0.1:8080"), "upstream url")
	flag.Parse()

	log.Printf("verbose is %v", verbose)

	// upstreamURL
	upstreamURL, err := url.Parse(rawUpstreamURL)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("upstream url is %v", upstreamURL)

	// AllowedIPNets
	for _, authorizedIP := range strings.Split(authorizedIPS, ",") {
		_, ipNet, err := net.ParseCIDR(authorizedIP)
		if err != nil {
			log.Fatal(err)
		}
		AllowedIPNets = append(AllowedIPNets, ipNet)
	}
	log.Printf("access allowed from %+v", AllowedIPNets)

	// proxy
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	proxySrv := http.NewServeMux()
	proxySrv.HandleFunc("/", proxyHandler(proxy))
	log.Printf("listen for requests on :%v", listenPort)
	err = http.ListenAndServe(":"+strconv.Itoa(listenPort), proxySrv)
	if err != nil {
		log.Fatalln(err)
	}
}

func proxyHandler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		remoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			log.Println(err)
			w.Header().Set("content-type", "text/html")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(
				"<h1>Internal Server Error</h1>\n" +
					err.Error() + "\n" +
					"<hr>ip-auth-proxy " + version + "\n",
			))
			return
		}

		ip := net.ParseIP(remoteIP)
		allowed := false
		for _, AllowedIPNet := range AllowedIPNets {
			if AllowedIPNet.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Printf("blocked access from %v", remoteIP)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(
				"<h1>Access Denied</h1>" +
					remoteIP + " is not authorized to acces this resource\n" +
					"<hr>ip-auth-proxy " + version + "\n",
			))
			return
		}

		if verbose {
			log.Printf("allowed access from %v to %v", remoteIP, req.URL)
		}
		// prevent sending 'X-Forwarded-For' header
		req.RemoteAddr = ""
		p.ServeHTTP(w, req)
	}
}
