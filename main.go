package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

//go:embed VERSION
var version string
var verbose bool
var enableWekanMetricsHack bool
var AllowedIPNets []*net.IPNet

func env(envName, defaultValue string) string {
	value := os.Getenv(envName)
	if value == "" {
		value = defaultValue
	}
	return value
}

func main() {
	log.Printf("ip-auth-proxy %v", version)

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
	flag.BoolVar(&enableWekanMetricsHack, "enable-wekan-metrics-hack",
		env("ENABLE_WEKAN_METRICS_HACK", "false") == "true", "fix wekan metrics labels")
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
	proxy.ModifyResponse = rewriteResponse
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

var sanitize = regexp.MustCompile("[^a-zA-Z0-9!@#$%^&*()_+\\-=\\[\\]{};'\\:|,./<>?`~ ]+")
var matcher = regexp.MustCompile(`^(\w+{n=)(.+)(} [0-9.])$`)

func rewriteResponse(res *http.Response) error {

	if !enableWekanMetricsHack || res.Request.URL.Path != "/metrics" {
		return nil
	}

	scanner := bufio.NewScanner(res.Body)
	bb := bytes.Buffer{}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "{n=") {
			match := matcher.FindStringSubmatch(line)
			if len(match) == 0 {
				continue
			}
			bb.WriteString(fmt.Sprintf(`%s"%s"%s`, match[1],
				sanitize.ReplaceAllString(match[2], ""), match[3]))
		} else {
			bb.WriteString(line)
		}
		bb.WriteString("\n")
	}

	body := bb.Bytes()
	res.Body = ioutil.NopCloser(bytes.NewReader(body))
	res.ContentLength = int64(len(body))
	res.Header.Set("Content-Length", strconv.Itoa(len(body)))

	return nil
}
