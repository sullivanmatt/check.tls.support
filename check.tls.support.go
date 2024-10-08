package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"expvar"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"github.com/sullivanmatt/check.tls.support/gzip"
	tls "github.com/sullivanmatt/check.tls.support/tls110"
)

const (
	resp500Format = `HTTP/1.%d 500 Internal Server Error
Content-Length: 26
Connection: close
Content-Type: text/plain; charset="utf-8"
Strict-Transport-Security: max-age=31536000; includeSubdomains; preload
Date: %s

500 Internal Server Error
`
	hstsHeaderValue = "max-age=31536000; includeSubdomains; preload"
	xForwardedProto = "X-Forwarded-Proto"
)

var (
	httpsAddr      = flag.String("httpsAddr", "localhost:443", "address to boot the HTTPS server on")
	httpAddr       = flag.String("httpAddr", "localhost:80", "address to boot the HTTP server on")
	rawVHost       = flag.String("vhost", "localhost:443", "public domain to use in redirects and templates")
	certPath       = flag.String("cert", "./config/development_cert.pem", "file path to the TLS certificate to serve with")
	keyPath        = flag.String("key", "./config/development_key.pem", "file path to the TLS key to serve with")
	acmeURL        = flag.String("acmeRedirect", "/s/", "URL to join with .well-known/acme paths and redirect to")
	allowListsFile = flag.String("allowListsFile", "", "file path to find the allowlists JSON file")
	allowLogName   = flag.String("allowLogName", "test_howsmyssl_allowance_checks", "the name to Google Cloud Logging log to send API allowance check data to")
	staticDir      = flag.String("staticDir", "./static", "file path to the directory of static files to serve")
	tmplDir        = flag.String("templateDir", "./templates", "file path to the directory of templates")
	adminAddr      = flag.String("adminAddr", "localhost:4567", "address to boot the admin server on")
	headless       = flag.Bool("headless", false, "Run without templates")
	hmacSecret     = flag.String("hmacSecret", "", "hmac secret (for signatures)")

	apiVars         = expvar.NewMap("api")
	staticVars      = expvar.NewMap("static")
	webVars         = expvar.NewMap("web")
	apiRequests     = new(expvar.Int)
	staticRequests  = new(expvar.Int)
	webRequests     = new(expvar.Int)
	apiStatuses     = newStatusStats(apiVars)
	staticStatuses  = newStatusStats(staticVars)
	webStatuses     = newStatusStats(webVars)
	commonRedirects = expvar.NewInt("common_redirects")

	nonAlphaNumeric = regexp.MustCompile("[^[:alnum:]]")

	index *template.Template

	// liveHijackCount is for counting hijacked connections so that we can do
	// clean shutdowns. It's global state because this app is small and we only
	// use it in this file.
	liveHijackCount = newUint64()
)

func main() {
	flag.Parse()
	t := time.Now()
	expvar.NewInt("start_time_epoch_secs").Set(t.Unix())
	expvar.NewString("start_time_timestamp").Set(t.Format(time.RFC3339))
	expvar.Publish("uptime_secs", expvar.Func(func() interface{} {
		return int64(time.Now().Sub(t) / time.Second)
	}))
	expvar.Publish("uptime_dur", expvar.Func(func() interface{} {
		return time.Now().Sub(t).String()
	}))

	apiVars.Set("requests", apiRequests)
	staticVars.Set("requests", staticRequests)
	webVars.Set("requests", webRequests)

	if len(*hmacSecret) == 0 {
		log.Fatalf("hmacSecret cannot be empty.")
	}

	tlsConf := makeTLSConfig(*certPath, *keyPath)

	tlsListener, err := tls.Listen("tcp", *httpsAddr, tlsConf)
	if err != nil {
		log.Fatalf("unable to listen for the HTTPS server on %s: %s", *httpsAddr, err)
	}
	plaintextListener, err := net.Listen("tcp", *httpAddr)
	if err != nil {
		log.Fatalf("unable to listen for the HTTP server on %s: %s", *httpAddr, err)
	}
	ns := expvar.NewMap("tls")
	l := newListener(tlsListener, ns)

	if *acmeURL != "" {
		if !strings.HasPrefix(*acmeURL, "/") &&
			!strings.HasPrefix(*acmeURL, "https://") &&
			!strings.HasPrefix(*acmeURL, "http://") {
			fmt.Fprintf(os.Stderr, "acmeRedirect must start with 'http://', 'https://', or '/' but does not: %#v\n", *acmeURL)
			os.Exit(1)
		}
	}

	am := &allowMaps{
		AllowTheseDomains: make(map[string]bool),
		AllowSubdomainsOn: make(map[string]bool),
		BlockedDomains:    make(map[string]bool),
	}
	ama := &allowMapsAtomic{}
	ama.Store(am)
	if *allowListsFile != "" {
		am, err := loadAllowMaps(*allowListsFile)
		if err != nil {
			log.Fatal(err)
		}
		ama.Store(am)
		alTick := time.NewTicker(20 * time.Second)
		go reloadAllowMapsForever(*allowListsFile, ama, alTick)
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("unable to get hostname of local machine: %s", err)
	}

	var gclog logClient
	gclog = nullLogClient{}
	oa := newOriginAllower(ama, hostname, gclog, expvar.NewMap("origins"))

	staticHandler := http.NotFoundHandler()
	webHandleFunc := http.NotFound
	if !*headless {
		index = loadIndex()
		staticHandler = makeStaticHandler(*staticDir, staticVars)
		webHandleFunc = handleWeb
	}

	m := tlsMux(
		*acmeURL,
		staticHandler,
		webHandleFunc,
		oa,
	)

	go func() {
		err := http.ListenAndServe(*adminAddr, nil)
		if err != nil {
			log.Fatalf("unable to open admin server: %s", err)
		}
	}()

	httpsSrv := &http.Server{
		Handler:      m,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	httpSrv := &http.Server{
		Handler:      plaintextMux(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	log.Printf("Booting HTTPS on %s and HTTP on %s", *httpsAddr, *httpAddr)
	go func() {
		err := httpsSrv.Serve(l)
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("https server error: %s", err)
		}
	}()
	go func() {
		err := httpSrv.Serve(plaintextListener)
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %s", err)
		}
	}()

	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		err := httpsSrv.Shutdown(ctx)
		if err != nil {
			log.Printf("error shutting down HTTPS: %s", err)
		}
	}()
	go func() {
		defer wg.Done()
		err := httpSrv.Shutdown(ctx)
		if err != nil {
			log.Printf("error shutting down HTTP: %s", err)
		}
	}()
	wg.Wait()
	for atomic.LoadUint64(liveHijackCount) != 0 && ctx.Err() == nil {
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	gclog.Flush()
}

func tlsMux(acmeRedirectURL string, staticHandler http.Handler, webHandleFunc http.HandlerFunc, oa *originAllower) http.Handler {
	acmeRedirectURL = strings.TrimRight(acmeRedirectURL, "/")
	m := http.NewServeMux()
	//m.Handle("/s/", staticHandler)
	//m.Handle("/a/check", &apiHandler{oa: oa})
	//m.HandleFunc("/", webHandleFunc)
	m.Handle("/", &apiHandler{oa: oa})
	m.HandleFunc("/healthcheck", healthcheck)
	return protoHandler{logHandler{m}, "https"}
}

func plaintextMux() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/healthcheck", healthcheck)
	m.Handle("/", commonRedirect())
	return protoHandler{logHandler{m}, "http"}
}

const htmlContentType = "text/html;charset=utf-8"

func renderHTML(r *http.Request, data *clientInfo) ([]byte, int, string, string, error) {
	b := new(bytes.Buffer)
	err := index.Execute(b, data)
	if err != nil {
		return nil, 0, "", "", err
	}
	return b.Bytes(), http.StatusOK, htmlContentType, "", nil
}

func disallowedRenderJSON(r *http.Request, data *clientInfo) ([]byte, int, string, string, error) {
	//callback := r.FormValue("callback")
	//sanitizedCallback := nonAlphaNumeric.ReplaceAll([]byte(callback), []byte(""))

	//if len(sanitizedCallback) != 0 {
	//	body := []byte(fmt.Sprintf("%s(%s);", sanitizedCallback, disallowedOriginBody))
	//	// Browsers won't run this code unless the status is OK.
	//	return body, http.StatusOK, "application/javascript", nil

	//}
	return disallowedOriginBody, http.StatusBadRequest, "application/json", "", nil
}

func allowedRenderJSON(r *http.Request, data *clientInfo) ([]byte, int, string, string, error) {
	//callback := r.FormValue("callback")
	//sanitizedCallback := nonAlphaNumeric.ReplaceAll([]byte(callback), []byte(""))

	marshalled, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return nil, 0, htmlContentType, "", err
	}
	//if len(sanitizedCallback) > 0 {
	//	return []byte(fmt.Sprintf("%s(%s);", sanitizedCallback, marshalled)), http.StatusOK, "application/javascript", nil
	//}

        // Compute and attach signature
        hash := hmac.New(sha256.New, []byte(*hmacSecret))
        hash.Write([]byte(marshalled))
        sha := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	return marshalled, http.StatusOK, "application/json", sha, nil
}

func handleWeb(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	webRequests.Add(1)
	hijackHandle(w, r, webStatuses, renderHTML)
}

var (
	// disallowedOriginBody's tls_version has a special format in order to
	// ensure that folks with weird JavaScript parsing conditions show their
	// users a failure. We've seen `tls_version.split(' ')[1] < 1.2` without any
	// other checks, so we have that 0 in there. The "Err" is intentionally 3
	// characters long to avoid anyone parsing it by character count. (We've not
	// seen that 3 char check, but I can imagine it.)
	disallowedOriginBody = []byte(`{"error": "See tls_version for the sign up link", "tls_version": "Err 0 The website calling tls.support's API has been making many calls and does not have a subscription. See https://tls.support/ for more information."}`)
)

type apiHandler struct {
	oa *originAllower
}

func (ah *apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	apiRequests.Add(1)

	detectedDomain, ok := ah.oa.Allow(r)
	ok = true

	renderJSON := allowedRenderJSON
	if ok {
		log.Printf("allowed domain: %#v; Origin: %#v; Referrer: %#v", detectedDomain, r.Header.Get("Origin"), r.Header.Get("Referer"))
	} else {
		renderJSON = disallowedRenderJSON
		log.Printf("disallowed domain: %#v; Origin: %#v; Referrer: %#v", detectedDomain, r.Header.Get("Origin"), r.Header.Get("Referer"))
	}

	hijackHandle(w, r, apiStatuses, renderJSON)
}

func hijackHandle(w http.ResponseWriter, r *http.Request, statuses *statusStats, render func(*http.Request, *clientInfo) ([]byte, int, string, string, error)) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("server not hijackable\n")
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}

	c, brw, err := hj.Hijack()
	if err != nil {
		log.Printf("server errored during hijack: %s\n", err)
		return
	}
	incrementHijack()
	defer decrementHijack()
	defer c.Close()
	tc, ok := c.(*conn)
	if !ok {
		log.Printf("Unable to convert net.Conn to *conn: %#v\n", c)
		hijacked500(brw, r.ProtoMinor, statuses)
		return
	}
	data := pullClientInfo(tc)

	bs, status, contentType, signature, err := render(r, data)
	if err != nil {
		log.Printf("Unable to execute render: %s\n", err)
		hijacked500(brw, r.ProtoMinor, statuses)
		return
	}
	contentLength := int64(len(bs))
	h := make(http.Header)
	defaultResponseHeaders(h, r, contentType, signature)
	resp := &http.Response{
		StatusCode:    status,
		ContentLength: contentLength,
		Header:        h,
		Body:          ioutil.NopCloser(bytes.NewBuffer(bs)),
		ProtoMajor:    1, // Assumes HTTP/1.x
		ProtoMinor:    r.ProtoMinor,
	}
	bs, err = httputil.DumpResponse(resp, true)
	if err != nil {
		log.Printf("unable to write response: %s\n", err)
		hijacked500(brw, r.ProtoMinor, statuses)
		return
	}
	statuses.status2xx.Add(1)
	brw.Write(bs)
	brw.Flush()
}

func defaultResponseHeaders(h http.Header, r *http.Request, contentType string, signature string) {
	h.Set("Date", time.Now().Format(http.TimeFormat))
	h.Set("Content-Type", contentType)
	h.Set("X-Response-Signature", signature)
	if r.ProtoMajor == 1 && r.ProtoMinor == 1 {
		h.Set("Connection", "close")
	}
	h.Set("Strict-Transport-Security", hstsHeaderValue)
	// Allow CORS requests from any domain, for easy API access
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Headers", "X-Response-Signature, Content-Type")
	h.Set("Access-Control-Expose-Headers", "X-Response-Signature, Content-Type")
	h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")

}
func hijacked500(brw *bufio.ReadWriter, protoMinor int, statuses *statusStats) {
	statuses.status5xx.Add(1)
	// Assumes HTTP/1.x
	s := fmt.Sprintf(resp500Format, protoMinor, time.Now().Format(http.TimeFormat))
	brw.WriteString(s)
	brw.Flush()
}

func healthcheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("ok"))
}

func commonRedirect() http.Handler {
	hf := func(w http.ResponseWriter, r *http.Request) {
		commonRedirects.Add(1)
		if r.Header.Get(xForwardedProto) == "https" {
			w.Header().Set("Strict-Transport-Security", hstsHeaderValue)
		}
		u := r.URL
		// Never set by the Go HTTP library.
		u.Scheme = "https"
		u.Host = "tls.support"
		http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
	}
	return http.HandlerFunc(hf)
}

func loadIndex() *template.Template {
	return template.Must(template.New("index.html").
		Funcs(template.FuncMap{"sentence": sentence, "ratingSpan": ratingSpan}).
		ParseFiles(*tmplDir + "/index.html"))
}

func makeTLSConfig(certPath, keyPath string) *tls.Config {
	kpr, err := newKeypairReloader(certPath, keyPath)
	if err != nil {
		log.Fatalf("unable to load TLS key cert pair %s: %s", certPath, err)
	}
	go reloadKeypairForever(kpr, time.NewTicker(1*time.Hour))
	tlsConf := &tls.Config{
		GetCertificate:           kpr.GetCertificate,
		NextProtos:               []string{"https"},
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionSSL30,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}
	tlsConf.BuildNameToCertificate()
	return tlsConf
}

func makeStaticHandler(dir string, vars *expvar.Map) http.HandlerFunc {
	stats := newStatusStats(vars)
	h := http.StripPrefix("/s/", http.FileServer(http.Dir(dir)))
	h = gzip.GZIPHandler(h, nil)
	return func(w http.ResponseWriter, r *http.Request) {
		staticRequests.Add(1)
		w = &statWriter{w: w, stats: stats}
		h.ServeHTTP(w, r)
	}
}

func ratingSpan(r rating) template.HTML {
	class := ""
	switch r {
	case good:
		class = "good"
	case improvable:
		class = "improvable"
	case bad:
		class = "bad"
	}
	return template.HTML(class)
}

func sentence(parts []string) string {
	if len(parts) == 1 {
		return parts[0] + "."
	}
	commaed := parts[:len(parts)-1]
	return strings.Join(commaed, ", ") + ", and " + parts[len(parts)-1] + "."
}

type logHandler struct {
	inner http.Handler
}

// Since we have a Hijack in our code, this simple writer will suffice for
// now.
func (h logHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = "0.0.0.0"
	}
	proto := r.Header.Get(xForwardedProto)
	if proto == "" {
		proto = "unknown"
	}
	referrer := r.Header.Get("Referer")
	if referrer == "" {
		referrer = "noreferrer"
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "noorigin"
	}
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		userAgent = "nouseragent"
	}
	fmt.Printf("request: %s %s %s %s %s %s\n", host, proto, r.URL, referrer, origin, userAgent)
	h.inner.ServeHTTP(w, r)
}

type protoHandler struct {
	inner http.Handler
	proto string
}

func (h protoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Set(xForwardedProto, h.proto)
	// TODO(sullivanmatt): gross hack in order to get ServeMux to match ports
	// See https://golang.org/issue/10463
	host, _, err := net.SplitHostPort(r.Host)
	if err == nil {
		r.Host = host
	}
	h.inner.ServeHTTP(w, r)
}

type acmeRedirect string

func (a acmeRedirect) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if string(a) == "" {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNotFound)
	}
	if p == "/.well-known/acme-challenge/" {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.RawQuery != "" {
		p += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, string(a)+p, http.StatusFound)
}

func newUint64() *uint64 {
	var i uint64
	return &i
}

func incrementHijack() {
	for {
		old := atomic.LoadUint64(liveHijackCount)
		new := old + 1
		if atomic.CompareAndSwapUint64(liveHijackCount, old, new) {
			break
		}
	}
}

func decrementHijack() {
	for {
		old := atomic.LoadUint64(liveHijackCount)
		new := old - 1
		if atomic.CompareAndSwapUint64(liveHijackCount, old, new) {
			break
		}
	}
}
