package goproxy

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
)

// The basic proxy type. Implements http.Handler.
type ProxyHttpServer struct {
	// session variable must be aligned in i386
	// see http://golang.org/src/pkg/sync/atomic/doc.go#L41
	sess int64
	// KeepDestinationHeaders indicates the proxy should retain any headers present in the http.Response before proxying
	KeepDestinationHeaders bool
	// setting Verbose to true will log information on each request sent to the proxy
	Verbose         bool
	Logger          Logger
	NonproxyHandler http.Handler
	reqHandlers     []ReqHandler
	respHandlers    []RespHandler
	httpsHandlers   []HttpsHandler
	Tr              *http.Transport
	// ConnectDial will be used to create TCP connections for CONNECT requests
	// if nil Tr.Dial will be used
	ConnectDial        func(network string, addr string) (net.Conn, error)
	ConnectDialWithReq func(req *http.Request, network string, addr string) (net.Conn, error)
	CertStore          CertStorage
	KeepHeader         bool
}

var hasPort = regexp.MustCompile(`:\d+$`)

func copyHeaders(dst, src http.Header, keepDestHeaders bool) {
	if !keepDestHeaders {
		for k := range dst {
			dst.Del(k)
		}
	}
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func isEof(r *bufio.Reader) bool {
	_, err := r.Peek(1)
	return err == io.EOF
}

func (proxy *ProxyHttpServer) filterRequest(r *http.Request, ctx *ProxyCtx) (req *http.Request, resp *http.Response) {
	req = r
	for _, h := range proxy.reqHandlers {
		req, resp = h.Handle(r, ctx)
		// non-nil resp means the handler decided to skip sending the request
		// and return canned response instead.
		if resp != nil {
			break
		}
	}
	return
}
func (proxy *ProxyHttpServer) filterResponse(respOrig *http.Response, ctx *ProxyCtx) (resp *http.Response) {
	resp = respOrig
	for _, h := range proxy.respHandlers {
		ctx.Resp = resp
		resp = h.Handle(resp, ctx)
	}
	return
}

func removeProxyHeaders(ctx *ProxyCtx, r *http.Request) {
	r.RequestURI = "" // Reset request URI for proxy handling
	ctx.Logf("removeProxyHeaders: request %v %v", r.Method, r.URL.String())
	// Prevent automatic compression negotiation
	// TODO: implement compression
	r.Header.Del("Accept-Encoding")
	// Address potential incorrect connection closure by backend server
	if strings.EqualFold(r.Header.Get("Connection"), "close") {
		r.Close = false
	}
	// Remove standard proxy-related headers
	headersToRemove := []string{
		"Proxy-Connection",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Forwarded-For",
		"Proxy-Remote-User",
		"Proxy-Server",
		"Proxy-User-Agent",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"Via",
		"Client-IP",
		"True-Client-IP",
		"CF-Connecting-IP",
		"Connection",
	}
	for _, header := range headersToRemove {
		r.Header.Del(header)
	}
}

type flushWriter struct {
	w io.Writer
}

func (fw flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok {
		// only flush if the Writer implements the Flusher interface.
		f.Flush()
	}

	return n, err
}

// Standard net/http function. Shouldn't be used directly, http.Serve will use it.
func (proxy *ProxyHttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// origR := r
	//r.Header["X-Forwarded-For"] = w.RemoteAddr()
	if r.Method == "CONNECT" {
		proxy.handleHttps(w, r)
	} else {
		ctx := &ProxyCtx{Req: r, Session: atomic.AddInt64(&proxy.sess, 1), Proxy: proxy}

		var err error
		ctx.Logf("Got request %v %v %v %v", r.URL.Path, r.Host, r.Method, r.URL.String())
		if !r.URL.IsAbs() {
			r.URL.Scheme = "https"
			r.URL.Host = r.Host
			if !r.URL.IsAbs() {
				proxy.NonproxyHandler.ServeHTTP(w, r)
				return
			}
		}
		r, resp := proxy.filterRequest(r, ctx)

		if r != nil && resp == nil {
			if isWebSocketRequest(r) {
				ctx.Logf("Request looks like websocket upgrade.")
				proxy.serveWebsocket(ctx, w, r)
			}

			if !proxy.KeepHeader {
				removeProxyHeaders(ctx, r)
			}
			resp, err = ctx.RoundTrip(r)
			if err != nil {
				ctx.Error = err
				resp = proxy.filterResponse(nil, ctx)

			}
			if resp != nil {
				ctx.Logf("Received response %v", resp.Status)
			}
		}

		var origBody io.ReadCloser

		if resp != nil {
			origBody = resp.Body
			defer origBody.Close()
		}

		resp = proxy.filterResponse(resp, ctx)

		if resp == nil {
			var errorString string
			if ctx.Error != nil {
				errorString = "error read response " + r.URL.Host + " : " + ctx.Error.Error()
				ctx.Logf(errorString)
				http.Error(w, ctx.Error.Error(), 500)
			} else {
				errorString = "error read response " + r.URL.Host
				ctx.Logf(errorString)
				http.Error(w, errorString, 500)
			}
			return
		}
		ctx.Logf("Copying response to client %v [%d]", resp.Status, resp.StatusCode)
		// http.ResponseWriter will take care of filling the correct response length
		// Setting it now, might impose wrong value, contradicting the actual new
		// body the user returned.
		// We keep the original body to remove the header only if things changed.
		// This will prevent problems with HEAD requests where there's no body, yet,
		// the Content-Length header should be set.
		if origBody != resp.Body {
			resp.Header.Del("Content-Length")
		}
		copyHeaders(w.Header(), resp.Header, proxy.KeepDestinationHeaders)
		w.WriteHeader(resp.StatusCode)
		var copyWriter io.Writer = w
		if w.Header().Get("content-type") == "text/event-stream" {
			// server-side events, flush the buffered data to the client.
			copyWriter = &flushWriter{w: w}
		}

		nr, err := io.Copy(copyWriter, resp.Body)
		if err := resp.Body.Close(); err != nil {
			ctx.Warnf("Can't close response body %v", err)
		}
		ctx.Logf("Copied %v bytes to client error=%v", nr, err)
	}
}

// handleHttpRequest handles non-HTTPS (HTTP and WebSocket) proxy requests.
func (p *ProxyHttpServer) handleHttpRequest(w http.ResponseWriter, r *http.Request) {
	ctx := &ProxyCtx{Req: r, Session: atomic.AddInt64(&p.sess, 1), Proxy: p}

	ctx.Logf("Received request %v %v %v %v", r.URL.Path, r.Host, r.Method, r.URL.String())

	if !enforceAbsoluteURL(r) {
		p.NonproxyHandler.ServeHTTP(w, r)
		return
	}

	r, resp := p.filterRequest(r, ctx)
	if r == nil && resp == nil {
		ctx.Logf("Request and response are nil, returning original request %s", r.URL.String())
		p.NonproxyHandler.ServeHTTP(w, r)
		return
	}

	if r != nil {
		p.handleClientRequest(ctx, w, r)
	}
}

// enforceAbsoluteURL ensures request URL is absolute, modifying the request if necessary.
func enforceAbsoluteURL(r *http.Request) bool {
	if !r.URL.IsAbs() {
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
	}
	return r.URL.IsAbs()
}

// handleClientRequest processes the request from the client and writes the response back.
func (p *ProxyHttpServer) handleClientRequest(ctx *ProxyCtx, w http.ResponseWriter, r *http.Request) {
	if isWebSocketRequest(r) {
		ctx.Logf("Request is a WebSocket upgrade.")
		p.serveWebsocket(ctx, w, r)
		return
	}

	if !p.KeepHeader {
		removeProxyHeaders(ctx, r)
	}

	resp, err := p.Tr.RoundTrip(r)
	if err != nil {
		ctx.Error = err
		resp = p.filterResponse(nil, ctx)
	}

	if resp != nil {
		ctx.Logf("Received response %v", resp.Status)
		writeResponseToClient(ctx, w, resp)
	}
}

// writeResponseToClient writes the filtered response back to the client.
func writeResponseToClient(ctx *ProxyCtx, w http.ResponseWriter, resp *http.Response) {
	defer resp.Body.Close()
	resp = ctx.Proxy.filterResponse(resp, ctx)
	if resp == nil {
		handleResponseError(ctx, w, resp)
		return
	}

	ctx.Logf("Copying response to client %v [%d]", resp.Status, resp.StatusCode)
	resp.Header.Del("Content-Length") // Ensure Content-Length is recalculated.
	copyHeaders(w.Header(), resp.Header, ctx.Proxy.KeepDestinationHeaders)

	w.WriteHeader(resp.StatusCode)
	copyResponseBody(w, resp.Body, ctx)
}

// handleResponseError handles error scenarios when reading response fails.
func handleResponseError(ctx *ProxyCtx, w http.ResponseWriter, resp *http.Response) {
	errorString := "error reading response " + ctx.Req.URL.Host
	if ctx.Error != nil {
		errorString += " : " + ctx.Error.Error()
		ctx.Logf(errorString)
		http.Error(w, ctx.Error.Error(), http.StatusInternalServerError)
		return
	}

	ctx.Logf(errorString)
	http.Error(w, errorString, http.StatusInternalServerError)
}

// copyResponseBody copies the response body to the client, supports server-sent events.
func copyResponseBody(w http.ResponseWriter, body io.Reader, ctx *ProxyCtx) {
	var copyWriter io.Writer = w
	if w.Header().Get("Content-Type") == "text/event-stream" {
		copyWriter = &flushWriter{w: w}
	}

	if _, err := io.Copy(copyWriter, body); err != nil {
		ctx.Warnf("Error while copying response body to client: %v", err)
	}
}

// NewProxyHttpServer creates and returns a proxy server, logging to stderr by default
func NewProxyHttpServer() *ProxyHttpServer {
	proxy := ProxyHttpServer{
		Logger:        log.New(os.Stderr, "", log.LstdFlags),
		reqHandlers:   []ReqHandler{},
		respHandlers:  []RespHandler{},
		httpsHandlers: []HttpsHandler{},
		NonproxyHandler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			http.Error(w, "This is a proxy server. Does not respond to non-proxy requests.", 500)
		}),
		Tr: &http.Transport{TLSClientConfig: tlsClientSkipVerify, Proxy: http.ProxyFromEnvironment},
	}
	// reqTransport := req.NewTransport()
	// reqTransport.
	// 	SetTLSClientConfig(defaultTLSConfig).
	// 	SetProxy(http.ProxyFromEnvironment)

	// // Adjust the proxy's transport to use reqTransport
	// proxy.Tr = reqTransport.WrapRoundTripFunc(func(rt http.RoundTripper) req.HttpRoundTripFunc {
	// 	return func(req *http.Request) (resp *http.Response, err error) {
	// 		resp, err = rt.RoundTrip(req)
	// 		return
	// 	}
	// })
	proxy.ConnectDial = dialerFromEnv(&proxy)
	return &proxy
}
