package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// -----------------------------------------------
//   EVASION CONFIG
// -----------------------------------------------

type EvasionConfig struct {
	Proxies     []string
	RotateUA    bool
	Delay       time.Duration
	Jitter      float64 // 0.0 to 1.0
	MaxRetries  int
	DOHEnabled  bool
	DOHServer   string
	ProxyIndex  uint64
	Verbose     bool
	InsecureTLS bool // skip TLS cert verification -- only needed behind intercepting proxies
}

func NewEvasionConfig() EvasionConfig {
	return EvasionConfig{
		MaxRetries: 3,
		DOHServer:  "https://cloudflare-dns.com/dns-query",
	}
}

// -----------------------------------------------
//   PROXY MANAGEMENT
// -----------------------------------------------

func LoadProxies(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read proxy file: %w", err)
	}

	var proxies []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Normalize proxy format
		if !strings.Contains(line, "://") {
			line = "http://" + line
		}
		if _, err := url.Parse(line); err == nil {
			proxies = append(proxies, line)
		}
	}
	return proxies, nil
}

func (ec *EvasionConfig) GetNextProxy() *url.URL {
	if len(ec.Proxies) == 0 {
		return nil
	}
	idx := atomic.AddUint64(&ec.ProxyIndex, 1) - 1
	idx %= uint64(len(ec.Proxies))
	proxyStr := ec.Proxies[idx]
	u, err := url.Parse(proxyStr)
	if err != nil {
		return nil
	}
	return u
}

// -----------------------------------------------
//   USER-AGENT ROTATION
// -----------------------------------------------

var userAgents = []string{
	// Chrome (Windows)
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	// Chrome (macOS)
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	// Chrome (Linux)
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	// Firefox (Windows)
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	// Firefox (macOS)
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
	// Firefox (Linux)
	"Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	// Safari
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	// Edge
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	// Cloud SDK / CLI patterns (blend in with legitimate cloud traffic)
	"aws-sdk-go/1.55.5 (go1.22.4; linux; amd64)",
	"google-cloud-sdk gcloud/484.0.0",
	"azsdk-python-storage-blob/12.20.0 Python/3.12.3 (Linux-6.5.0-x86_64)",
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// -----------------------------------------------
//   REQUEST DELAY & JITTER
// -----------------------------------------------

func applyDelay(baseDelay time.Duration, jitter float64) {
	if baseDelay <= 0 {
		return
	}
	delay := baseDelay
	if jitter > 0 {
		jitterRange := float64(baseDelay) * jitter
		delta := time.Duration(rand.Float64()*2*jitterRange - jitterRange)
		delay = baseDelay + delta
		if delay < 0 {
			delay = 0
		}
	}
	time.Sleep(delay)
}

// -----------------------------------------------
//   EXPONENTIAL BACKOFF
// -----------------------------------------------

func shouldRetryStatus(statusCode int) bool {
	switch statusCode {
	case 429, 503, 502, 504:
		return true
	default:
		return false
	}
}

func backoffDuration(attempt int) time.Duration {
	base := time.Duration(1<<uint(attempt)) * time.Second
	jitter := time.Duration(rand.Int63n(int64(time.Second)))
	total := base + jitter
	if total > 30*time.Second {
		total = 30 * time.Second
	}
	return total
}

// -----------------------------------------------
//   EVASION-AWARE HTTP CLIENT
// -----------------------------------------------

// evasionTransport wraps http.RoundTripper with UA rotation, delay, and retry
type evasionTransport struct {
	base    http.RoundTripper
	config  *EvasionConfig
	mu      sync.Mutex
	lastReq time.Time
}

func (t *evasionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Apply delay between requests. lastReq is reserved (advanced) under the
	// lock *before* sleeping, so concurrent callers each get a distinct,
	// staggered send slot instead of all reading the same stale timestamp
	// and bursting through together.
	if t.config.Delay > 0 {
		t.mu.Lock()
		now := time.Now()
		var remaining time.Duration
		if !t.lastReq.IsZero() {
			nextAllowed := t.lastReq.Add(t.config.Delay)
			if nextAllowed.After(now) {
				remaining = nextAllowed.Sub(now)
			}
		}
		t.lastReq = now.Add(remaining)
		t.mu.Unlock()
		if remaining > 0 {
			applyDelay(remaining, t.config.Jitter)
		}
	}

	// Rotate User-Agent
	if t.config.RotateUA {
		req.Header.Set("User-Agent", getRandomUserAgent())
	}

	// Add common headers to blend in
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "*/*")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}

	// Execute with retry logic
	var resp *http.Response
	var err error
	maxAttempts := t.config.MaxRetries
	if maxAttempts <= 0 {
		maxAttempts = 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		resp, err = t.base.RoundTrip(req)
		if err != nil {
			if attempt < maxAttempts-1 {
				wait := backoffDuration(attempt)
				if t.config.Verbose {
					logWarn("Request failed (attempt %d/%d), retrying in %s: %v",
						attempt+1, maxAttempts, wait, err)
				}
				time.Sleep(wait)
				continue
			}
			break
		}

		if shouldRetryStatus(resp.StatusCode) && attempt < maxAttempts-1 {
			wait := backoffDuration(attempt)
			if t.config.Verbose {
				logWarn("Rate limited (HTTP %d, attempt %d/%d), backing off %s",
					resp.StatusCode, attempt+1, maxAttempts, wait)
			}
			resp.Body.Close()
			time.Sleep(wait)
			continue
		}
		break
	}

	return resp, err
}

func buildEvasionClient(ec EvasionConfig, resolvers []string) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxConnsPerHost:     20,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// Only skip TLS verification when explicitly requested (e.g. behind an
	// intercepting proxy with a self-signed cert). Verifying certs by default
	// avoids silently trusting a MITM'd connection during a scan.
	if ec.InsecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Proxy rotation
	if len(ec.Proxies) > 0 {
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			return ec.GetNextProxy(), nil
		}
		logInfo("Proxy rotation enabled: %s%d%s proxies loaded", Cyan, len(ec.Proxies), Reset)
	}

	// Custom DNS resolvers
	if len(resolvers) > 0 {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				server := resolvers[rand.Intn(len(resolvers))]
				if !strings.Contains(server, ":") {
					server = server + ":53"
				}
				return d.DialContext(ctx, "udp", server)
			},
		}
		transport.DialContext = (&net.Dialer{
			Timeout:  7 * time.Second,
			Resolver: resolver,
		}).DialContext
	}

	// Wrap transport with evasion layer
	evasion := &evasionTransport{
		base:   transport,
		config: &ec,
	}

	client := &http.Client{
		Transport: evasion,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return client
}

// -----------------------------------------------
//   SHARED EVASION CLIENT (used by deep-scan files)
// -----------------------------------------------

// sharedHTTPClient is initialized once in main() via InitSharedClient so that
// azure.go/alibaba.go deep-scan requests honor -proxy/-ua-rotate/-delay
// instead of each building their own bare http.Client.
var sharedHTTPClient *http.Client

func InitSharedClient(ec EvasionConfig, resolvers []string) {
	sharedHTTPClient = buildEvasionClient(ec, resolvers)
}

// getHTTPClient returns the shared evasion-aware client, falling back to a
// plain client if InitSharedClient was never called (e.g. in tests).
func getHTTPClient() *http.Client {
	if sharedHTTPClient == nil {
		return buildEvasionClient(NewEvasionConfig(), nil)
	}
	return sharedHTTPClient
}

// -----------------------------------------------
//   PROXY ENV SETUP FOR CLI TOOLS
// -----------------------------------------------

// SetProxyEnvForCLI sets HTTP_PROXY/HTTPS_PROXY env vars so CLI tools
// (aws, az, gsutil, aliyun, curl) also route through the proxy pool.
func SetProxyEnvForCLI(ec *EvasionConfig) {
	if len(ec.Proxies) == 0 {
		return
	}
	proxy := ec.GetNextProxy()
	if proxy == nil {
		return
	}
	proxyStr := proxy.String()
	os.Setenv("HTTP_PROXY", proxyStr)
	os.Setenv("HTTPS_PROXY", proxyStr)
	os.Setenv("ALL_PROXY", proxyStr)
}

// RotateCLIProxy picks a new proxy from the pool and updates env vars.
// Call this between CLI tool invocations to rotate.
func RotateCLIProxy(ec *EvasionConfig) {
	if len(ec.Proxies) == 0 {
		return
	}
	SetProxyEnvForCLI(ec)
}

// -----------------------------------------------
//   EVASION SUMMARY LOG
// -----------------------------------------------

func logEvasionConfig(ec EvasionConfig) {
	if Silent {
		return
	}
	logSection("Evasion Configuration")

	features := []string{}
	if len(ec.Proxies) > 0 {
		features = append(features, fmt.Sprintf("Proxy Rotation (%d proxies)", len(ec.Proxies)))
	}
	if ec.RotateUA {
		features = append(features, fmt.Sprintf("User-Agent Rotation (%d UAs)", len(userAgents)))
	}
	if ec.Delay > 0 {
		features = append(features, fmt.Sprintf("Request Delay (%s, jitter %.0f%%)", ec.Delay, ec.Jitter*100))
	}
	if ec.MaxRetries > 1 {
		features = append(features, fmt.Sprintf("Auto-Retry (max %d, exponential backoff)", ec.MaxRetries))
	}

	if len(features) == 0 {
		logInfo("No evasion features enabled (use -proxy, -delay, -ua-rotate)")
		return
	}

	for _, f := range features {
		logSuccess("  %s", f)
	}
}
