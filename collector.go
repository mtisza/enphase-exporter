package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"time"

	"k8s.io/klog/v2"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	apiBaseURL = "https://api.enphaseenergy.com/api/v4"
)

var buildTime string // will be set at build with -ldflags

// gatewayScrapeTimeout is a generous backstop, not a tuned value yet — see
// enphase_gateway_request_duration_seconds for the real call-time
// distribution to size this against. It's well above Prometheus's own
// scrape_timeout (10s, the cluster default), so a call that runs past that
// but under this still completes successfully here, while that one
// Prometheus scrape times out and shows as failed. A call that blows past
// this timeout fails the scrape and sets enphase_up to 0; it no longer takes
// the process down with it.
const gatewayScrapeTimeout = 60 * time.Second

// errGatewayUnauthorized marks the one failure that a retry can actually fix:
// the Envoy rejecting our bearer token. Tokens are minted at startup and are
// good for months, so this is rare — but it is also the one error that never
// clears on its own, which is why it gets a sentinel and a re-auth path
// instead of being lumped in with transient network failures.
var errGatewayUnauthorized = errors.New("gateway rejected token")

type enphaseMetricsCollector struct {
	loadMetric     *prometheus.Desc
	prodMetric     *prometheus.Desc
	cumLoadMetric  *prometheus.Desc
	cumProdMetric  *prometheus.Desc
	gatewayReqTime *prometheus.Desc
	upMetric       *prometheus.Desc
	token          string
	gatewayIP      string
	verbose        bool
	httpClient     *http.Client

	// Kept so the token can be re-minted in-process when the gateway starts
	// rejecting it. Before this existed the only way to get a fresh token was
	// to crash and let Kubernetes restart the pod.
	user        string
	password    string
	envoySerial string

	// Indirection over getToken purely so the re-auth path can be exercised
	// in tests without calling Enphase's cloud. Always getToken in production.
	mintToken func(user, password, envoySerial string) (string, error)
}

type Cumulative struct {
	CurrW     float64 `json:"currW"`
	WhDlvdCum float64 `json:"whDlvdCum"`
}

type Report struct {
	ReportType string     `json:"reportType"`
	CreatedAt  int64      `json:"createdAt"`
	Cumulative Cumulative `json:"cumulative"`
}

func GetEnvMust(key string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	klog.Fatalf("Missing required environment variable %s", key)
	return "" // UNREACHABLE
}

func GetEnvDefault(key string, dflt string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return dflt
}

func NewEnphaseMetricsCollector(ctx context.Context) *enphaseMetricsCollector {
	envoySerial := GetEnvMust("ENPHASE_SERIAL")
	user := GetEnvMust("ENPHASE_HO_USERNAME")
	password := GetEnvMust("ENPHASE_HO_PASSWORD")
	gatewayIP := GetEnvMust("ENPHASE_GATEWAY_IP")
	verbose, err := strconv.ParseBool(GetEnvDefault("VERBOSE", "false"))
	if err != nil {
		klog.Fatalf("Failed to parse VERBOSE from environment: %v", err)
	}

	token, err := getToken(user, password, envoySerial)
	if err != nil {
		klog.Fatalf("Failed to get token: %v", err)
	}
	if verbose {
		klog.Infof("Token acquired (%d bytes, redacted)", len(token))
	}

	return &enphaseMetricsCollector{
		loadMetric: prometheus.NewDesc("enphase_load",
			"load",
			nil, nil,
		),
		prodMetric: prometheus.NewDesc("enphase_production",
			"solar production",
			nil, nil,
		),
		cumLoadMetric: prometheus.NewDesc("enphase_cumulative_load",
			"cumulative load",
			nil, nil,
		),
		cumProdMetric: prometheus.NewDesc("enphase_cumulative_production",
			"cumulative solar production",
			nil, nil,
		),
		gatewayReqTime: prometheus.NewDesc("enphase_gateway_request_duration_seconds",
			"duration of the HTTP request to the local Envoy gateway",
			nil, nil,
		),
		upMetric: prometheus.NewDesc("enphase_up",
			"1 if the last scrape of the Envoy gateway succeeded, 0 otherwise",
			nil, nil,
		),
		token:       token,
		gatewayIP:   gatewayIP,
		verbose:     verbose,
		user:        user,
		password:    password,
		envoySerial: envoySerial,
		mintToken:   getToken,
		httpClient: &http.Client{
			Timeout: gatewayScrapeTimeout,
			Transport: &http.Transport{
				// The gateway is on the local network and presents a
				// self-signed cert; there's no CA to verify it against.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func getToken(user, password, envoySerial string) (string, error) {
	// Startup-only calls, not scrape-gated, but still shouldn't hang forever
	// if Enphase's cloud is unreachable.
	client := &http.Client{Timeout: 15 * time.Second}

	// First request to login and get session_id
	var loginData bytes.Buffer
	writer := multipart.NewWriter(&loginData)
	writer.WriteField("user[email]", user)
	writer.WriteField("user[password]", password)
	writer.Close()

	loginResp, err := client.Post(
		"https://enlighten.enphaseenergy.com/login/login.json?",
		writer.FormDataContentType(),
		&loginData,
	)
	if err != nil {
		return "", fmt.Errorf("failed to login: %v", err)
	}
	defer loginResp.Body.Close()

	bodyBytes, err := io.ReadAll(loginResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read login response body: %v", err)
	}

	var loginRespData map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &loginRespData); err != nil {
		klog.Infof("Login response body: %s", string(bodyBytes))
		return "", fmt.Errorf("failed to decode login response: %v", err)
	}

	sessionID, ok := loginRespData["session_id"].(string)
	if !ok {
		return "", fmt.Errorf("session_id not found in login response")
	}

	// Second use session_id to request a token
	tokenData := map[string]string{
		"session_id": sessionID,
		"serial_num": envoySerial,
		"username":   user,
	}
	tokenDataJSON, err := json.Marshal(tokenData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token data: %v", err)
	}

	tokenResp, err := client.Post("https://entrez.enphaseenergy.com/tokens", "application/json", bytes.NewBuffer(tokenDataJSON))
	if err != nil {
		return "", fmt.Errorf("failed to get token: %v", err)
	}
	defer tokenResp.Body.Close()

	tokenRaw, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %v", err)
	}

	return string(tokenRaw), nil
}

func (c *enphaseMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.loadMetric
	ch <- c.prodMetric
	ch <- c.cumLoadMetric
	ch <- c.cumProdMetric
	ch <- c.gatewayReqTime
	ch <- c.upMetric
}

func (c *enphaseMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	klog.Infoln("Collecting metrics")

	// A failed scrape must not kill the process. The Envoy drops off the
	// network for hours at a time (multi-hour outages on 2026-08-27..29 and
	// again 2026-09-11), and exiting on the first failed fetch turned every
	// one of those into a CrashLoopBackOff — 33 restarts in 2.5h on 09-11,
	// paging at 03:54 local about a pod, when the real event was "the solar
	// gateway is unreachable".
	//
	// This used to be klog.Fatalf, and that was load-bearing: it was the only
	// way an expired token ever got replaced, since one is minted at startup
	// and never refreshed. Simply downgrading it to an error (as commit
	// 3b7cc40 did, reverted by 6131e57) trades a noisy crash loop for a
	// permanently silent exporter. The re-auth path in
	// fetchReportsWithTokenRefresh replaces that mechanism properly, and
	// enphase_up below is what makes a stuck exporter visible without it
	// having to die to get attention.
	err := c.fetchDataFromGateway(ch)
	if err != nil {
		klog.Errorf("Failed to fetch data from API: %v", err)
	}

	up := 0.0
	if err == nil {
		up = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.upMetric, prometheus.GaugeValue, up)
}

func (c *enphaseMetricsCollector) fetchResponseFromGateway(cmd string, verbose bool) ([]byte, error) {
	url := fmt.Sprintf("https://%s/%s", c.gatewayIP, cmd)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: status %d", errGatewayUnauthorized, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if verbose {
		klog.Infof("Response to cmd %s body: %s", cmd, string(bodyBytes))
	}

	return bodyBytes, nil
}

// fetchReportsWithTokenRefresh performs the gateway call, and if the gateway
// rejects our token, mints a new one and retries exactly once. This is what
// the old crash-and-restart behaviour was really accomplishing; doing it in
// process means a stale token costs one extra round trip instead of a pod
// restart, and means a genuinely unreachable gateway no longer gets the same
// treatment as an expired credential.
//
// The returned duration covers only the gateway call whose result is being
// returned, so a re-auth never inflates
// enphase_gateway_request_duration_seconds.
func (c *enphaseMetricsCollector) fetchReportsWithTokenRefresh(cmd string) ([]byte, time.Duration, error) {
	start := time.Now()
	bodyBytes, err := c.fetchResponseFromGateway(cmd, c.verbose)
	elapsed := time.Since(start)

	if err == nil || !errors.Is(err, errGatewayUnauthorized) {
		return bodyBytes, elapsed, err
	}

	klog.Warningf("Gateway rejected the token (%v), re-authenticating", err)
	token, tokenErr := c.mintToken(c.user, c.password, c.envoySerial)
	if tokenErr != nil {
		return nil, elapsed, fmt.Errorf("re-authentication failed after %v: %v", err, tokenErr)
	}
	c.token = token
	klog.Infof("Re-authenticated (%d bytes, redacted)", len(token))

	start = time.Now()
	bodyBytes, err = c.fetchResponseFromGateway(cmd, c.verbose)
	return bodyBytes, time.Since(start), err
}

func (c *enphaseMetricsCollector) fetchDataFromGateway(ch chan<- prometheus.Metric) error {
	cmd := "ivp/meters/reports/"
	bodyBytes, reqDuration, err := c.fetchReportsWithTokenRefresh(cmd)
	klog.Infof("Gateway request for cmd %s took %s", cmd, reqDuration)
	ch <- prometheus.MustNewConstMetric(c.gatewayReqTime, prometheus.GaugeValue, reqDuration.Seconds())
	if err != nil {
		return fmt.Errorf("failed to fetch response for cmd %s: %v", cmd, err)
	}
	consNow, consCum, consUpdatedAt, prodNow, prodCum, prodUpdatedAt, err := c.parseReportData(bodyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse report data: %v", err)
	}
	klog.Infof("Production last update: %s, consumption last update: %s", prodUpdatedAt, consUpdatedAt)

	ch <- prometheus.MustNewConstMetric(c.loadMetric, prometheus.GaugeValue, consNow)
	ch <- prometheus.MustNewConstMetric(c.cumLoadMetric, prometheus.CounterValue, consCum)
	ch <- prometheus.MustNewConstMetric(c.prodMetric, prometheus.GaugeValue, prodNow)
	ch <- prometheus.MustNewConstMetric(c.cumProdMetric, prometheus.CounterValue, prodCum)

	return nil
}

func (c *enphaseMetricsCollector) parseReportData(body []byte) (consNow, consCum float64, consUpdatedAt time.Time, prodNow, prodCum float64, prodUpdatedAt time.Time, err error) {
	var reports []Report
	if err := json.Unmarshal(body, &reports); err != nil {
		return 0, 0, time.Time{}, 0, 0, time.Time{}, fmt.Errorf("failed to unmarshal response: %v", err)
	}
	if c.verbose {
		klog.Infof("reports: \n%v", reports)
	}

	for _, report := range reports {
		switch report.ReportType {
		case "total-consumption":
			consNow = report.Cumulative.CurrW
			consCum = report.Cumulative.WhDlvdCum
			consUpdatedAt = time.Unix(report.CreatedAt, 0)
		case "production":
			prodNow = report.Cumulative.CurrW
			prodCum = report.Cumulative.WhDlvdCum
			prodUpdatedAt = time.Unix(report.CreatedAt, 0)
		}
	}

	return consNow, consCum, consUpdatedAt, prodNow, prodCum, prodUpdatedAt, nil
}

func main() {
	if buildTime == "" {
		buildTime = "unknown"
	}
	klog.Infof("Build time: %s\n", buildTime)

	enphaseCollector := NewEnphaseMetricsCollector(context.Background())
	pr := prometheus.NewRegistry()
	pr.MustRegister(enphaseCollector)

	http.Handle("/metrics", promhttp.HandlerFor(pr, promhttp.HandlerOpts{}))

	klog.Infoln("Starting server on :9100")
	klog.Fatal(http.ListenAndServe(":9100", nil))
}
