package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	apiBaseURL = "https://api.enphaseenergy.com/api/v4"
)

type enphaseMetricsCollector struct {
	loadMetric    *prometheus.Desc
	prodMetric    *prometheus.Desc
	cumLoadMetric *prometheus.Desc
	cumProdMetric *prometheus.Desc
	token         string
	gatewayIP     string
	verbose       bool
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
	log.Fatalf("Missing required environment variable %s", key)
	panic("UNREACHABLE")
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
		log.Fatalf("Failed to parse VERBOSE from environment: %v", err)
	}

	token, err := getToken(user, password, envoySerial)
	if err != nil {
		log.Fatalf("Failed to get token: %v", err)
	}
	if verbose {
		log.Printf("Token: %s", token)
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
		token:     token,
		gatewayIP: gatewayIP,
		verbose:   verbose,
	}
}

func getToken(user, password, envoySerial string) (string, error) {
	// First request to login and get session_id
	var loginData bytes.Buffer
	writer := multipart.NewWriter(&loginData)
	writer.WriteField("user[email]", user)
	writer.WriteField("user[password]", password)
	writer.Close()

	loginResp, err := http.Post(
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
		log.Printf("Login response body: %s", string(bodyBytes))
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

	tokenResp, err := http.Post("https://entrez.enphaseenergy.com/tokens", "application/json", bytes.NewBuffer(tokenDataJSON))
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
}

func (c *enphaseMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	log.Println("Collecting metrics")
	err := c.fetchDataFromGateway(ch)
	if err != nil {
		log.Panicf("Failed to fetch data from API: %v", err)
	}
}

func (c *enphaseMetricsCollector) fetchResponseFromGateway(cmd string, verbose bool) ([]byte, error) {
	url := fmt.Sprintf("https://%s/%s", c.gatewayIP, cmd)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))

	// Create a custom HTTP client with TLS configuration to skip certificate verification
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if verbose {
		log.Printf("Response to cmd %s body: %s", cmd, string(bodyBytes))
	}

	return bodyBytes, nil
}

func (c *enphaseMetricsCollector) fetchDataFromGateway(ch chan<- prometheus.Metric) error {
	var cmd string

	cmd = "ivp/meters/reports/"
	bodyBytes, err := c.fetchResponseFromGateway(cmd, c.verbose)
	if err != nil {
		return fmt.Errorf("failed to fetch response for cmd %s: %v", cmd, err)
	}
	lastUpdate, consNow, consCum, prodNow, prodCum, err := c.parseReportData(bodyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse report data: %v", err)
	}
	log.Printf("Last update: %s", lastUpdate)

	loadMetric := prometheus.MustNewConstMetric(c.loadMetric, prometheus.GaugeValue, float64(consNow))
	loadMetric = prometheus.NewMetricWithTimestamp(lastUpdate, loadMetric)

	cumLoadMetric := prometheus.MustNewConstMetric(c.cumLoadMetric, prometheus.CounterValue, float64(consCum))
	cumLoadMetric = prometheus.NewMetricWithTimestamp(lastUpdate, cumLoadMetric)

	prodMetric := prometheus.MustNewConstMetric(c.prodMetric, prometheus.GaugeValue, float64(prodNow))
	prodMetric = prometheus.NewMetricWithTimestamp(lastUpdate, prodMetric)

	cumProdMetric := prometheus.MustNewConstMetric(c.cumProdMetric, prometheus.CounterValue, float64(prodCum))
	cumProdMetric = prometheus.NewMetricWithTimestamp(lastUpdate, cumProdMetric)

	ch <- loadMetric
	ch <- prodMetric
	ch <- cumLoadMetric
	ch <- cumProdMetric

	return nil
}

func (c *enphaseMetricsCollector) parseReportData(body []byte) (time.Time, float64, float64, float64, float64, error) {
	var reports []Report
	if err := json.Unmarshal(body, &reports); err != nil {
		return time.Time{}, 0, 0, 0, 0, fmt.Errorf("failed to unmarshal response: %v", err)
	}
	if c.verbose {
		log.Printf("reports: \n%v", reports)
	}

	var totalConsumptionCurrW, totalConsumptionWhDlvdCum float64
	var totalConsumptionCreatedAt time.Time
	var productionCurrW, productionWhDlvdCum float64
	var productionCreatedAt time.Time

	for _, report := range reports {
		switch report.ReportType {
		case "total-consumption":
			totalConsumptionCurrW = report.Cumulative.CurrW
			totalConsumptionWhDlvdCum = report.Cumulative.WhDlvdCum
			totalConsumptionCreatedAt = time.Unix(report.CreatedAt, 0)
		case "production":
			productionCurrW = report.Cumulative.CurrW
			productionWhDlvdCum = report.Cumulative.WhDlvdCum
			productionCreatedAt = time.Unix(report.CreatedAt, 0)
		}
	}

	if !productionCreatedAt.Equal(totalConsumptionCreatedAt) {
		return time.Time{}, 0, 0, 0, 0, fmt.Errorf("production and total consumption reports have different timestamps")
	}

	return productionCreatedAt, totalConsumptionCurrW, totalConsumptionWhDlvdCum, productionCurrW, productionWhDlvdCum, nil
}

func main() {
	enphaseCollector := NewEnphaseMetricsCollector(context.Background())
	pr := prometheus.NewRegistry()
	pr.MustRegister(enphaseCollector)

	http.Handle("/metrics", promhttp.HandlerFor(pr, promhttp.HandlerOpts{}))

	log.Println("Starting server on :9100")
	log.Fatal(http.ListenAndServe(":9100", nil))
}
