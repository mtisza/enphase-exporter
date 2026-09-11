package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// These tests pin the behaviour that commit 3b7cc40 introduced and 6131e57
// reverted: a scrape failure must not take the process down, but an expired
// token must still get replaced. Getting only the first half right is what
// made the revert necessary, so both are asserted here together.

func newTestCollector(t *testing.T, gatewayURL string) *enphaseMetricsCollector {
	t.Helper()

	c := &enphaseMetricsCollector{
		loadMetric:     prometheus.NewDesc("enphase_load", "load", nil, nil),
		prodMetric:     prometheus.NewDesc("enphase_production", "solar production", nil, nil),
		cumLoadMetric:  prometheus.NewDesc("enphase_cumulative_load", "cumulative load", nil, nil),
		cumProdMetric:  prometheus.NewDesc("enphase_cumulative_production", "cumulative solar production", nil, nil),
		gatewayReqTime: prometheus.NewDesc("enphase_gateway_request_duration_seconds", "duration", nil, nil),
		upMetric:       prometheus.NewDesc("enphase_up", "up", nil, nil),
		token:          "initial-token",
		gatewayIP:      strings.TrimPrefix(gatewayURL, "https://"),
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		mintToken: func(_, _, _ string) (string, error) {
			t.Fatal("mintToken called unexpectedly")
			return "", nil
		},
	}

	return c
}

// gather runs one full Collect cycle through a real registry, which is also
// what catches duplicate or missing metric emissions.
func gather(t *testing.T, c *enphaseMetricsCollector) map[string]float64 {
	t.Helper()

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() returned an error: %v", err)
	}

	out := map[string]float64{}
	for _, fam := range families {
		for _, m := range fam.GetMetric() {
			if g := m.GetGauge(); g != nil {
				out[fam.GetName()] = g.GetValue()
			}
			if ctr := m.GetCounter(); ctr != nil {
				out[fam.GetName()] = ctr.GetValue()
			}
		}
	}

	return out
}

func reportsHandler(prodW, consW float64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]Report{
			{ReportType: "production", CreatedAt: 1757000000, Cumulative: Cumulative{CurrW: prodW, WhDlvdCum: 1000}},
			{ReportType: "total-consumption", CreatedAt: 1757000000, Cumulative: Cumulative{CurrW: consW, WhDlvdCum: 2000}},
		})
	}
}

func TestCollectSucceeds(t *testing.T) {
	srv := httptest.NewTLSServer(reportsHandler(1234, 567))
	defer srv.Close()

	got := gather(t, newTestCollector(t, srv.URL))

	if got["enphase_up"] != 1 {
		t.Errorf("enphase_up = %v, want 1", got["enphase_up"])
	}
	if got["enphase_production"] != 1234 {
		t.Errorf("enphase_production = %v, want 1234", got["enphase_production"])
	}
	if got["enphase_load"] != 567 {
		t.Errorf("enphase_load = %v, want 567", got["enphase_load"])
	}
}

// The regression that caused the 3:54am page: the Envoy is simply not there.
// Before this change Collect called klog.Fatalf here and the process exited.
func TestCollectSurvivesUnreachableGateway(t *testing.T) {
	srv := httptest.NewTLSServer(reportsHandler(1, 1))
	url := srv.URL
	srv.Close() // nothing is listening now

	got := gather(t, newTestCollector(t, url))

	if got["enphase_up"] != 0 {
		t.Errorf("enphase_up = %v, want 0", got["enphase_up"])
	}
	if _, ok := got["enphase_production"]; ok {
		t.Error("enphase_production should not be reported when the scrape failed")
	}
}

func TestCollectSurvivesGatewayError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	if got := gather(t, newTestCollector(t, srv.URL)); got["enphase_up"] != 0 {
		t.Errorf("enphase_up = %v, want 0", got["enphase_up"])
	}
}

// The half that the revert was protecting: a rejected token must be replaced
// in-process. If this regresses, the exporter goes quiet forever instead of
// crashing, which is strictly worse than the bug being fixed here.
func TestExpiredTokenIsRefreshedAndRetried(t *testing.T) {
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		seen = append(seen, auth)
		if auth != "Bearer fresh-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		reportsHandler(42, 7)(w, r)
	}))
	defer srv.Close()

	c := newTestCollector(t, srv.URL)
	minted := 0
	c.mintToken = func(_, _, _ string) (string, error) {
		minted++
		return "fresh-token", nil
	}

	got := gather(t, c)

	if minted != 1 {
		t.Errorf("mintToken called %d times, want exactly 1", minted)
	}
	if got["enphase_up"] != 1 {
		t.Errorf("enphase_up = %v, want 1 after a successful re-auth", got["enphase_up"])
	}
	if got["enphase_production"] != 42 {
		t.Errorf("enphase_production = %v, want 42", got["enphase_production"])
	}
	if c.token != "fresh-token" {
		t.Errorf("token = %q, want the refreshed one to be retained for next scrape", c.token)
	}
	if len(seen) != 2 {
		t.Errorf("gateway saw %d requests, want 2 (initial 401 then retry)", len(seen))
	}
}

// A 401 whose re-auth also fails must still not crash — it just reports down.
func TestFailedReauthReportsDown(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newTestCollector(t, srv.URL)
	c.mintToken = func(_, _, _ string) (string, error) {
		return "", errors.New("enlighten unreachable")
	}

	if got := gather(t, c); got["enphase_up"] != 0 {
		t.Errorf("enphase_up = %v, want 0", got["enphase_up"])
	}
}
