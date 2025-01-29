package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")
var ApiKey = os.Getenv("API_KEY")

const (
	bunnyAPIBase = "https://api.bunny.net"
	recordTTL    = 10
	recordType   = 3 // TXT record type

	errMissingGroupName = "GROUP_NAME must be specified"
	errMissingAPIKey    = "API_KEY must be specified"
)

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

func main() {
	if GroupName == "" {
		panic(errMissingGroupName)
	}
	if ApiKey == "" {
		panic(errMissingAPIKey)
	}

	cmd.RunWebhookServer(GroupName,
		&bunnyNetDNSSolver{},
	)
}

type bunnyNetDNSSolver struct{}
type bunnyNetDNSConfig struct {
	APIKey string
}

func (c *bunnyNetDNSSolver) Name() string {
	return "bunny-net"
}

func (c *bunnyNetDNSSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	if ch == nil {
		return fmt.Errorf("challenge request cannot be nil")
	}

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	zoneID, err := GetZoneID(ch.ResolvedZone, cfg)
	if err != nil {
		return fmt.Errorf("failed to get zone ID: %w", err)
	}

	url := fmt.Sprintf("%s/dnszone/%d/records", bunnyAPIBase, zoneID)

	hostname := strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone)
	hostname = strings.TrimSuffix(hostname, ".")

	record := Record{
		Type:     recordType,
		Ttl:      recordTTL,
		Value:    ch.Key,
		Name:     hostname,
		Disabled: false,
	}

	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("AccessKey", ApiKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("Successfully created DNS record for %s", ch.ResolvedFQDN)
	return nil
}

func GetZone(zone string, cfg bunnyNetDNSConfig) (ZoneResponse, error) {
	if zone[len(zone)-1] == '.' {
		zone = zone[:len(zone)-1]
	}
	url := fmt.Sprintf(`%s/dnszone?page=1&perPage=1&search=%s`, bunnyAPIBase, zone)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ZoneResponse{}, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("AccessKey", cfg.APIKey)

	res, err := httpClient.Do(req)
	if err != nil {
		return ZoneResponse{}, fmt.Errorf("failed to execute request: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return ZoneResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var data ZoneResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return ZoneResponse{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(data.Items) == 0 {
		return ZoneResponse{}, fmt.Errorf("no DNS zone found for %s", zone)
	}

	return data, nil
}

func GetZoneID(zone string, cfg bunnyNetDNSConfig) (int64, error) {
	data, err := GetZone(zone, cfg)
	if err != nil {
		return 0, err
	}
	return int64(data.Items[0].ID), nil
}

func (c *bunnyNetDNSSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	zoneData, err := GetZone(ch.ResolvedZone, cfg)
	if err != nil {
		return fmt.Errorf("failed to get zone ID: %w", err)
	}

	recordID := 0
	hostname := strings.TrimSuffix(strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone), ".")

	for _, record := range zoneData.Items[0].Records {
		if record.Type == 3 && record.Name == hostname && record.Value == ch.Key {
			recordID = record.ID
			break
		}
	}
	if recordID == 0 {
		// Nothing to delete
		return nil
	}

	url := fmt.Sprintf("%s/dnszone/%d/records/%d", bunnyAPIBase, zoneData.Items[0].ID, recordID)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	req.Header.Add("accept", "application/json")
	req.Header.Add("AccessKey", cfg.APIKey)
	_, err = httpClient.Do(req)
	return err
}

func (c *bunnyNetDNSSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	return nil
}

func loadConfig() (bunnyNetDNSConfig, error) {
	if ApiKey == "" {
		panic(errMissingAPIKey)
	}
	cfg := bunnyNetDNSConfig{
		APIKey: ApiKey,
	}

	return cfg, nil
}

type ZoneResponse struct {
	Items        []Item `json:"Items"`
	CurrentPage  int    `json:"CurrentPage"`
	TotalItems   int    `json:"TotalItems"`
	HasMoreItems bool   `json:"HasMoreItems"`
}
type Item struct {
	ID      int      `json:"Id"`
	Domain  string   `json:"Domain"`
	Records []Record `json:"Records"`
}
type Record struct {
	ID       int    `json:"Id,omitempty"`
	Type     int    `json:"Type,omitempty"`
	Ttl      int    `json:"Ttl,omitempty"`
	Value    string `json:"Value,omitempty"`
	Name     string `json:"Name,omitempty"`
	Disabled bool   `json:"Disabled,omitempty"`
}
