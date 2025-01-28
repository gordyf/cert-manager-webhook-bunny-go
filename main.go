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
	recordType   = 3
)

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}
	if ApiKey == "" {
		panic("API_KEY must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&bunnyNetDNSSolver{},
	)
}

// bunnyNetDNSSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type bunnyNetDNSSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	//client kubernetes.Clientset
}

// bunnyNetDNSConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type bunnyNetDNSConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	//APIKeySecretRef v1alpha1.SecretKeySelector `json:"apiKeySecretRef"`
	APIKey string
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *bunnyNetDNSSolver) Name() string {
	return "bunny-net"
}

// Present creates a DNS record to prove domain ownership.
// It implements the ACME DNS01 challenge verification.
func (c *bunnyNetDNSSolver) Present(ch *v1alpha1.ChallengeRequest) error {
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

	record := struct {
		Type     int    `json:"Type"`
		TTL      int    `json:"Ttl"`
		Value    string `json:"Value"`
		Name     string `json:"Name"`
		Disabled bool   `json:"Disabled"`
	}{
		Type:     recordType,
		TTL:      recordTTL,
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

	resp, err := http.DefaultClient.Do(req)
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

func GetZone(zone string, cfg bunnyNetDNSConfig) (Root, error) {
	if zone[len(zone)-1] == '.' {
		zone = zone[:len(zone)-1]
	}
	url := fmt.Sprintf(`https://api.bunny.net/dnszone?page=1&perPage=1&search=%s`, zone)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("AccessKey", cfg.APIKey)

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	var data Root
	json.Unmarshal([]byte(body), &data)
	return data, nil
}

func GetZoneID(zone string, cfg bunnyNetDNSConfig) (int64, error) {
	data, err := GetZone(zone, cfg)
	if err != nil {
		return 0, err
	}
	return int64(data.Items[0].ID), nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *bunnyNetDNSSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	zoneData, err := GetZone(ch.ResolvedZone, cfg)
	if err != nil {
		return fmt.Errorf("failed to get zone ID: %w", err)
	}

	// get matching record id
	recordID := 0
	hostname := strings.TrimSuffix(strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone), ".")
	fmt.Printf("Looking for: %d %s %s\n", 3, hostname, ch.Key)
	for _, record := range zoneData.Items[0].Records {
		fmt.Printf("%d %s %s\n", record.Type, record.Name, record.Value)
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
	_, err = http.DefaultClient.Do(req)
	return err
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *bunnyNetDNSSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	///// UNCOMMENT THE BELOW CODE TO MAKE A KUBERNETES CLIENTSET AVAILABLE TO
	///// YOUR CUSTOM DNS PROVIDER

	//cl, err := kubernetes.NewForConfig(kubeClientConfig)
	//if err != nil {
	//	return err
	//}
	//
	//c.client = cl

	///// END OF CODE TO MAKE KUBERNETES CLIENTSET AVAILABLE
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig() (bunnyNetDNSConfig, error) {
	if ApiKey == "" {
		panic("API_KEY must be specified")
	}
	cfg := bunnyNetDNSConfig{
		APIKey: ApiKey,
	}

	return cfg, nil
}

type Root struct {
	Items        []Item `json:"Items"`
	CurrentPage  int    `json:"CurrentPage"`
	TotalItems   int    `json:"TotalItems"`
	HasMoreItems bool   `json:"HasMoreItems"`
}

// Item represents an item in the Items array
type Item struct {
	ID                            int       `json:"Id"`
	Domain                        string    `json:"Domain"`
	Records                       []Record  `json:"Records"`
	DateModified                  time.Time `json:"DateModified"`
	DateCreated                   time.Time `json:"DateCreated"`
	NameserversDetected           bool      `json:"NameserversDetected"`
	CustomNameserversEnabled      bool      `json:"CustomNameserversEnabled"`
	Nameserver1                   string    `json:"Nameserver1"`
	Nameserver2                   string    `json:"Nameserver2"`
	SoaEmail                      string    `json:"SoaEmail"`
	NameserversNextCheck          time.Time `json:"NameserversNextCheck"`
	LoggingEnabled                bool      `json:"LoggingEnabled"`
	LoggingIPAnonymizationEnabled bool      `json:"LoggingIPAnonymizationEnabled"`
	LogAnonymizationType          int       `json:"LogAnonymizationType"`
}

// Record represents a DNS record
type Record struct {
	ID                    int            `json:"Id"`
	Type                  int            `json:"Type"`
	Ttl                   int            `json:"Ttl"`
	Value                 string         `json:"Value"`
	Name                  string         `json:"Name"`
	Weight                int            `json:"Weight"`
	Priority              int            `json:"Priority"`
	Port                  int            `json:"Port"`
	Flags                 int            `json:"Flags"`
	Tag                   string         `json:"Tag"`
	Accelerated           bool           `json:"Accelerated"`
	AcceleratedPullZoneId int            `json:"AcceleratedPullZoneId"`
	LinkName              string         `json:"LinkName"`
	IPGeoLocationInfo     *IPGeoLocation `json:"IPGeoLocationInfo"`
	GeolocationInfo       interface{}    `json:"GeolocationInfo"`
	MonitorStatus         int            `json:"MonitorStatus"`
	MonitorType           int            `json:"MonitorType"`
	GeolocationLatitude   float64        `json:"GeolocationLatitude"`
	GeolocationLongitude  float64        `json:"GeolocationLongitude"`
	EnviromentalVariables []interface{}  `json:"EnviromentalVariables"`
	LatencyZone           *string        `json:"LatencyZone"`
	SmartRoutingType      int            `json:"SmartRoutingType"`
	Disabled              bool           `json:"Disabled"`
	Comment               *string        `json:"Comment"`
}

// IPGeoLocation represents the IP geolocation information
type IPGeoLocation struct {
	CountryCode      string `json:"CountryCode"`
	Country          string `json:"Country"`
	ASN              int    `json:"ASN"`
	OrganizationName string `json:"OrganizationName"`
	City             string `json:"City"`
}
