package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

// DNSRecord represents a cached DNS record
type DNSRecord struct {
	ID        int64     `json:"id"`
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	Address   string    `json:"address"`
	TTL       uint32    `json:"ttl"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CustomRoute represents a custom host routing rule
type CustomRoute struct {
	ID        int64     `json:"id"`
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	Target    string    `json:"target"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// ServerStats represents server statistics
type ServerStats struct {
	QueriesTotal      int64     `json:"queries_total"`
	CacheHits         int64     `json:"cache_hits"`
	CustomRoutesUsed  int64     `json:"custom_routes_used"`
	CacheSize         int       `json:"cache_size"`
	UptimeSeconds     int64     `json:"uptime_seconds"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// DNSServer configuration
type DNSServer struct {
	config      *Config
	db          *sql.DB
	dnsServer   *dns.Server
	httpServer  *http.Server
	cache       sync.Map
	upstreamDNS []string
	startTime   time.Time
	stats       ServerStats
	statsMutex  sync.RWMutex
}

// Config holds server configuration
type Config struct {
	Server struct {
		ListenAddr    string `json:"listen_addr"`
		HTTPAddr      string `json:"http_addr"`
		EnableHTTPS   bool   `json:"enable_https"`
		SSLCertPath   string `json:"ssl_cert_path"`
		SSLKeyPath    string `json:"ssl_key_path"`
		ReadTimeout   int    `json:"read_timeout"`
		WriteTimeout  int    `json:"write_timeout"`
		IdleTimeout   int    `json:"idle_timeout"`
	} `json:"server"`
	DNS struct {
		UpstreamServers      []string `json:"upstream_servers"`
		DoHEndpoints         []string `json:"doh_endpoints"`
		DotServers           []string `json:"dot_servers"`
		CacheTTL             int      `json:"cache_ttl"`
		MaxCacheSize         int      `json:"max_cache_size"`
		EnableIPv6           bool     `json:"enable_ipv6"`
		EnableLogging        bool     `json:"enable_logging"`
		QueryTimeout         int      `json:"query_timeout"`
		MaxRetries           int      `json:"max_retries"`
		EnableDNSSEC         bool     `json:"enable_dnssec"`
		PreferSecureTransport bool   `json:"prefer_secure_transport"`
	} `json:"dns"`
	Database struct {
		Path                 string `json:"path"`
		MaxConnections       int    `json:"max_connections"`
		MaxIdleConnections   int    `json:"max_idle_connections"`
		ConnectionMaxLifetime int  `json:"connection_max_lifetime"`
	} `json:"database"`
	Logging struct {
		Level          string `json:"level"`
		FilePath       string `json:"file_path"`
		MaxSize        int    `json:"max_size"`
		MaxBackups     int    `json:"max_backups"`
		MaxAge         int    `json:"max_age"`
		Compress       bool   `json:"compress"`
		EnableAccessLog bool  `json:"enable_access_log"`
	} `json:"logging"`
	Security struct {
		EnableRateLimiting  bool     `json:"enable_rate_limiting"`
		RequestsPerSecond   int      `json:"requests_per_second"`
		TrustedProxies      []string `json:"trusted_proxies"`
		CORSAllowedOrigins  []string `json:"cors_allowed_origins"`
		EnableAuthentication bool    `json:"enable_authentication"`
		APIKeys             []string `json:"api_keys"`
		BlockedDomains      []string `json:"blocked_domains"`
		AllowedNetworks     []string `json:"allowed_networks"`
	} `json:"security"`
	Monitoring struct {
		EnableMetrics      bool   `json:"enable_metrics"`
		MetricsPort        string `json:"metrics_port"`
		EnableHealthCheck  bool   `json:"enable_health_check"`
		HealthCheckInterval int  `json:"health_check_interval"`
		EnableProfiling    bool   `json:"enable_profiling"`
	} `json:"monitoring"`
}

// CacheEntry represents a cache entry
type CacheEntry struct {
	Records []string  `json:"records"`
	Expires time.Time `json:"expires"`
}

func main() {
	// Load configuration
	config := &Config{}
	
	// Set default values
	config.Server.ListenAddr = ":53"
	config.Server.HTTPAddr = ":8080"
	config.Server.ReadTimeout = 30
	config.Server.WriteTimeout = 30
	config.Server.IdleTimeout = 60
	
	config.DNS.UpstreamServers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	config.DNS.DoHEndpoints = []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"}
	config.DNS.CacheTTL = 300
	config.DNS.MaxCacheSize = 10000
	config.DNS.EnableIPv6 = true
	config.DNS.EnableLogging = true
	config.DNS.QueryTimeout = 5
	config.DNS.MaxRetries = 3
	
	config.Database.Path = "./data/dns_cache.db"
	config.Database.MaxConnections = 25
	config.Database.MaxIdleConnections = 5
	config.Database.ConnectionMaxLifetime = 300
	
	config.Logging.Level = "info"
	config.Logging.FilePath = "./logs/local-dns-go.log"
	config.Logging.MaxSize = 100
	config.Logging.MaxBackups = 3
	config.Logging.MaxAge = 28
	config.Logging.Compress = true
	
	config.Security.EnableRateLimiting = true
	config.Security.RequestsPerSecond = 100
	config.Security.TrustedProxies = []string{"127.0.0.1", "::1"}
	config.Security.CORSAllowedOrigins = []string{"*"}
	
	config.Monitoring.EnableMetrics = true
	config.Monitoring.MetricsPort = ":9090"
	config.Monitoring.EnableHealthCheck = true

	// Initialize DNS server
	server, err := NewDNSServer(config)
	if err != nil {
		log.Fatal("Failed to create DNS server:", err)
	}

	// Start DNS server
	go func() {
		log.Printf("Starting DNS server on %s", config.Server.ListenAddr)
		if err := server.StartDNSServer(); err != nil {
			log.Fatal("DNS server error:", err)
		}
	}()

	// Start HTTP management server
	log.Printf("Starting HTTP management server on %s", config.Server.HTTPAddr)
	if err := server.StartHTTPServer(); err != nil && err != http.ErrServerClosed {
		log.Fatal("HTTP server error:", err)
	}
}

// NewDNSServer creates a new DNS server instance
func NewDNSServer(config *Config) (*DNSServer, error) {
	// Initialize database
	db, err := initDatabase(config.Database.Path)
	if err != nil {
		return nil, err
	}

	server := &DNSServer{
		config:      config,
		db:          db,
		cache:       sync.Map{},
		upstreamDNS: config.DNS.UpstreamServers,
		startTime:   time.Now(),
		stats:       ServerStats{},
	}

	// Initialize DNS server
	dns.HandleFunc(".", server.handleDNSRequest)
	server.dnsServer = &dns.Server{
		Addr: config.Server.ListenAddr,
		Net:  "udp",
	}

	// Initialize HTTP server
	mux := http.NewServeMux()
	
	// Web UI
	mux.HandleFunc("/", server.handleWebUI)
	
	// API endpoints
	mux.HandleFunc("/api/stats", server.handleStatsAPI)
	mux.HandleFunc("/api/cache", server.handleCacheAPI)
	mux.HandleFunc("/api/routes", server.handleRoutesAPI)
	mux.HandleFunc("/api/config", server.handleConfigAPI)
	mux.HandleFunc("/api/query-test", server.handleQueryTestAPI)
	mux.HandleFunc("/api/cache/stats", server.handleCacheStatsAPI)
	
	// Health check
	mux.HandleFunc("/health", server.handleHealthAPI)

	server.httpServer = &http.Server{
		Addr:         config.Server.HTTPAddr,
		Handler:      mux,
		ReadTimeout:  time.Duration(config.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(config.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(config.Server.IdleTimeout) * time.Second,
	}

	return server, nil
}

// initDatabase initializes SQLite database
func initDatabase(dbPath string) (*sql.DB, error) {
	// Create data directory if it doesn't exist
	dir := "./data"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, 0755)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Create tables
	queries := []string{
		`CREATE TABLE IF NOT EXISTS dns_records (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT NOT NULL,
			type TEXT NOT NULL,
			address TEXT NOT NULL,
			ttl INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(domain, type, address)
		)`,

		`CREATE TABLE IF NOT EXISTS custom_routes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT NOT NULL UNIQUE,
			type TEXT NOT NULL DEFAULT 'A',
			target TEXT NOT NULL,
			enabled BOOLEAN DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS server_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			queries_total INTEGER DEFAULT 0,
			cache_hits INTEGER DEFAULT 0,
			custom_routes_used INTEGER DEFAULT 0,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		`INSERT OR IGNORE INTO server_stats (id, queries_total, cache_hits, custom_routes_used) 
		 VALUES (1, 0, 0, 0)`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return nil, err
		}
	}

	return db, nil
}

// handleDNSRequest processes DNS queries
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	s.updateStats("queries_total", 1)

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	question := r.Question[0]
	qtype := dns.TypeToString[question.Qtype]
	domain := question.Name

	if s.config.DNS.EnableLogging {
		log.Printf("DNS Query: %s %s from %s", domain, qtype, w.RemoteAddr())
	}

	// Check custom routes first
	if customResponse, found := s.checkCustomRoutes(domain, qtype); found {
		s.updateStats("custom_routes_used", 1)
		for _, rr := range customResponse {
			m.Answer = append(m.Answer, rr)
		}
		w.WriteMsg(m)
		return
	}

	// Check cache
	cacheKey := fmt.Sprintf("%s:%s", domain, qtype)
	if cached, found := s.getFromCache(cacheKey); found {
		s.updateStats("cache_hits", 1)
		m.Answer = cached
		w.WriteMsg(m)
		return
	}

	// Resolve from upstream
	response, err := s.resolveUpstream(domain, qtype)
	if err != nil {
		log.Printf("Failed to resolve %s: %v", domain, err)
		dns.HandleFailed(w, r)
		return
	}

	if len(response) > 0 {
		// Cache the response
		s.addToCache(cacheKey, response)
		m.Answer = response
	}

	w.WriteMsg(m)
}

// checkCustomRoutes checks for custom routing rules
func (s *DNSServer) checkCustomRoutes(domain, qtype string) ([]dns.RR, bool) {
	var routes []CustomRoute
	query := "SELECT domain, type, target FROM custom_routes WHERE enabled = 1 AND domain = ?"
	rows, err := s.db.Query(query, strings.TrimSuffix(domain, "."))
	if err != nil {
		return nil, false
	}
	defer rows.Close()

	for rows.Next() {
		var route CustomRoute
		if err := rows.Scan(&route.Domain, &route.Type, &route.Target); err == nil {
			routes = append(routes, route)
		}
	}

	if len(routes) == 0 {
		return nil, false
	}

	var result []dns.RR
	for _, route := range routes {
		if route.Type != qtype && !(qtype == "AAAA" && route.Type == "A" && !s.config.DNS.EnableIPv6) {
			continue
		}

		switch route.Type {
		case "A":
			if rr, err := dns.NewRR(fmt.Sprintf("%s A %s", domain, route.Target)); err == nil {
				result = append(result, rr)
			}
		case "AAAA":
			if s.config.DNS.EnableIPv6 {
				if rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", domain, route.Target)); err == nil {
					result = append(result, rr)
				}
			}
		case "CNAME":
			if rr, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", domain, route.Target)); err == nil {
				result = append(result, rr)
			}
		}
	}

	return result, len(result) > 0
}

// resolveUpstream resolves DNS queries using upstream servers
func (s *DNSServer) resolveUpstream(domain, qtype string) ([]dns.RR, error) {
	// Try DoH first if preferred
	if s.config.DNS.PreferSecureTransport {
		for _, dohEndpoint := range s.config.DNS.DoHEndpoints {
			if response, err := s.resolveDoH(domain, qtype, dohEndpoint); err == nil {
				return response, nil
			}
		}
	}

	// Try DoT if preferred
	if s.config.DNS.PreferSecureTransport {
		for _, dotServer := range s.config.DNS.DotServers {
			if response, err := s.resolveDoT(domain, qtype, dotServer); err == nil {
				return response, nil
			}
		}
	}

	// Fallback to traditional DNS
	question := dns.Question{
		Name:   domain,
		Qtype:  dns.StringToType[qtype],
		Qclass: dns.ClassINET,
	}

	msg := new(dns.Msg)
	msg.Question = []dns.Question{question}
	msg.RecursionDesired = true

	for _, upstream := range s.upstreamDNS {
		client := &dns.Client{
			Net:     "udp",
			Timeout: time.Duration(s.config.DNS.QueryTimeout) * time.Second,
		}
		response, _, err := client.Exchange(msg, upstream)
		if err == nil && len(response.Answer) > 0 {
			return response.Answer, nil
		}
	}

	return nil, fmt.Errorf("failed to resolve from all upstream servers")
}

// resolveDoH resolves DNS over HTTPS
func (s *DNSServer) resolveDoH(domain, qtype, endpoint string) ([]dns.RR, error) {
	client := &http.Client{
		Timeout: time.Duration(s.config.DNS.QueryTimeout) * time.Second,
	}

	url := fmt.Sprintf("%s?name=%s&type=%s", endpoint, domain, qtype)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var dohResponse struct {
		Answer []struct {
			Name string `json:"name"`
			Type uint16 `json:"type"`
			TTL  uint32 `json:"TTL"`
			Data string `json:"data"`
		} `json:"Answer"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&dohResponse); err != nil {
		return nil, err
	}

	var result []dns.RR
	for _, ans := range dohResponse.Answer {
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", ans.Name, ans.TTL, dns.TypeToString[ans.Type], ans.Data))
		if err == nil {
			result = append(result, rr)
		}
	}

	return result, nil
}

// resolveDoT resolves DNS over TLS
func (s *DNSServer) resolveDoT(domain, qtype, dotServer string) ([]dns.RR, error) {
	question := dns.Question{
		Name:   domain,
		Qtype:  dns.StringToType[qtype],
		Qclass: dns.ClassINET,
	}

	msg := new(dns.Msg)
	msg.Question = []dns.Question{question}
	msg.RecursionDesired = true

	// Create TLS configuration
	tlsConfig := &tls.Config{
		ServerName: strings.Split(dotServer, ":")[0],
	}

	// Create DNS over TLS client
	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Timeout:   time.Duration(s.config.DNS.QueryTimeout) * time.Second,
	}

	response, _, err := client.Exchange(msg, dotServer)
	if err != nil {
		return nil, err
	}

	if len(response.Answer) > 0 {
		return response.Answer, nil
	}

	return nil, fmt.Errorf("no answer from DoT server")
}

// Cache management
func (s *DNSServer) getFromCache(key string) ([]dns.RR, bool) {
	if cached, found := s.cache.Load(key); found {
		entry := cached.(CacheEntry)
		if time.Now().Before(entry.Expires) {
			// Convert stored data back to DNS RR
			var result []dns.RR
			for _, rrStr := range entry.Records {
				if rr, err := dns.NewRR(rrStr); err == nil {
					result = append(result, rr)
				}
			}
			return result, true
		}
		s.cache.Delete(key)
	}
	return nil, false
}

func (s *DNSServer) addToCache(key string, records []dns.RR) {
	var rrStrings []string
	for _, rr := range records {
		rrStrings = append(rrStrings, rr.String())
	}

	entry := CacheEntry{
		Records: rrStrings,
		Expires: time.Now().Add(time.Duration(s.config.DNS.CacheTTL) * time.Second),
	}

	s.cache.Store(key, entry)

	// Also store in database
	go s.storeRecordInDB(key, records)
}

func (s *DNSServer) storeRecordInDB(key string, records []dns.RR) {
	parts := strings.Split(key, ":")
	if len(parts) != 2 {
		return
	}

	domain := parts[0]
	qtype := parts[1]

	var rrStrings []string
	for _, rr := range records {
		rrStrings = append(rrStrings, rr.String())
	}

	address := strings.Join(rrStrings, "|")

	query := `INSERT OR REPLACE INTO dns_records (domain, type, address, ttl, updated_at) 
	          VALUES (?, ?, ?, ?, ?)`
	s.db.Exec(query, domain, qtype, address, s.config.DNS.CacheTTL, time.Now())
}

// Stats management
func (s *DNSServer) updateStats(field string, increment int64) {
	s.statsMutex.Lock()
	defer s.statsMutex.Unlock()

	switch field {
	case "queries_total":
		s.stats.QueriesTotal += increment
	case "cache_hits":
		s.stats.CacheHits += increment
	case "custom_routes_used":
		s.stats.CustomRoutesUsed += increment
	}
	s.stats.UpdatedAt = time.Now()
	s.stats.UptimeSeconds = int64(time.Since(s.startTime).Seconds())

	// Update cache size
	cacheSize := 0
	s.cache.Range(func(_, _ interface{}) bool {
		cacheSize++
		return true
	})
	s.stats.CacheSize = cacheSize
}

// Start servers
func (s *DNSServer) StartDNSServer() error {
	return s.dnsServer.ListenAndServe()
}

func (s *DNSServer) StartHTTPServer() error {
	if s.config.Server.EnableHTTPS && s.config.Server.SSLCertPath != "" && s.config.Server.SSLKeyPath != "" {
		return s.httpServer.ListenAndServeTLS(s.config.Server.SSLCertPath, s.config.Server.SSLKeyPath)
	}
	return s.httpServer.ListenAndServe()
}

// Web UI Handlers
func (s *DNSServer) handleWebUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	tmpl := template.Must(template.New("index").Parse(webUITemplate))
	
	stats := s.getStats()
	cacheEntries := s.getCacheEntries()
	customRoutes := s.getCustomRoutes()

	data := struct {
		Stats        ServerStats
		CacheEntries []DNSRecord
		CustomRoutes []CustomRoute
		Config       *Config
	}{
		Stats:        stats,
		CacheEntries: cacheEntries,
		CustomRoutes: customRoutes,
		Config:       s.config,
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// API Handlers
func (s *DNSServer) handleStatsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := s.getStats()
	json.NewEncoder(w).Encode(stats)
}

func (s *DNSServer) handleCacheAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		entries := s.getCacheEntries()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"entries": entries,
			"total":   len(entries),
		})
	case "DELETE":
		s.clearCache()
		json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Cache cleared successfully"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *DNSServer) handleRoutesAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		routes := s.getCustomRoutes()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"routes": routes,
			"total":  len(routes),
		})
	case "POST":
		var route CustomRoute
		if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.addCustomRoute(route); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(route)
	case "DELETE":
		id := r.URL.Query().Get("id")
		if err := s.deleteCustomRoute(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Route deleted successfully"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *DNSServer) handleConfigAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		json.NewEncoder(w).Encode(s.config)
		return
	}

	if r.Method == "POST" {
		var newConfig Config
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Update only allowed fields
		s.config.DNS.CacheTTL = newConfig.DNS.CacheTTL
		s.config.DNS.EnableLogging = newConfig.DNS.EnableLogging
		json.NewEncoder(w).Encode(s.config)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *DNSServer) handleQueryTestAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Domain string `json:"domain"`
		Type   string `json:"type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	start := time.Now()
	response, err := s.resolveUpstream(request.Domain+".", request.Type)
	responseTime := time.Since(start).Milliseconds()

	var answers []string
	source := "upstream"
	if err == nil {
		for _, rr := range response {
			answers = append(answers, rr.String())
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"domain":        request.Domain,
		"type":          request.Type,
		"answers":       answers,
		"response_time": responseTime,
		"source":        source,
		"error":         err,
	})
}

func (s *DNSServer) handleCacheStatsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cacheSize := 0
	s.cache.Range(func(_, _ interface{}) bool {
		cacheSize++
		return true
	})

	dbSize := 0
	s.db.QueryRow("SELECT COUNT(*) FROM dns_records").Scan(&dbSize)

	stats := s.getStats()
	hitRate := 0.0
	if stats.QueriesTotal > 0 {
		hitRate = float64(stats.CacheHits) / float64(stats.QueriesTotal)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_entries":    cacheSize + dbSize,
		"memory_entries":   cacheSize,
		"database_entries": dbSize,
		"hit_rate":         hitRate,
	})
}

func (s *DNSServer) handleHealthAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Check database connection
	dbStatus := "healthy"
	if err := s.db.Ping(); err != nil {
		dbStatus = "unhealthy"
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":            "healthy",
		"timestamp":         time.Now().Format(time.RFC3339),
		"uptime_seconds":    int64(time.Since(s.startTime).Seconds()),
		"database_connected": dbStatus == "healthy",
		"cache_operational": true,
	})
}

// Database helpers
func (s *DNSServer) getStats() ServerStats {
	s.statsMutex.RLock()
	defer s.statsMutex.RUnlock()

	// Get additional stats from database
	var dbQueries, dbHits, dbRoutes int64
	s.db.QueryRow("SELECT queries_total, cache_hits, custom_routes_used FROM server_stats WHERE id = 1").
		Scan(&dbQueries, &dbHits, &dbRoutes)

	stats := s.stats
	stats.QueriesTotal += dbQueries
	stats.CacheHits += dbHits
	stats.CustomRoutesUsed += dbRoutes

	return stats
}

func (s *DNSServer) getCacheEntries() []DNSRecord {
	var entries []DNSRecord
	query := "SELECT id, domain, type, address, ttl, created_at, updated_at FROM dns_records ORDER BY updated_at DESC LIMIT 100"
	rows, err := s.db.Query(query)
	if err != nil {
		return entries
	}
	defer rows.Close()

	for rows.Next() {
		var record DNSRecord
		rows.Scan(&record.ID, &record.Domain, &record.Type, &record.Address, &record.TTL, &record.CreatedAt, &record.UpdatedAt)
		entries = append(entries, record)
	}
	return entries
}

func (s *DNSServer) getCustomRoutes() []CustomRoute {
	var routes []CustomRoute
	query := "SELECT id, domain, type, target, enabled, created_at FROM custom_routes ORDER BY created_at DESC"
	rows, err := s.db.Query(query)
	if err != nil {
		return routes
	}
	defer rows.Close()

	for rows.Next() {
		var route CustomRoute
		rows.Scan(&route.ID, &route.Domain, &route.Type, &route.Target, &route.Enabled, &route.CreatedAt)
		routes = append(routes, route)
	}
	return routes
}

func (s *DNSServer) addCustomRoute(route CustomRoute) error {
	query := "INSERT OR REPLACE INTO custom_routes (domain, type, target, enabled) VALUES (?, ?, ?, ?)"
	_, err := s.db.Exec(query, route.Domain, route.Type, route.Target, route.Enabled)
	return err
}

func (s *DNSServer) deleteCustomRoute(id string) error {
	_, err := s.db.Exec("DELETE FROM custom_routes WHERE id = ?", id)
	return err
}

func (s *DNSServer) clearCache() {
	s.cache = sync.Map{}
	s.db.Exec("DELETE FROM dns_records")
}

// Web UI Template (same as before, but I'll include it for completeness)
const webUITemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Local-DNS-Go</title>
    <style>
        :root {
            --primary: #2563eb;
            --secondary: #64748b;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --dark: #1e293b;
            --light: #f8fafc;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: var(--dark);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            padding: 2rem;
            border-radius: 15px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
            text-align: center;
        }
        
        .header h1 {
            color: var(--primary);
            margin-bottom: 0.5rem;
        }
        
        .header p {
            color: var(--secondary);
            font-size: 1.1rem;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .card {
            background: white;
            padding: 1.5rem;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .card h2 {
            color: var(--primary);
            margin-bottom: 1rem;
            font-size: 1.3rem;
        }
        
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }
        
        .stat-item {
            text-align: center;
            padding: 1rem;
            background: var(--light);
            border-radius: 10px;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: var(--primary);
        }
        
        .stat-label {
            color: var(--secondary);
            font-size: 0.9rem;
        }
        
        .table-container {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        
        th {
            background: var(--light);
            font-weight: 600;
            color: var(--dark);
        }
        
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.2s;
        }
        
        .btn-primary {
            background: var(--primary);
            color: white;
        }
        
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        
        .btn-success {
            background: var(--success);
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        
        .form-control {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid #cbd5e1;
            border-radius: 5px;
            font-size: 1rem;
        }
        
        .tabs {
            display: flex;
            margin-bottom: 1rem;
            border-bottom: 1px solid #cbd5e1;
        }
        
        .tab {
            padding: 0.75rem 1.5rem;
            cursor: pointer;
            border-bottom: 2px solid transparent;
        }
        
        .tab.active {
            border-bottom-color: var(--primary);
            color: var(--primary);
            font-weight: 500;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .badge {
            padding: 0.25rem 0.5rem;
            border-radius: 15px;
            font-size: 0.8rem;
            font-weight: 500;
        }
        
        .badge-success {
            background: var(--success);
            color: white;
        }
        
        .badge-warning {
            background: var(--warning);
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Local-DNS-Go</h1>
            <p>DNS Cache Server with Web Management</p>
        </div>

        <div class="dashboard">
            <div class="card">
                <h2>Server Statistics</h2>
                <div class="stat-grid">
                    <div class="stat-item">
                        <div class="stat-value">{{.Stats.QueriesTotal}}</div>
                        <div class="stat-label">Total Queries</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{{.Stats.CacheHits}}</div>
                        <div class="stat-label">Cache Hits</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{{.Stats.CustomRoutesUsed}}</div>
                        <div class="stat-label">Custom Routes</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{{.Stats.CacheSize}}</div>
                        <div class="stat-label">Cached Entries</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Quick Actions</h2>
                <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                    <button class="btn btn-primary" onclick="clearCache()">Clear Cache</button>
                    <button class="btn btn-success" onclick="refreshStats()">Refresh Stats</button>
                    <button class="btn btn-primary" onclick="showTab('config')">Server Config</button>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="tabs">
                <div class="tab active" onclick="showTab('cache')">DNS Cache</div>
                <div class="tab" onclick="showTab('routes')">Custom Routes</div>
                <div class="tab" onclick="showTab('config')">Configuration</div>
            </div>

            <div id="cache-tab" class="tab-content active">
                <h2>DNS Cache Entries</h2>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>Type</th>
                                <th>Address</th>
                                <th>TTL</th>
                                <th>Last Updated</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .CacheEntries}}
                            <tr>
                                <td>{{.Domain}}</td>
                                <td>{{.Type}}</td>
                                <td>{{.Address}}</td>
                                <td>{{.TTL}}</td>
                                <td>{{.UpdatedAt.Format "2006-01-02 15:04:05"}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>

            <div id="routes-tab" class="tab-content">
                <h2>Custom Routing Rules</h2>
                <button class="btn btn-primary" onclick="showAddRouteForm()" style="margin-bottom: 1rem;">Add Route</button>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>Type</th>
                                <th>Target</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .CustomRoutes}}
                            <tr>
                                <td>{{.Domain}}</td>
                                <td>{{.Type}}</td>
                                <td>{{.Target}}</td>
                                <td>
                                    {{if .Enabled}}
                                    <span class="badge badge-success">Enabled</span>
                                    {{else}}
                                    <span class="badge badge-warning">Disabled</span>
                                    {{end}}
                                </td>
                                <td>
                                    <button class="btn btn-danger" onclick="deleteRoute({{.ID}})">Delete</button>
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>

            <div id="config-tab" class="tab-content">
                <h2>Server Configuration</h2>
                <form id="config-form">
                    <div class="form-group">
                        <label>Cache TTL (seconds)</label>
                        <input type="number" class="form-control" name="cache_ttl" value="{{.Config.DNS.CacheTTL}}">
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" name="enable_ipv6" {{if .Config.DNS.EnableIPv6}}checked{{end}}>
                            Enable IPv6 Support
                        </label>
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" name="enable_logging" {{if .Config.DNS.EnableLogging}}checked{{end}}>
                            Enable Query Logging
                        </label>
                    </div>
                    <button type="submit" class="btn btn-primary">Update Configuration</button>
                </form>
            </div>
        </div>
    </div>

    <!-- Add Route Modal -->
    <div id="add-route-modal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center;">
        <div style="background: white; padding: 2rem; border-radius: 15px; width: 90%; max-width: 500px;">
            <h3 style="margin-bottom: 1rem;">Add Custom Route</h3>
            <form id="add-route-form">
                <div class="form-group">
                    <label>Domain</label>
                    <input type="text" class="form-control" name="domain" required>
                </div>
                <div class="form-group">
                    <label>Type</label>
                    <select class="form-control" name="type" required>
                        <option value="A">A (IPv4)</option>
                        <option value="AAAA">AAAA (IPv6)</option>
                        <option value="CNAME">CNAME</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Target</label>
                    <input type="text" class="form-control" name="target" required>
                </div>
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="enabled" checked>
                        Enabled
                    </label>
                </div>
                <div style="display: flex; gap: 0.5rem; justify-content: flex-end;">
                    <button type="button" class="btn" onclick="hideAddRouteForm()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add Route</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');
            event.target.classList.add('active');
        }
        
        function clearCache() {
            fetch('/api/cache', { method: 'DELETE' })
                .then(response => response.json())
                .then(data => {
                    alert('Cache cleared successfully');
                    location.reload();
                });
        }
        
        function refreshStats() {
            location.reload();
        }
        
        function showAddRouteForm() {
            document.getElementById('add-route-modal').style.display = 'flex';
        }
        
        function hideAddRouteForm() {
            document.getElementById('add-route-modal').style.display = 'none';
        }
        
        function deleteRoute(id) {
            if (confirm('Are you sure you want to delete this route?')) {
                fetch('/api/routes?id=' + id, { method: 'DELETE' })
                    .then(response => response.json())
                    .then(data => {
                        alert('Route deleted successfully');
                        location.reload();
                    });
            }
        }
        
        // Form handlers
        document.getElementById('add-route-form').addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            const route = {
                domain: formData.get('domain'),
                type: formData.get('type'),
                target: formData.get('target'),
                enabled: formData.get('enabled') === 'on'
            };
            
            fetch('/api/routes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(route)
            })
            .then(response => response.json())
            .then(data => {
                hideAddRouteForm();
                location.reload();
            });
        });
        
        document.getElementById('config-form').addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            const config = {
                dns: {
                    cache_ttl: parseInt(formData.get('cache_ttl')),
                    enable_ipv6: formData.get('enable_ipv6') === 'on',
                    enable_logging: formData.get('enable_logging') === 'on'
                }
            };
            
            fetch('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            })
            .then(response => response.json())
            .then(data => {
                alert('Configuration updated successfully');
            });
        });
    </script>
</body>
</html>`
