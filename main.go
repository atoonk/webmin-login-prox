package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	WebminURL      string `json:"webminURL"`
	ListenAddr     string `json:"listenAddr"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	RequireBorder0 bool   `json:"requireBorder0"`
}

var (
	config = Config{
		ListenAddr:     "127.0.0.1:8443",
		RequireBorder0: true,
	}
	sessionStore = NewSessionStore()
	sessionLocks = &sync.Map{}
)

func main() {
	// Load configuration
	loadConfig("config.json")

	// Validate configuration
	validateConfig()

	// Parse the Webmin URL
	proxyURL, err := url.Parse(config.WebminURL)
	if err != nil {
		log.Fatalf("Failed to parse Webmin URL: %v", err)
	}

	// Create a reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(proxyURL)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	// Modify the response to store the cookies in the session store and send them back to the client
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Retrieve ProxySID from context
		ProxySID, ok := resp.Request.Context().Value("ProxySID").(string)
		if !ok {
			return nil
		}

		if ProxySID != "" {
			sessionLock := getSessionLock(ProxySID)
			sessionLock.Lock()
			defer sessionLock.Unlock()

			sessionStore.Set(ProxySID, resp.Cookies())
		}
		return nil
	}

	// Handle proxy errors
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if err != nil && strings.Contains(err.Error(), "context canceled") {
			http.Error(w, "Request canceled by the client", http.StatusRequestTimeout)
			return
		}
		log.Printf("Proxy error: %v", err)
		http.Error(w, "Proxy error", http.StatusBadGateway)
	}

	// Handle incoming requests
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var ProxySID string

		// Check if X-Auth-Email header is present, if so log the value
		if config.RequireBorder0 && r.Header.Get("X-Auth-Email") == "" {
			log.Printf("Access denied: Request did not come through Border0")
			http.Error(w, "Access denied", http.StatusUnauthorized)
			return
		}

		// Check if the request has the ProxySID cookie
		for _, cookie := range r.Cookies() {
			if cookie.Name == "ProxySID" {
				ProxySID = cookie.Value
				break
			}
		}

		// If no ProxySID cookie or session not authenticated, perform authentication
		if ProxySID == "" || !sessionStore.IsAuthenticated(ProxySID) {
			sessionLock := getSessionLock(ProxySID)
			sessionLock.Lock()
			defer sessionLock.Unlock()

			var err error
			ProxySID, err = authenticateAndSetCookies(proxyURL, r, w)
			if err != nil {
				http.Error(w, "Failed to authenticate", http.StatusUnauthorized)
				log.Printf("Authentication failed: %v", err)
				return
			}
		}

		// Check if the upstream session is still valid
		// Re-authenticate if the sid cookie is invalid
		if !isUpstreamSessionValid(ProxySID) {
			sessionLock := getSessionLock(ProxySID)
			sessionLock.Lock()
			defer sessionLock.Unlock()

			var err error
			ProxySID, err = authenticateAndSetCookies(proxyURL, r, w)
			if err != nil {
				http.Error(w, "Failed to re-authenticate", http.StatusUnauthorized)
				log.Printf("Re-authentication failed: %v", err)
				return
			}
		}

		// Set ProxySID in the request context
		ctx := context.WithValue(r.Context(), "ProxySID", ProxySID)
		r = r.WithContext(ctx)

		// Add session cookies to the request
		sessionCookies := sessionStore.Get(ProxySID)
		for _, cookie := range sessionCookies {
			r.AddCookie(cookie)
		}

		// Serve the request using the proxy
		proxy.ServeHTTP(w, r)

		// Get cookies from the response
		respCookies := sessionStore.Get(ProxySID)

		// Handle logout if sid=x
		for _, cookie := range respCookies {
			if cookie.Name == "sid" && (cookie.Value == "x" || cookie.Value == "") {

				// Clear the ProxySID cookie on the client
				http.SetCookie(w, &http.Cookie{
					Name:     "ProxySID",
					Value:    "",
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
					Expires:  time.Unix(0, 0),
				})

				// Clear the session
				sessionStore.Delete(ProxySID)
				log.Printf("User logged out: %s", ProxySID)

				return
			}
		}

		// Clear existing cookies
		r.Header.Del("Cookie")

		// After serving the request, ensure cookies set by Webmin are sent back to the client
		for _, cookie := range respCookies {
			http.SetCookie(w, cookie)
		}
	})

	// Check and generate TLS files if not present
	checkAndGenerateTLSFiles("cert.pem", "key.pem")

	log.Printf("Starting proxy server on %s", config.ListenAddr)
	if err := http.ListenAndServeTLS(config.ListenAddr, "cert.pem", "key.pem", nil); err != nil {
		log.Fatalf("Failed to start HTTPS server: %v", err)
	}
}

// loadConfig loads the configuration from a JSON file.
func loadConfig(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("Failed to open config file: %v", err)
		return
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		log.Printf("Failed to decode config file: %v", err)
	}
}

// validateConfig checks for required configuration values and logs warnings or exits if not found.
func validateConfig() {
	missingConfig := false

	if config.WebminURL == "" {
		log.Println("Error: Webmin URL is not set in the configuration.")
		missingConfig = true
	}

	if config.Username == "" {
		log.Println("Error: Username is not set in the configuration.")
		missingConfig = true
	}

	if config.Password == "" {
		log.Println("Error: Password is not set in the configuration.")
		missingConfig = true
	}
	if !config.RequireBorder0 {
		log.Println("⚠️ ⚠️ Warning: Border0 authentication is disabled, you're running an open proxy, this is dangerous.")
	}

	if missingConfig {
		log.Fatal("Please set the required configuration values in config.json.")
	}
}

// authenticateAndSetCookies performs the login to the Webmin server, stores the session cookies, and sets the ProxySID cookie.
func authenticateAndSetCookies(proxyURL *url.URL, r *http.Request, w http.ResponseWriter) (string, error) {
	ProxySID, err := authenticate(proxyURL, r)
	if err != nil {
		return "", err
	}

	// Set the ProxySID cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "ProxySID",
		Value:    ProxySID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
	})

	return ProxySID, nil
}

// authenticate performs the login to the Webmin server and stores the session cookies.
func authenticate(proxyURL *url.URL, r *http.Request) (string, error) {
	jar, _ := cookiejar.New(nil)

	client := &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Get the initial cookies
	initialReq, err := http.NewRequest("GET", fmt.Sprintf("%s/session_login.cgi", proxyURL), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create initial request: %v", err)
	}

	initialResp, err := client.Do(initialReq)
	if err != nil {
		return "", fmt.Errorf("failed to perform initial request: %v", err)
	}
	defer initialResp.Body.Close()
	io.ReadAll(initialResp.Body) // Read and discard the body

	// Step 2: Perform login
	loginURL := fmt.Sprintf("%s/session_login.cgi", proxyURL)
	data := url.Values{
		"user": {config.Username},
		"pass": {config.Password},
		"save": {"1"},
	}
	loginReq, err := http.NewRequest("POST", loginURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create login request: %v", err)
	}
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	loginResp, err := client.Do(loginReq)
	if err != nil {
		return "", fmt.Errorf("failed to perform login request: %v", err)
	}
	defer loginResp.Body.Close()
	body, _ := io.ReadAll(loginResp.Body)

	if loginResp.StatusCode >= 400 {
		return "", fmt.Errorf("failed to authenticate, status code: %d, response: %s", loginResp.StatusCode, string(body))
	}

	// Generate a new ProxySID
	ProxySID, err := generateSessionID()
	if err != nil {
		return "", fmt.Errorf("failed to generate session ID: %v", err)
	}

	// Store the session cookie (SID) in the session store with ProxySID as the key
	sessionStore.Set(ProxySID, jar.Cookies(proxyURL))

	// Check if X-Auth-Email header is present, if so log the value
	if r.Header.Get("X-Auth-Email") != "" {
		log.Printf("New session: Border0 login for: %s from %s", r.Header.Get("X-Auth-Email"), r.Header.Get("X-Real-IP"))
	} else {
		// Anonymous login
		log.Printf("New session: Anonymous login from %s", r.RemoteAddr)
	}
	return ProxySID, nil
}

// generateSessionID generates a new session ID.
func generateSessionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// getSessionLock returns a mutex for the given ProxySID, creating one if necessary.
func getSessionLock(ProxySID string) *sync.Mutex {
	lock, _ := sessionLocks.LoadOrStore(ProxySID, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

// isUpstreamSessionValid checks if the upstream session is still valid by verifying the value of the sid cookie.
func isUpstreamSessionValid(ProxySID string) bool {
	sessionCookies := sessionStore.Get(ProxySID)
	for _, cookie := range sessionCookies {
		if cookie.Name == "sid" && (cookie.Value == "x" || cookie.Value == "") {
			return false
		}
	}
	return true
}

// SessionStore manages session cookies for different clients.
type SessionStore struct {
	sessions map[string][]*http.Cookie
	mutex    sync.Mutex
}

// NewSessionStore creates a new SessionStore.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string][]*http.Cookie),
	}
}

// IsAuthenticated checks if a client is authenticated.
func (s *SessionStore) IsAuthenticated(ProxySID string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	_, ok := s.sessions[ProxySID]
	return ok
}

// Set stores session cookies for a client.
func (s *SessionStore) Set(ProxySID string, cookies []*http.Cookie) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if existingCookies, ok := s.sessions[ProxySID]; ok {
		// Append new cookies to the existing ones, replacing any with the same name
		cookieMap := make(map[string]*http.Cookie)
		for _, cookie := range existingCookies {
			cookieMap[cookie.Name] = cookie
		}
		for _, cookie := range cookies {
			cookieMap[cookie.Name] = cookie
		}
		// Convert the map back to a slice
		mergedCookies := make([]*http.Cookie, 0, len(cookieMap))
		for _, cookie := range cookieMap {
			mergedCookies = append(mergedCookies, cookie)
		}
		s.sessions[ProxySID] = mergedCookies
	} else {
		s.sessions[ProxySID] = cookies
	}
}

// Delete removes session cookies for a client.
func (s *SessionStore) Delete(ProxySID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.sessions, ProxySID)
}

// Get retrieves session cookies for a client.
func (s *SessionStore) Get(ProxySID string) []*http.Cookie {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.sessions[ProxySID]
}

func checkAndGenerateTLSFiles(certFile, keyFile string) {
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)

	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		log.Println("No TLS PEM files found, generating some to get started...")
		generateTLSFiles(certFile, keyFile)
	}
}

// generateTLSFiles generates and writes TLS certificate and key files to disk.
func generateTLSFiles(certFile, keyFile string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Webmin Login Proxy"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()
	log.Println("Written cert.pem")

	keyOut, err := os.Create(keyFile)
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Println("Written key.pem")
}
