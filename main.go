package main
// test

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
)

type Config struct {
	WebminURL  string `json:"webminURL"`
	ListenAddr string `json:"listenAddr"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}


var (
	config       Config
	sessionStore = NewSessionStore()
	sessionLocks = &sync.Map{}
)

func main() {
	// Load configuration
	loadConfig("config.json")

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

			if ProxySID == "" || !sessionStore.IsAuthenticated(ProxySID) {
				var err error
				ProxySID, err = authenticate(proxyURL, r)
				if err != nil {
					http.Error(w, "Failed to authenticate", http.StatusUnauthorized)
					log.Printf("Authentication failed: %v", err)
					return
				}

				// Set the ProxySID cookie
				http.SetCookie(w, &http.Cookie{
					Name:     "ProxySID",
					Value:    ProxySID,
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
				})
			}
		}

		// Add session cookies to the request
		sessionCookies := sessionStore.Get(ProxySID)
		for _, cookie := range sessionCookies {
			r.AddCookie(cookie)
		}

		// Serve the request using the proxy
		proxy.ServeHTTP(w, r)
	})

	log.Printf("Starting proxy server on %s", config.ListenAddr)
	if err := http.ListenAndServeTLS(config.ListenAddr, "cert.pem", "key.pem", nil); err != nil {
		log.Fatalf("Failed to start HTTPS server: %v", err)
	}
}

// loadConfig loads the configuration from a JSON file.
func loadConfig(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		log.Fatalf("Failed to decode config file: %v", err)
	}
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
		log.Printf("New session: Anonymous login from %s", r.Header.Get("X-Real-IP"))
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
	s.sessions[ProxySID] = cookies
}

// Get retrieves session cookies for a client.
func (s *SessionStore) Get(ProxySID string) []*http.Cookie {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.sessions[ProxySID]
}

