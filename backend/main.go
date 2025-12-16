package main

import (
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

var (
	jwtSecret        = []byte(os.Getenv("JWT_SECRET"))
	rsaPrivateKey    *rsa.PrivateKey
	rsaPublicKey     *rsa.PublicKey
	rsaPublicKeyDER  []byte // Store raw DER bytes for algorithm confusion attack
	tokenBlacklist   = make(map[string]time.Time)
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Admin    bool   `json:"admin"`
	jwt.RegisteredClaims
}

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Token   string      `json:"token,omitempty"`
}

func init() {
	loadRSAKeys()
}

func loadRSAKeys() {
	privateKeyPath := os.Getenv("RSA_PRIVATE_KEY_PATH")
	publicKeyPath := os.Getenv("RSA_PUBLIC_KEY_PATH")

	privateKeyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Printf("Warning: Could not load private key: %v", err)
		return
	}

	publicKeyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		log.Printf("Warning: Could not load public key: %v", err)
		return
	}

	privateBlock, _ := pem.Decode(privateKeyData)
	if privateBlock == nil {
		log.Println("Warning: Failed to decode private key PEM")
		return
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	if err != nil {
		log.Printf("Warning: Failed to parse private key: %v", err)
		return
	}
	rsaPrivateKey = privateKey

	publicBlock, _ := pem.Decode(publicKeyData)
	if publicBlock == nil {
		log.Println("Warning: Failed to decode public key PEM")
		return
	}

	// Store the raw DER bytes from the PEM file for algorithm confusion attack
	// This is what Python uses when reading the public key file
	rsaPublicKeyDER = publicBlock.Bytes

	pubInterface, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		log.Printf("Warning: Failed to parse public key: %v", err)
		return
	}

	var ok bool
	rsaPublicKey, ok = pubInterface.(*rsa.PublicKey)
	if !ok {
		log.Println("Warning: Not an RSA public key")
	}

	log.Printf("RSA keys loaded successfully. Public key DER length: %d bytes", len(rsaPublicKeyDER))
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/login/vulnerable", loginVulnerable).Methods("POST")
	r.HandleFunc("/login/secure", loginSecure).Methods("POST")
	r.HandleFunc("/vulnerable/none-algorithm", vulnerableNoneAlgorithm).Methods("GET")
	r.HandleFunc("/vulnerable/algorithm-confusion", vulnerableAlgorithmConfusion).Methods("GET")
	r.HandleFunc("/vulnerable/timing-attack", vulnerableTimingAttack).Methods("POST")
	r.HandleFunc("/vulnerable/no-expiry", vulnerableNoExpiry).Methods("GET")
	r.HandleFunc("/secure/protected", secureProtected).Methods("GET")
	r.HandleFunc("/secure/refresh", secureRefresh).Methods("POST")
	r.HandleFunc("/secure/logout", secureLogout).Methods("POST")
	r.HandleFunc("/tools/tamper-token", tamperToken).Methods("POST")
	r.HandleFunc("/tools/crack-weak-secret", crackWeakSecret).Methods("POST")
	r.HandleFunc("/docs", serveDocs).Methods("GET")
	r.HandleFunc("/health", healthCheck).Methods("GET")

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	handler := c.Handler(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func loginVulnerable(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		sendError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Same credential validation as secure endpoint
	validUsers := map[string]string{
		"admin": "secure_password",
		"user":  "user_password",
	}

	expectedPassword, userExists := validUsers[creds.Username]
	if !userExists || expectedPassword != creds.Password {
		sendError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	claims := Claims{
		Username: creds.Username,
		Role:     "user",
		Admin:    creds.Username == "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "jwt-playground-vulnerable",
		},
	}

	// VULNERABLE: Uses RS256, susceptible to algorithm confusion attack
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(rsaPrivateKey)
	if err != nil {
		sendError(w, "Error creating token", http.StatusInternalServerError)
		return
	}

	sendSuccess(w, "Login successful", map[string]interface{}{
		"token":    tokenString,
		"username": creds.Username,
		"role":     claims.Role,
		"admin":    claims.Admin,
	})
}

func loginSecure(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		sendError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Secure: validate credentials (hardcoded for demo)
	validUsers := map[string]string{
		"admin":    "secure_password",
		"testuser": "user_password",
	}

	expectedPassword, userExists := validUsers[creds.Username]
	if !userExists || expectedPassword != creds.Password {
		sendError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	claims := Claims{
		Username: creds.Username,
		Role:     "user",
		Admin:    creds.Username == "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "jwt-playground-secure",
			Subject:   creds.Username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		sendError(w, "Error creating token", http.StatusInternalServerError)
		return
	}

	sendSuccess(w, "Login successful", map[string]interface{}{
		"token":     tokenString,
		"username":  creds.Username,
		"role":      claims.Role,
		"admin":     claims.Admin,
		"expiresIn": "15m",
	})
}

func vulnerableNoneAlgorithm(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		sendError(w, "No token provided", http.StatusUnauthorized)
		return
	}

	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, &Claims{})
	if err != nil {
		sendError(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		sendError(w, "Invalid claims", http.StatusUnauthorized)
		return
	}

	sendSuccess(w, "Access granted (VULNERABLE: accepted 'none' algorithm)", map[string]interface{}{
		"username": claims.Username,
		"role":     claims.Role,
		"admin":    claims.Admin,
		"warning":  "This endpoint accepts tokens with 'none' algorithm!",
	})
}

func vulnerableAlgorithmConfusion(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		sendError(w, "No token provided", http.StatusUnauthorized)
		return
	}

	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

	// VULNERABLE: Accepts both RS256 and HS256
	// For HS256, uses the raw public key DER bytes as the HMAC secret
	// This allows an attacker who knows the public key to forge tokens
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA:
			return rsaPublicKey, nil
		case *jwt.SigningMethodHMAC:
			// VULNERABILITY: Use raw DER bytes from PEM file as HMAC secret
			// Attacker can read public.pem, extract DER bytes, and sign with HMAC
			return rsaPublicKeyDER, nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
	})

	if err != nil {
		sendError(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		sendError(w, "Invalid claims", http.StatusUnauthorized)
		return
	}

	sendSuccess(w, "Access granted (VULNERABLE: algorithm confusion)", map[string]interface{}{
		"username": claims.Username,
		"role":     claims.Role,
		"admin":    claims.Admin,
		"warning":  "This endpoint is vulnerable to RS256->HS256 algorithm confusion!",
	})
}

func vulnerableTimingAttack(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Secret string `json:"secret"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// VULNERABLE: byte-by-byte comparison
	expectedSecret := string(jwtSecret)
	for i := 0; i < len(payload.Secret) && i < len(expectedSecret); i++ {
		if payload.Secret[i] != expectedSecret[i] {
			time.Sleep(time.Microsecond * 100) // Exaggerated timing difference
			sendError(w, "Invalid secret", http.StatusUnauthorized)
			return
		}
		time.Sleep(time.Microsecond * 100)
	}

	if len(payload.Secret) != len(expectedSecret) {
		sendError(w, "Invalid secret", http.StatusUnauthorized)
		return
	}

	sendSuccess(w, "Secret verified (VULNERABLE: timing attack possible)", map[string]interface{}{
		"warning": "This endpoint leaks timing information!",
	})
}

func vulnerableNoExpiry(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		sendError(w, "No token provided", http.StatusUnauthorized)
		return
	}

	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	}, jwt.WithoutClaimsValidation())

	if err != nil {
		sendError(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		sendError(w, "Invalid claims", http.StatusUnauthorized)
		return
	}

	sendSuccess(w, "Access granted (VULNERABLE: no expiry check)", map[string]interface{}{
		"username": claims.Username,
		"role":     claims.Role,
		"admin":    claims.Admin,
		"warning":  "This endpoint doesn't validate token expiration!",
	})
}

func secureProtected(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		sendError(w, "No token provided", http.StatusUnauthorized)
		return
	}

	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

	if _, blacklisted := tokenBlacklist[tokenString]; blacklisted {
		sendError(w, "Token has been revoked", http.StatusUnauthorized)
		return
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		sendError(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		sendError(w, "Invalid claims", http.StatusUnauthorized)
		return
	}

	expectedIssuer := "jwt-playground-secure"
	if subtle.ConstantTimeCompare([]byte(claims.Issuer), []byte(expectedIssuer)) != 1 {
		sendError(w, "Invalid issuer", http.StatusUnauthorized)
		return
	}

	sendSuccess(w, "Access granted (SECURE endpoint)", map[string]interface{}{
		"username": claims.Username,
		"role":     claims.Role,
		"admin":    claims.Admin,
		"expiresAt": claims.ExpiresAt.Time,
		"protections": []string{
			"Algorithm whitelist",
			"Expiry validation",
			"Token blacklist",
			"Constant-time comparison",
			"Issuer validation",
		},
	})
}

func secureRefresh(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		sendError(w, "No token provided", http.StatusUnauthorized)
		return
	}

	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil {
		sendError(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	oldClaims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		sendError(w, "Invalid claims", http.StatusUnauthorized)
		return
	}

	tokenBlacklist[tokenString] = time.Now()

	newClaims := Claims{
		Username: oldClaims.Username,
		Role:     oldClaims.Role,
		Admin:    oldClaims.Admin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "jwt-playground-secure",
			Subject:   oldClaims.Username,
		},
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	newTokenString, err := newToken.SignedString(jwtSecret)
	if err != nil {
		sendError(w, "Error creating token", http.StatusInternalServerError)
		return
	}

	sendSuccess(w, "Token refreshed", map[string]interface{}{
		"token":     newTokenString,
		"expiresIn": "15m",
	})
}

func secureLogout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		sendError(w, "No token provided", http.StatusUnauthorized)
		return
	}

	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
	tokenBlacklist[tokenString] = time.Now()

	sendSuccess(w, "Logged out successfully", nil)
}

func tamperToken(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Token  string                 `json:"token"`
		Claims map[string]interface{} `json:"claims"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	token, _, err := jwt.NewParser().ParseUnverified(payload.Token, jwt.MapClaims{})
	if err != nil {
		sendError(w, "Invalid token", http.StatusBadRequest)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		sendError(w, "Invalid claims", http.StatusBadRequest)
		return
	}

	for k, v := range payload.Claims {
		claims[k] = v
	}

	tamperedToken := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tamperedString, _ := tamperedToken.SignedString(jwt.UnsafeAllowNoneSignatureType)

	sendSuccess(w, "Token tampered", map[string]interface{}{
		"original": payload.Token,
		"tampered": tamperedString,
		"claims":   claims,
		"note":     "This token uses 'none' algorithm and is unsigned",
	})
}

func crackWeakSecret(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Token    string   `json:"token"`
		Wordlist []string `json:"wordlist"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_, _, err := jwt.NewParser().ParseUnverified(payload.Token, jwt.MapClaims{})
	if err != nil {
		sendError(w, "Invalid token", http.StatusBadRequest)
		return
	}

	for _, secret := range payload.Wordlist {
		testToken, err := jwt.ParseWithClaims(payload.Token, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		})

		if err == nil && testToken.Valid {
			sendSuccess(w, "Weak secret found!", map[string]interface{}{
				"secret": secret,
				"claims": testToken.Claims,
				"note":   "This demonstrates why strong secrets are critical",
			})
			return
		}
	}

	sendSuccess(w, "No weak secret found", map[string]interface{}{
		"tried": len(payload.Wordlist),
		"note":  "Secret appears strong against this wordlist",
	})
}

func serveDocs(w http.ResponseWriter, r *http.Request) {
	docs := map[string]interface{}{
		"title": "JWT Attack & Defense Playground API",
		"endpoints": map[string]interface{}{
			"authentication": []map[string]string{
				{"POST /login/vulnerable": "Login with vulnerable JWT (RS256, accepts 'none')"},
				{"POST /login/secure": "Login with secure JWT (HS256, proper validation)"},
			},
			"vulnerable": []map[string]string{
				{"GET /vulnerable/none-algorithm": "Accepts tokens with 'none' algorithm"},
				{"GET /vulnerable/algorithm-confusion": "Vulnerable to RS256->HS256 confusion"},
				{"POST /vulnerable/timing-attack": "Timing side-channel vulnerability"},
				{"GET /vulnerable/no-expiry": "Doesn't validate token expiration"},
			},
			"secure": []map[string]string{
				{"GET /secure/protected": "Properly secured endpoint"},
				{"POST /secure/refresh": "Secure token refresh with blacklist"},
				{"POST /secure/logout": "Secure logout (blacklist token)"},
			},
			"tools": []map[string]string{
				{"POST /tools/tamper-token": "Tamper with token claims"},
				{"POST /tools/crack-weak-secret": "Demonstrate weak secret cracking"},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(docs)
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	sendSuccess(w, "Server is healthy", map[string]interface{}{
		"status": "ok",
		"time":   time.Now(),
	})
}

func sendSuccess(w http.ResponseWriter, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: message,
		Data:    data,
	})
}

func sendError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{
		Success: false,
		Message: message,
	})
}
