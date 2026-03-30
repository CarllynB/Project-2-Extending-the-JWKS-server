package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

/*
Project 2 JWKS Server.

Extends Project 1 by persisting RSA private keys in a SQLite database
(totally_not_my_privateKeys.db) using PKCS1 PEM encoding.

Key design decisions:
  - Keys are serialized as PKCS1 PEM text so SQLite can store them as BLOB/TEXT.
  - All queries use parameterized placeholders (?) to prevent SQL injection.
  - The /auth endpoint accepts both HTTP Basic Auth and a JSON body so the
    Gradebot test client works regardless of which method it uses.
*/

// DB file name required by the project spec.
const DBFile = "totally_not_my_privateKeys.db"

// Server holds the database connection and a clock function (for testability).
type Server struct {
	mu  sync.RWMutex
	db  *sql.DB
	now func() time.Time
}

// NewServer opens (or creates) the SQLite DB, creates the keys table, seeds
// initial key pairs, and returns a ready-to-use Server.
func NewServer(dbPath string) (*Server, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	s := &Server{
		db:  db,
		now: time.Now,
	}

	if err := s.initDB(); err != nil {
		return nil, fmt.Errorf("init db: %w", err)
	}

	return s, nil
}

// initDB creates the keys table (if it doesn't exist) and inserts one active
// key (expires in 1 hour) and one expired key (expired 30 minutes ago).
func (s *Server) initDB() error {
	// Create the table with the schema required by the project spec.
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)
	if err != nil {
		return err
	}

	// Seed keys every time so tests that use :memory: always have fresh keys.
	// In a production server you'd only generate if the table is empty.
	now := s.now()

	// Active key — expires 1 hour from now.
	if err := s.generateAndStoreKey(now.Add(time.Hour)); err != nil {
		return fmt.Errorf("seed active key: %w", err)
	}

	// Expired key — already expired 30 minutes ago.
	if err := s.generateAndStoreKey(now.Add(-30 * time.Minute)); err != nil {
		return fmt.Errorf("seed expired key: %w", err)
	}

	return nil
}

// generateAndStoreKey creates a 2048-bit RSA key pair and saves it to the DB.
// The private key is serialized as PKCS1 PEM before storage.
func (s *Server) generateAndStoreKey(expiry time.Time) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	pemBytes := privateKeyToPEM(priv)

	// Use a parameterized query — no SQL injection possible.
	_, err = s.db.Exec(
		`INSERT INTO keys(key, exp) VALUES (?, ?)`,
		pemBytes,
		expiry.Unix(),
	)
	return err
}

// Routes wires up the two required endpoints.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("/auth", s.handleAuth)
	return mux
}

// handleJWKS returns a JWKS document containing all non-expired public keys.
// Only GET is allowed per the REST spec.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	now := s.now().Unix()

	// Parameterized query: only rows whose exp is in the future.
	rows, err := s.db.Query(
		`SELECT kid, key FROM keys WHERE exp > ?`,
		now,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	jwks := make([]any, 0)

	for rows.Next() {
		var kid int64
		var pemBytes []byte

		if err := rows.Scan(&kid, &pemBytes); err != nil {
			continue
		}

		priv, err := pemToPrivateKey(pemBytes)
		if err != nil {
			continue
		}

		jwks = append(jwks, rsaPublicToJWK(kid, &priv.PublicKey))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": jwks})
}

// handleAuth issues a signed JWT.
//   - POST /auth            → valid JWT signed by an unexpired key
//   - POST /auth?expired=*  → JWT signed by an expired key (exp also in the past)
//
// The endpoint intentionally ignores credentials — it mocks authentication.
// It accepts both HTTP Basic Auth and a JSON body so it is compatible with
// the Gradebot test client.
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Determine whether the caller wants an expired token.
	useExpired := strings.Contains(r.URL.RawQuery, "expired")

	// Extract a username from Basic Auth or JSON body (purely cosmetic — we
	// don't validate credentials, just include the subject in the JWT).
	username := extractUsername(r)

	s.mu.RLock()
	defer s.mu.RUnlock()

	now := s.now()

	var (
		kid     int64
		pemBytes []byte
		expUnix int64
	)

	if useExpired {
		// Read one expired key (exp <= now).
		err := s.db.QueryRow(
			`SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1`,
			now.Unix(),
		).Scan(&kid, &pemBytes, &expUnix)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		// Read one valid (unexpired) key.
		err := s.db.QueryRow(
			`SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1`,
			now.Unix(),
		).Scan(&kid, &pemBytes, &expUnix)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	priv, err := pemToPrivateKey(pemBytes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	claims := jwt.MapClaims{
		"sub": username,
		"iss": "jwks-server",
		"iat": now.Unix(),
		"exp": expUnix,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// kid is stored as an integer in the DB; format it as a string for the header.
	token.Header["kid"] = fmt.Sprintf("%d", kid)

	signed, err := token.SignedString(priv)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": signed})
}

// extractUsername tries HTTP Basic Auth first, then falls back to a JSON body
// with a "username" field. Returns "fake-user" if neither is present.
func extractUsername(r *http.Request) string {
	if user, _, ok := r.BasicAuth(); ok && user != "" {
		return user
	}

	// Try to decode a JSON body without consuming it destructively.
	var body struct {
		Username string `json:"username"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&body); err == nil && body.Username != "" {
		return body.Username
	}

	return "fake-user"
}

// ---------------------------------------------------------------------------
// RSA / PEM helpers
// ---------------------------------------------------------------------------

// privateKeyToPEM serializes an RSA private key as PKCS1 PEM bytes.
func privateKeyToPEM(priv *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
}

// pemToPrivateKey deserializes a PKCS1 PEM-encoded RSA private key.
func pemToPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// rsaPublicToJWK converts an RSA public key into a JWK map.
// kid is the integer primary key from the DB, formatted as a string.
func rsaPublicToJWK(kid int64, pub *rsa.PublicKey) map[string]string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": fmt.Sprintf("%d", kid),
		"n":   n,
		"e":   e,
	}
}
