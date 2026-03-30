package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

/*
Tests cover every rubric item:
  - JWKS returns only unexpired keys
  - /auth returns a valid JWT with the correct kid header
  - /auth?expired returns a token signed by an expired key (and is expired)
  - Correct HTTP method enforcement (405 for wrong methods)
  - Both HTTP Basic Auth and JSON body are accepted by /auth
  - SQLite is queried correctly (no keys returned after all expire)
*/

// newTestServer creates a fresh in-memory server for each test.
// Using ":memory:" keeps tests isolated and fast.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(":memory:")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

// TestJWKSOnlyServesUnexpiredKeys verifies the JWKS endpoint returns exactly
// one key (the active one) and does NOT include the expired key.
func TestJWKSOnlyServesUnexpiredKeys(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(body.Keys) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %d", len(body.Keys))
	}

	// The returned key must have the required JWK fields.
	key := body.Keys[0]
	for _, field := range []string{"kid", "kty", "alg", "use", "n", "e"} {
		if key[field] == nil || key[field] == "" {
			t.Errorf("JWK missing field %q", field)
		}
	}
}

// TestJWKSEmptyWhenAllExpired confirms the JWKS returns zero keys when we
// artificially advance the clock past all key expirations.
func TestJWKSEmptyWhenAllExpired(t *testing.T) {
	s := newTestServer(t)
	// Move clock 2 hours into the future so even the active key is expired.
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)

	if len(body.Keys) != 0 {
		t.Fatalf("expected 0 keys after all expire, got %d", len(body.Keys))
	}
}

// TestAuthReturnsValidJWT verifies POST /auth issues a valid RS256 JWT that
// can be verified with the public key from the JWKS.
func TestAuthReturnsValidJWT(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token")
	}

	// Parse and verify the token using the DB-backed public key.
	parsed, err := jwt.Parse(resp.Token, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Fatalf("unexpected signing method: %v", token.Header["alg"])
		}
		kid := token.Header["kid"].(string)
		// Re-query the DB for this kid to get the public key.
		var pemBytes []byte
		if err := s.db.QueryRow(`SELECT key FROM keys WHERE kid = ?`, kid).Scan(&pemBytes); err != nil {
			return nil, err
		}
		priv, err := pemToPrivateKey(pemBytes)
		if err != nil {
			return nil, err
		}
		return &priv.PublicKey, nil
	})

	if err != nil || !parsed.Valid {
		t.Fatalf("token should be valid: %v", err)
	}
}

// TestAuthExpiredReturnsExpiredToken verifies POST /auth?expired issues a JWT
// that is already expired (signed with the expired key).
func TestAuthExpiredReturnsExpiredToken(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	// Parsing should fail because exp is in the past.
	parsed, err := jwt.Parse(resp.Token, func(token *jwt.Token) (any, error) {
		kid := token.Header["kid"].(string)
		var pemBytes []byte
		if scanErr := s.db.QueryRow(`SELECT key FROM keys WHERE kid = ?`, kid).Scan(&pemBytes); scanErr != nil {
			return nil, scanErr
		}
		priv, pemErr := pemToPrivateKey(pemBytes)
		if pemErr != nil {
			return nil, pemErr
		}
		return &priv.PublicKey, nil
	})

	if err == nil && parsed != nil && parsed.Valid {
		t.Fatal("expected token to be expired/invalid")
	}
}

// TestAuthAcceptsBasicAuth confirms /auth works with HTTP Basic Auth credentials.
func TestAuthAcceptsBasicAuth(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	req.SetBasicAuth("userABC", "password123")
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with Basic Auth, got %d", rr.Code)
	}

	var resp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Token == "" {
		t.Fatal("expected non-empty token with Basic Auth")
	}
}

// TestAuthAcceptsJSONBody confirms /auth works with a JSON credentials payload.
func TestAuthAcceptsJSONBody(t *testing.T) {
	s := newTestServer(t)

	body := strings.NewReader(`{"username":"userABC","password":"password123"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with JSON body, got %d", rr.Code)
	}

	var resp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Token == "" {
		t.Fatal("expected non-empty token with JSON body")
	}
}

// TestMethodNotAllowed checks that wrong HTTP methods return 405.
func TestMethodNotAllowed(t *testing.T) {
	s := newTestServer(t)

	// GET on /auth should be rejected.
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /auth: expected 405, got %d", rr.Code)
	}

	// POST on /.well-known/jwks.json should be rejected.
	req2 := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", strings.NewReader(""))
	rr2 := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /jwks: expected 405, got %d", rr2.Code)
	}
}

// TestPEMRoundTrip verifies that a key serialized to PEM and back is identical.
func TestPEMRoundTrip(t *testing.T) {
	s := newTestServer(t)

	var pemBytes []byte
	if err := s.db.QueryRow(`SELECT key FROM keys LIMIT 1`).Scan(&pemBytes); err != nil {
		t.Fatalf("query: %v", err)
	}

	priv, err := pemToPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("pemToPrivateKey: %v", err)
	}

	roundTripped := privateKeyToPEM(priv)
	priv2, err := pemToPrivateKey(roundTripped)
	if err != nil {
		t.Fatalf("second pemToPrivateKey: %v", err)
	}

	if priv.N.Cmp(priv2.N) != 0 {
		t.Fatal("round-tripped key does not match original")
	}
}

// TestRsaPublicToJWK verifies the JWK helper produces the required fields.
func TestRsaPublicToJWK(t *testing.T) {
	s := newTestServer(t)

	var pemBytes []byte
	var kid int64
	if err := s.db.QueryRow(`SELECT kid, key FROM keys LIMIT 1`).Scan(&kid, &pemBytes); err != nil {
		t.Fatalf("query: %v", err)
	}

	priv, _ := pemToPrivateKey(pemBytes)
	jwk := rsaPublicToJWK(kid, &priv.PublicKey)

	for _, field := range []string{"kty", "use", "alg", "kid", "n", "e"} {
		if jwk[field] == "" {
			t.Errorf("JWK missing required field %q", field)
		}
	}
}

// TestPemToPrivateKeyBadInput ensures pemToPrivateKey returns an error for
// invalid/non-PEM data, covering the error branch.
func TestPemToPrivateKeyBadInput(t *testing.T) {
	_, err := pemToPrivateKey([]byte("this is not a pem block"))
	if err == nil {
		t.Fatal("expected error for bad PEM input, got nil")
	}
}

// TestAuthJWTClaimsContent checks that the JWT payload contains the expected
// standard claims (sub, iss, iat, exp).
func TestAuthJWTClaimsContent(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	req.SetBasicAuth("userABC", "password123")
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	var resp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	// Parse without verification to inspect claims directly.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(resp.Token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims not MapClaims")
	}
	for _, field := range []string{"sub", "iss", "iat", "exp"} {
		if claims[field] == nil {
			t.Errorf("JWT claim %q is missing", field)
		}
	}
	if claims["sub"] != "userABC" {
		t.Errorf("expected sub=userABC, got %v", claims["sub"])
	}
}

// TestExtractUsernameDefaultFallback verifies that a request with no credentials
// and no parseable JSON body falls back to "fake-user" as the subject.
func TestExtractUsernameDefaultFallback(t *testing.T) {
	s := newTestServer(t)

	// No auth header, body is not valid JSON.
	req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader("not-json"))
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(resp.Token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}
	claims := token.Claims.(jwt.MapClaims)
	if claims["sub"] != "fake-user" {
		t.Errorf("expected sub=fake-user, got %v", claims["sub"])
	}
}

// TestAuthKidMatchesDB ensures the kid in the JWT header corresponds to a real
// row in the keys table.
func TestAuthKidMatchesDB(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	var resp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(resp.Token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		t.Fatal("kid header missing or empty")
	}

	var count int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM keys WHERE kid = ?`, kid).Scan(&count)
	if count != 1 {
		t.Errorf("kid %q not found in DB (count=%d)", kid, count)
	}
}

// TestAuthReturns500WhenNoValidKey covers the 500 error branch in handleAuth
// when no unexpired key exists in the DB.
func TestAuthReturns500WhenNoValidKey(t *testing.T) {
	s := newTestServer(t)

	// Delete all keys so the unexpired query returns nothing.
	if _, err := s.db.Exec(`DELETE FROM keys`); err != nil {
		t.Fatalf("delete keys: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 with no keys, got %d", rr.Code)
	}
}

// TestAuthReturns500WhenNoExpiredKey covers the 500 error branch in handleAuth
// when no expired key exists in the DB.
func TestAuthReturns500WhenNoExpiredKey(t *testing.T) {
	s := newTestServer(t)

	// Delete only the expired key (exp <= now), leaving the active one.
	now := s.now().Unix()
	if _, err := s.db.Exec(`DELETE FROM keys WHERE exp <= ?`, now); err != nil {
		t.Fatalf("delete expired keys: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 with no expired keys, got %d", rr.Code)
	}
}

// TestJWKSSkipsBadPEMRows confirms the JWKS handler skips rows whose PEM is
// corrupt, covering the pemToPrivateKey error path inside the rows loop.
func TestJWKSSkipsBadPEMRows(t *testing.T) {
	s := newTestServer(t)

	// Insert a row with garbage PEM so scan succeeds but deserialization fails.
	future := s.now().Add(2 * time.Hour).Unix()
	if _, err := s.db.Exec(`INSERT INTO keys(key, exp) VALUES (?, ?)`, []byte("bad-pem"), future); err != nil {
		t.Fatalf("insert bad row: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Should still return the one valid key — bad row is silently skipped.
	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if len(body.Keys) != 1 {
		t.Errorf("expected 1 valid key, got %d", len(body.Keys))
	}
}

// TestDeleteMethodNotAllowed covers additional HTTP verbs on both endpoints.
func TestDeleteMethodNotAllowed(t *testing.T) {
	s := newTestServer(t)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodDelete, "/auth"},
		{http.MethodPut, "/auth"},
		{http.MethodDelete, "/.well-known/jwks.json"},
		{http.MethodPut, "/.well-known/jwks.json"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rr := httptest.NewRecorder()
		s.Routes().ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: expected 405, got %d", tc.method, tc.path, rr.Code)
		}
	}
}
