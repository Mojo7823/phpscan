// Command phpscan-web is the online scanner. It checks only sites whose owner
// has proved control of the domain with a DNS TXT record, and it only connects
// to public IP addresses.
package main

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"phpscan/check"
)

//go:embed index.html
var page []byte

func main() {
	secret := os.Getenv("PHPSCAN_SECRET")
	if len(secret) < 32 {
		log.Fatal("set PHPSCAN_SECRET to a random string of at least 32 characters")
	}
	client := check.NewClient(10*time.Second, check.IsPublic)

	http.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	})
	// shortcut: no rate limit; put one in front (platform or proxy) before opening this to the public.
	http.HandleFunc("GET /api/token", func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.URL.Query().Get("host"))
		if host == "" || len(host) > 253 {
			http.Error(w, "missing or invalid host", http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]string{"type": "TXT", "name": "_phpscan." + host, "value": token(secret, host)})
	})
	http.HandleFunc("GET /api/scan", func(w http.ResponseWriter, r *http.Request) {
		u, err := url.Parse(r.URL.Query().Get("url"))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			http.Error(w, "url must be a full http:// or https:// address", http.StatusBadRequest)
			return
		}
		host := strings.ToLower(u.Hostname())
		if !verified(r.Context(), secret, host) {
			http.Error(w, "domain not verified: add the TXT record from /api/token?host="+host+" and try again", http.StatusForbidden)
			return
		}
		writeJSON(w, check.Check(r.Context(), client, u.String()))
	})

	addr := ":" + cmp.Or(os.Getenv("PORT"), "8080")
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// token is stateless: the same secret and host always give the same value, so no database is needed.
func token(secret, host string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(host))
	return "phpscan-verify=" + hex.EncodeToString(m.Sum(nil))[:32]
}

func verified(ctx context.Context, secret, host string) bool {
	records, err := net.DefaultResolver.LookupTXT(ctx, "_phpscan."+host)
	if err != nil {
		return false
	}
	want := []byte(token(secret, host))
	for _, rec := range records {
		if hmac.Equal([]byte(rec), want) {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
