// Command phpscan-web is the online scanner. Anyone can check a website: the
// check is one ordinary page request, the same as a browser visit, so it needs
// no proof of ownership. It only connects to public IP addresses on the
// standard web ports, so it can't be used to probe internal networks or ports.
package main

import (
	"cmp"
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"phpscan/check"
)

//go:embed index.html
var page string

func main() {
	tmpl := template.Must(template.New("page").Parse(page))
	client := check.NewClient(10*time.Second, check.IsPublic)

	// shortcut: one shared limit per instance (burst 30, then 1 scan every 2s); add per-IP limits at the platform or a CDN before a public launch.
	tokens := make(chan struct{}, 30)
	for range cap(tokens) {
		tokens <- struct{}{}
	}
	go func() {
		for range time.Tick(2 * time.Second) {
			select {
			case tokens <- struct{}{}:
			default:
			}
		}
	}()

	http.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl.Execute(w, map[string]string{"Repo": check.RepoURL, "Contact": check.ContactURL})
	})
	http.HandleFunc("GET /api/scan", func(w http.ResponseWriter, r *http.Request) {
		target, err := parseTarget(r.URL.Query().Get("url"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		select {
		case <-tokens:
		default:
			http.Error(w, "Too many checks right now. Please try again in a minute.", http.StatusTooManyRequests)
			return
		}
		writeJSON(w, check.Check(r.Context(), client, target))
	})

	addr := ":" + cmp.Or(os.Getenv("PORT"), "8080")
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// parseTarget accepts a website address as people type it, adding https:// when missing.
func parseTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", errors.New("Enter a website address, for example www.example.com")
	}
	if p := u.Port(); p != "" && p != "80" && p != "443" {
		return "", errors.New("Only standard web ports (80 and 443) can be checked")
	}
	return u.String(), nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
