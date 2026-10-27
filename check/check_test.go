package check

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"
)

func TestAnalyze(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		path    string
		body    string
		want    Status
		product bool
	}{
		{"old branch", map[string]string{"X-Powered-By": "PHP/7.4.33"}, "/", "", Vulnerable, false},
		{"supported but unpatched", map[string]string{"X-Powered-By": "PHP/8.3.10"}, "/", "", Vulnerable, false},
		{"patched", map[string]string{"X-Powered-By": "PHP/8.3.36"}, "/", "", Patched, false},
		{"patched distro build", map[string]string{"X-Powered-By": "PHP/8.4.27-1+deb13u1"}, "/", "", Patched, false},
		{"distro may backport", map[string]string{"X-Powered-By": "PHP/8.1.2-1ubuntu2.18"}, "/", "", Likely, false},
		{"newer branch", map[string]string{"X-Powered-By": "PHP/8.6.0"}, "/", "", Unknown, false},
		{"server header", map[string]string{"Server": "Apache/2.4.41 (Ubuntu) PHP/7.4.3"}, "/", "", Vulnerable, false},
		{"hidden version", map[string]string{"Set-Cookie": "PHPSESSID=abc; path=/"}, "/", "", Unknown, false},
		{"router login page", nil, "/", `<form action="login.php">`, Unknown, false},
		{"pan-os", nil, "/php/login.php", "", Unknown, true},
		{"no php", map[string]string{"Server": "nginx"}, "/", "<html>hi</html>", NotDetected, false},
	}
	for _, c := range cases {
		h := http.Header{}
		for k, v := range c.headers {
			h.Set(k, v)
		}
		r := analyze(h, &url.URL{Path: c.path}, []byte(c.body))
		if r.Status != c.want || (r.Product != "") != c.product {
			t.Errorf("%s: got status %s product %q, want %s", c.name, r.Status, r.Product, c.want)
		}
		if (r.Contact != "") != (c.want == Vulnerable || c.want == Likely || c.want == Unknown) {
			t.Errorf("%s: contact %q for status %s", c.name, r.Contact, r.Status)
		}
	}
}

func TestIsPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"10.0.0.1": false, "192.168.1.1": false, "172.16.0.1": false, "127.0.0.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "0.0.0.1": false,
		"::1": false, "fd00::1": false, "::ffff:10.0.0.1": false, "64:ff9b::a00:1": false,
	} {
		if got := IsPublic(netip.MustParseAddr(addr)); got != want {
			t.Errorf("IsPublic(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.20")
	}))
	defer srv.Close()

	all := func(netip.Addr) bool { return true }
	if r := Check(context.Background(), NewClient(time.Second, all), srv.URL); r.Status != Vulnerable || r.PHPVersion != "8.2.20" {
		t.Errorf("got %+v, want vulnerable 8.2.20", r)
	}
	// The server is on 127.0.0.1, which the public-only client must refuse.
	if r := Check(context.Background(), NewClient(time.Second, IsPublic), srv.URL); r.Status != Unreachable {
		t.Errorf("public-only client reached loopback: %+v", r)
	}
}
