// Package check finds the PHP version behind a URL with one ordinary GET request
// and compares it with the PHP2Shell (CVE-2026-109618, CVE-2026-109619) fixed
// releases. It never sends exploit payloads.
package check

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	RepoURL    = "https://github.com/Mojo7823/phpscan"
	ContactURL = "https://example.com/contact"         // set to your company's support page
)

// First fixed release per supported branch (PHP security release, 2026-10-21).
var fixed = map[string]int{"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}

type Status string

const (
	Vulnerable  Status = "vulnerable"
	Likely      Status = "likely_vulnerable"
	Unknown     Status = "unknown"
	Patched     Status = "patched"
	NotDetected Status = "no_php_detected"
	Unreachable Status = "unreachable"
)

var advice = map[Status]string{
	Vulnerable: "Upgrade PHP to 8.2.35, 8.3.36, 8.4.27, 8.5.12 or later. PHP 8.1 and older get no fixes, so move to a supported version. " +
		"Until then, keep this service away from untrusted networks and limit request size, input fields and nesting depth at the web server or reverse proxy.",
	Likely: "This PHP build comes from a Linux distribution, which may have backported the fix without changing the version number. " +
		"Check your distribution's security tracker for CVE-2026-109618 and CVE-2026-109619 and install pending PHP updates.",
	Unknown:     "PHP is in use but its version is hidden. Run `php -v` on the server, or ask the device vendor whether its firmware includes the PHP2Shell fix.",
	Patched:     "This PHP version includes the PHP2Shell fix. Keep it updated.",
	NotDetected: "No sign of PHP in this response. That does not prove PHP isn't used elsewhere on this host.",
	Unreachable: "The page could not be loaded.",
}

// Appliances that vendors list as affected. They hide their PHP version, so we
// match their login pages instead. Best effort: extend as vendors publish.
var products = []struct{ marker, name, advisory string }{
	{"/php/login.php", "Palo Alto Networks PAN-OS management interface", "https://security.paloaltonetworks.com"},
	{"fortisoar", "Fortinet FortiSOAR", "https://www.fortiguard.com/psirt"},
	{"fortiddos", "Fortinet FortiDDoS", "https://www.fortiguard.com/psirt"},
	{"cisco expressway", "Cisco Expressway", "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"},
	{"duo access gateway", "Cisco Duo Access Gateway", "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"},
}

type Result struct {
	URL        string   `json:"url"`
	Status     Status   `json:"status"`
	PHPVersion string   `json:"php_version,omitempty"`
	Product    string   `json:"product,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	Advice     string   `json:"advice"`
	Contact    string   `json:"contact,omitempty"`
	Error      string   `json:"error,omitempty"`
}

var cgnat, zeroNet, nat64 = netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("64:ff9b::/96")

// IsPublic reports whether a is a globally routable unicast address.
func IsPublic(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a) && !zeroNet.Contains(a) && !nat64.Contains(a)
}

// NewClient returns an HTTP client that only connects to addresses allow accepts.
// The check runs on every connect, so DNS rebinding and redirects can't bypass it.
func NewClient(timeout time.Duration, allow func(netip.Addr) bool) *http.Client {
	d := &net.Dialer{Timeout: timeout, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if !allow(ap.Addr().Unmap()) {
			return fmt.Errorf("address %s is not allowed", ap.Addr())
		}
		return nil
	}}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: d.DialContext,
			// Devices use self-signed certificates, and we only read response headers.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 || req.URL.Hostname() != via[0].URL.Hostname() {
				return http.ErrUseLastResponse // stay on the host we were asked to check
			}
			return nil
		},
	}
}

// Check sends one GET request to target and reports PHP2Shell exposure.
func Check(ctx context.Context, c *http.Client, target string) Result {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Result{URL: target, Status: Unreachable, Advice: advice[Unreachable], Error: err.Error()}
	}
	req.Header.Set("User-Agent", "phpscan/0.1 (PHP2Shell exposure check; +"+RepoURL+")")
	resp, err := c.Do(req)
	if err != nil {
		return Result{URL: target, Status: Unreachable, Advice: advice[Unreachable], Error: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	r := analyze(resp.Header, resp.Request.URL, body)
	r.URL = target
	return r
}

var phpVer = regexp.MustCompile(`(?i)PHP/(\d+)\.(\d+)\.(\d+)([-+~][\w.+~]*)?`)

func analyze(h http.Header, final *url.URL, body []byte) (r Result) {
	php := false
	for _, k := range []string{"X-Powered-By", "Server"} {
		v := h.Get(k)
		if !strings.Contains(strings.ToLower(v), "php") {
			continue
		}
		php = true
		r.Evidence = append(r.Evidence, k+": "+v)
		if m := phpVer.FindStringSubmatch(v); m != nil && r.PHPVersion == "" {
			r.PHPVersion = m[0][len("PHP/"):]
			r.Status = classify(atoi(m[1]), atoi(m[2]), atoi(m[3]), m[4])
		}
	}
	for _, c := range h.Values("Set-Cookie") {
		if strings.HasPrefix(c, "PHPSESSID=") {
			php = true
			r.Evidence = append(r.Evidence, "PHP session cookie (PHPSESSID)")
			break
		}
	}
	path := strings.ToLower(final.Path)
	if strings.HasSuffix(path, ".php") {
		php = true
		r.Evidence = append(r.Evidence, "page served from "+final.Path)
	}
	page := strings.ToLower(string(body))
	if strings.Contains(page, ".php") {
		php = true
		r.Evidence = append(r.Evidence, "page links to .php files")
	}
	var advisory string
	for _, p := range products {
		if strings.Contains(path, p.marker) || strings.Contains(page, p.marker) {
			php, r.Product, advisory = true, p.name, p.advisory
			r.Evidence = append(r.Evidence, "login page matches "+p.name)
			break
		}
	}

	switch {
	case r.Status != "":
	case php:
		r.Status = Unknown
	default:
		r.Status = NotDetected
	}
	r.Advice = advice[r.Status]
	if r.Product != "" && r.Status != Patched {
		r.Advice += " This looks like " + r.Product + ": install the fixed firmware from the vendor advisory (" + advisory +
			") and allow management access only from trusted internal IPs."
	}
	if r.Status == Vulnerable || r.Status == Likely || r.Status == Unknown {
		r.Contact = ContactURL
	}
	return r
}

func classify(major, minor, patch int, distro string) Status {
	fix, supported := fixed[fmt.Sprintf("%d.%d", major, minor)]
	switch {
	case supported && patch >= fix:
		return Patched
	case !supported && (major > 8 || major == 8 && minor > 5):
		return Unknown // branch newer than this advisory
	case distro != "":
		return Likely
	default:
		return Vulnerable
	}
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }
