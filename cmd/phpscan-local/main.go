// Command phpscan-local is the one-time companion tool. It runs on a computer
// inside the customer's network, checks the web interfaces of local devices
// (routers, switches, modems, NAS) for PHP2Shell exposure, and shows the
// report on screen. It only connects to private addresses and sends nothing
// to the internet.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"phpscan/check"
)

var ports = []uint16{80, 443, 8080, 8443}

func local(a netip.Addr) bool { return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() }

func main() {
	yes := flag.Bool("yes", false, "skip the confirmation prompt and the final 'press Enter'")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: phpscan-local [-yes] [IP ...]\nWith no IPs, scans the local /24 network of each private address on this computer.\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	var hosts []netip.Addr
	var ranges []string
	for _, arg := range flag.Args() {
		a, err := netip.ParseAddr(arg)
		if err != nil || !local(a) {
			fmt.Fprintf(os.Stderr, "%s is not a private IP address; this tool only checks your local network\n", arg)
			os.Exit(2)
		}
		hosts, ranges = append(hosts, a), append(ranges, arg)
	}
	if len(hosts) == 0 {
		hosts, ranges = localHosts()
	}
	if len(hosts) == 0 {
		fmt.Println("No private network found on this computer. Connect to the network you want to check and run this again.")
		return
	}

	fmt.Printf(`phpscan-local: one-time PHP2Shell check (CVE-2026-109618, CVE-2026-109619)
Source code and how it works: %s

It will look for web interfaces on: %s
and send each one ordinary page request, like opening it in a browser.
It does NOT log in, change settings, send attack payloads, install anything,
or send results anywhere. The report is shown only on this screen.

`, check.RepoURL, strings.Join(ranges, ", "))
	in := bufio.NewReader(os.Stdin)
	if !*yes {
		fmt.Print("Continue? [y/N] ")
		if line, _ := in.ReadString('\n'); strings.ToLower(strings.TrimSpace(line)) != "y" {
			return
		}
	}

	fmt.Println("Scanning, this takes up to a minute…")
	results := scan(hosts)
	report(results)
	if !*yes {
		fmt.Print("\nPress Enter to close.")
		in.ReadString('\n')
	}
}

// localHosts returns every address in the /24 around each private IPv4 address of this computer.
// shortcut: larger networks are cut to the computer's own /24; pass IPs as arguments to check others.
func localHosts() (hosts []netip.Addr, ranges []string) {
	addrs, _ := net.InterfaceAddrs()
	seen := map[netip.Prefix]bool{}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if ip = ip.Unmap(); !ok || !ip.Is4() || !ip.IsPrivate() {
			continue
		}
		ones, _ := ipn.Mask.Size()
		p, _ := ip.Prefix(max(ones, 24))
		if seen[p] {
			continue
		}
		seen[p] = true
		ranges = append(ranges, p.String())
		for h := p.Addr().Next(); p.Contains(h); h = h.Next() {
			hosts = append(hosts, h)
		}
	}
	return hosts, ranges
}

// scan finds open web ports with a plain TCP connect, then checks each one.
func scan(hosts []netip.Addr) []check.Result {
	client := check.NewClient(5*time.Second, local)
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []check.Result
	)
	sem := make(chan struct{}, 64)
	for _, h := range hosts {
		for _, p := range ports {
			sem <- struct{}{}
			wg.Go(func() {
				defer func() { <-sem }()
				addr := netip.AddrPortFrom(h, p).String()
				conn, err := net.DialTimeout("tcp", addr, time.Second)
				if err != nil {
					return
				}
				conn.Close()
				scheme := "http"
				if p == 443 || p == 8443 {
					scheme = "https"
				}
				r := check.Check(context.Background(), client, scheme+"://"+addr+"/")
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			})
		}
	}
	wg.Wait()
	slices.SortFunc(results, func(a, b check.Result) int { return strings.Compare(a.URL, b.URL) })
	return results
}

func report(results []check.Result) {
	attention := 0
	for _, r := range results {
		fmt.Printf("\n%s\n  Status:     %s", r.URL, strings.ReplaceAll(string(r.Status), "_", " "))
		if r.PHPVersion != "" {
			fmt.Printf(" (PHP %s)", r.PHPVersion)
		}
		fmt.Println()
		if r.Product != "" {
			fmt.Printf("  Device:     %s\n", r.Product)
		}
		if len(r.Evidence) > 0 {
			fmt.Printf("  Found in:   %s\n", strings.Join(r.Evidence, "; "))
		}
		if r.Error != "" {
			fmt.Printf("  Error:      %s\n", r.Error)
		}
		fmt.Printf("  What to do: %s\n", r.Advice)
		if r.Contact != "" {
			attention++
		}
	}
	fmt.Printf("\nChecked %d web interfaces. %d need attention.\n", len(results), attention)
	if attention > 0 {
		fmt.Printf("Need help fixing them? Contact us: %s\n", check.ContactURL)
	}
}
