# phpscan

Checks websites and local network devices for exposure to **PHP2Shell**
(CVE-2026-109618, CVE-2026-109619), two unauthenticated remote code execution
flaws in PHP fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12.

It **detects and reports only**. It never sends attack payloads, never logs in,
and never changes anything on the devices it checks.

There are two parts. Both use the same check, in [`check/check.go`](check/check.go).

| Part | Checks | Runs |
|---|---|---|
| `phpscan-web` | Public websites whose owner has verified the domain | As a serverless container |
| `phpscan-local` | Routers, switches, modems and NAS on your own network | Once, on a computer in that network |

## How the check works

For each address, the tool sends **one ordinary `GET` request**, the same one a
browser sends when you open the page. Then it reads:

1. The `X-Powered-By` and `Server` headers, for a version such as `PHP/7.4.33`.
2. A `PHPSESSID` cookie, a `.php` page address, or links to `.php` files. These
   show PHP is in use when the version is hidden.
3. Login page markers for appliances that vendors list as affected
   (Palo Alto PAN-OS, Fortinet FortiSOAR/FortiDDoS, Cisco Expressway, Duo Access Gateway).

It compares the version with the fixed releases and reports one of these:

| Status | Meaning |
|---|---|
| `vulnerable` | Version is older than the fix |
| `likely_vulnerable` | Older version from a Linux distribution, which may have backported the fix |
| `unknown` | PHP or an affected appliance found, version hidden |
| `patched` | Version includes the fix |
| `no_php_detected` | No sign of PHP in the response |

Every result says where the evidence was found and what to do next.

**Limits:** a version string is evidence, not proof. Distributions backport fixes
without changing the version, and many servers hide it. To confirm for certain
you need an active test that triggers the bug. This tool deliberately doesn't
run one, because such tests can crash PHP workers.

## phpscan-local (companion tool)

Download the file for your system from Releases and run it. It:

- finds this computer's private network (for example `192.168.1.0/24`)
- shows exactly which range it will check and asks for confirmation
- tries ports 80, 443, 8080 and 8443 on each address, then checks the web interfaces it finds
- prints the report on screen and exits

It **cannot** connect to public internet addresses. That rule is enforced in
code, in `NewClient`. It installs nothing, keeps no data and sends results
nowhere. It uses only the Go standard library, with no third-party dependencies.

```sh
phpscan-local                 # scan this computer's local network
phpscan-local 192.168.1.1     # check specific devices
```

### Verify your download

Releases are built by GitHub Actions from the tagged source
([workflow](.github/workflows/release.yml)), and each file has a signed build
attestation. To check that a file came from this repository:

```sh
gh attestation verify phpscan-local-windows-amd64.exe --repo Mojo7823/phpscan
```

Or build it yourself from source with Go 1.25+: `go build ./cmd/phpscan-local`

## phpscan-web (online scanner)

A small HTTP service with a one-page UI. `GET /api/scan?url=www.example.com`
returns the result as JSON.

Anyone can check any website, and no proof of ownership is needed. The check
is one ordinary page request, the same as a browser visit, and it reads only
what the site already sends to every visitor. Public tools such as SSL Labs
and securityheaders.com work the same way. Active tests that trigger the bug
belong in an authorized engagement with a signed scope, not in this tool.

To keep the service from being misused:

- it connects only to public IP addresses, never private, loopback, link-local or cloud metadata ones
- it checks only ports 80 and 443, so it can't be used as a port scanner
- it has a rate limit, and it stores no results

```sh
docker build -t phpscan-web .
docker run -p 8080:8080 phpscan-web
```

Deploy the same image to any container-based serverless host (Google Cloud Run,
Zeabur, Fly.io, AWS App Runner).

## Development

```sh
go vet ./... && go test ./...
```

Before publishing, set `ContactURL` in `check/check.go`.
