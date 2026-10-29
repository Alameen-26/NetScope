# Changelog

All notable changes to this project are documented here.

## v0.1.0 (2026-10-29, released)

First release, published on GitHub on 2026-10-29.

- `netscope ping`: reachability and latency (min/avg/max/jitter, packet loss) using the system `ping`,
  with a TCP-connect fallback that needs no administrator rights. Reply parsing is language-neutral
  (it reads the number before "ms" on lines containing `TTL=`), so English, French and German Windows
  and Linux output all work.
- `netscope scan`: threaded TCP port scanner with timeouts, a `common` ports preset, ranges such as
  `8000-8100`, service names and open/closed/filtered states. Accepts a host, IP or small CIDR range.
- Guard rails for scanning: loopback, private and link-local ranges are allowed; carrier-grade NAT
  (100.64.0.0/10) and public ranges larger than /24 are refused unless `--i-own-this` is passed (which
  prints the responsible-use line). Hard limit of 1,024 addresses per scan.
- `netscope dns`: A/AAAA lookups and reverse (PTR) lookups using the standard library.
- `netscope trace`: hop list using the system `tracert`/`traceroute`/`tracepath` (no raw sockets);
  skipped with a clear message when none is installed.
- `netscope info`: host name, local IP and interfaces (interfaces with the optional psutil).
- `netscope http`: status, response time, key headers, redirects, TLS version and certificate expiry
  (warning at 30 days, critical at 7).
- `netscope latency`: quick latency summary to Cloudflare, Google DNS and Quad9.
- Output as aligned tables or `--json` (with `schema_version`), and `--save` to JSON or HTML reports.
- Documented exit codes: 0 ok, 1 findings, 2 usage, 3 refused by guard rail, 4 network error,
  130 stopped with Ctrl-C.
- 389 pytest tests that never touch the internet; GitHub Actions (pytest, mypy, pyflakes) on
  Windows, macOS and Linux with Python 3.10 and 3.13.

### Fixed during review (before release)

Ping and traceroute

- Windows output is decoded with the console's code page (cp850, cp866, ...) instead of crashing
  on German "für" or French "Réponse"; any unknown byte becomes "?" rather than an error.
- A reply line is one with `TTL=`/`hlim=` or exactly one time value, so Windows IPv6 replies
  ("Reply from ::1: time<1ms") and macOS `ping6` replies are counted.
- Russian "мс" is understood; `<1ms` is stored as 0.5 ms and shown as `<1 ms`.
- Duplicate replies (`DUP!`) no longer hide packet loss; they are counted and mentioned.
- macOS uses `ping6` and `traceroute6` for IPv6; macOS traceroute lines for extra routers on the
  same hop are kept (`(also ...)`).
- Host names are validated (no leading `-`, only host-name characters) and resolved once; only the
  IP address is passed to `ping`/`tracert`/`traceroute`.

Scanning and guard rails

- The size of a range is checked before it is expanded, so `10.0.0.0/8` or `::/64` is refused at once.
- IPv4-mapped, NAT64 and 6to4 IPv6 addresses are judged by the IPv4 address inside them.
- New cap of 65,536 connection attempts per scan (`--max-probes` to change it).
- Running out of open files (EMFILE) slows the scan down instead of marking ports "filtered";
  the socket is created inside the error handling. README example lowered to `--workers 50`.
  The "slowed down" note only appears when that actually happened.
- Default per-port timeout is 2 s on Windows (0.5 s elsewhere); CI runs a 1-1024 loopback scan there.

HTTP check

- A failed certificate check is a finding (exit 1); OpenSSL code 10 is reported as "certificate has
  expired". The certificate is read once more without checking, only to display it, labelled
  "(unverified)".
- Redirects: only `http`/`https` are followed (a `file://` redirect is reported, not followed), host
  and port are checked on every hop, an HTTPS-to-HTTP downgrade is a finding, and certificate
  details are reset on each hop.
- New overall `--deadline` (default 3 x `--timeout`), redirects and body included.

Command line

- `--timeout` must be a finite number above 0 and at most 60; `--max-hops` 1-64; `--port` 1-65535.
- Exit codes made consistent: unknown host is 4 in every command, expired certificate 1, a trace
  where every hop is `*` is 1, a ping with partial loss is 1, Ctrl-C is 130, and any unexpected
  error prints one line and exits 4.
- `--save` no longer creates folders, refuses to overwrite without `--force`, is checked before the
  work starts, and is written before printing; a failed save warns without changing the exit code.
- JSON is plain ASCII when stdout is not a terminal, and text output can no longer crash on a
  console that can't show a character (it is escaped instead).
- The HTML report has a Content-Security-Policy that blocks scripts and remote loads.
- Type hints checked with mypy (`types-psutil` in the dev extra); the last `type: ignore` was removed.

### Repository layout at release

- Screenshots in `docs/screenshots/` are SVG files that embed the original PNG pictures, and the raw
  Windows console fixtures are stored base64-encoded (`tests/data/*.bin.b64`), so the repository holds
  only text files. The tests decode the fixtures back to the exact original bytes.
