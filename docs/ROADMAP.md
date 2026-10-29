# NetScope roadmap

What's planned after v0.1.0. Items may move between releases; [CHANGELOG.md](../CHANGELOG.md) records
what actually shipped.

## v0.2.0

### Faster, politer scanning
- **asyncio scanner** using `asyncio.open_connection()` with `asyncio.wait_for()` timeouts, keeping
  the current thread-pool scanner as a fallback (`--engine threads`).
- **Benchmark** script comparing the two engines on localhost and a lab subnet (ports per second,
  CPU and memory use), with the results written up in the docs.
- **`--rate`** (new connections per second) and **`--concurrency`** (connections open at once;
  default 100, max 500).
- **Presets:** `--preset polite` (low rate, long timeout, for networks you share),
  `normal` (the defaults) and `fast` (for your own lab).

### Testing
- **pytest-socket** to block network access in tests at the socket level, replacing the
  hand-written guard in `conftest.py` (with `127.0.0.1` allowed for the local test servers).
- Keep the **Windows / Ubuntu / macOS CI matrix**, and add OS-specific tests for the
  ping and traceroute integrations.

### Ping and hops without admin rights
- **Windows:** call `IcmpSendEcho` from `iphlpapi.dll` through `ctypes` for ping (no admin needed),
  and keep `tracert` for hops.
- **Linux:** unprivileged ICMP via `icmplib` (datagram ICMP sockets, allowed by
  `net.ipv4.ping_group_range`), and `tracepath` for hops when `traceroute` isn't installed.
- **macOS:** unprivileged ICMP datagram sockets, with the system `ping` as a fallback.

### TLS details
- Show the negotiated **protocol** and cipher.
- **Days to expiry** with a **warning at 30 days** and **critical at 7** (already in v0.1.0), made
  configurable with `--warn-days` and `--crit-days`.
- List the certificate's **SANs** (subject alternative names) and the full **issuer**, and flag a
  host name that doesn't match.

### Opt-in banner grabbing
- **`--banners`** reads the first line a service sends (SSH, SMTP, FTP, ...) after connecting.
  Off by default, as it's more intrusive than a connect scan; short read limit and timeout.

### Local-subnet host discovery (no root)
- **TCP sweep** of a few common ports across your own subnet.
- Read the **ARP cache** (`arp -a`, `ip neigh`) for devices the OS already knows about.
- **mDNS** (`_services._dns-sd._udp.local`) and **SSDP** (UPnP `M-SEARCH`) queries to find
  printers, TVs and smart devices that announce themselves.
- Only the subnet of your own interface is allowed, and the same guard rails apply.

### IPv6 and DNS
- Full **IPv6** support in scans, ping and traceroute (with guard rails for global IPv6 ranges).
- **`--resolver 1.1.1.1`** to query a chosen DNS server directly (plain UDP/TCP DNS messages),
  plus record types beyond A/AAAA/PTR (MX, TXT, NS, CNAME).

### Comparing and repeating checks
- **Diff mode:** `netscope diff old.json new.json` shows ports that opened or closed, changed
  certificates and changed DNS answers between two saved reports (relies on `schema_version`).
- **Profiles** in a TOML file read with the standard library's `tomllib` (Python 3.11+; the `tomli` package on 3.10), e.g.
  `netscope scan --profile homelab` with saved targets, ports and presets.

### Output
- **rich** tables, colours and progress bars when the optional `rich` package is installed,
  with plain text when it isn't, when output is piped, or when **`NO_COLOR`** is set.
