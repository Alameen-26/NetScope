# NetScope: interview notes

Talking points for explaining how NetScope works and why it's built the way it is, followed by
questions an interviewer is likely to ask.

## 30-second summary

NetScope is a cross-platform Python command-line tool for checking networks you own: ping, a threaded
TCP port scanner, DNS lookups, traceroute, local network info, an HTTP/TLS check and a latency
summary. It uses only the standard library, needs no admin rights, prints tables or JSON, saves
JSON/HTML reports, and has guard rails that refuse scans of address space that isn't clearly yours.
It has 389 tests that run without internet access and CI on Windows, macOS and Linux.

## Threads vs asyncio

- A port check is **I/O-bound**: almost all its time is spent waiting for a SYN-ACK, a reset or a
  timeout. CPU work is tiny.
- Python's GIL stops two threads running Python bytecode at the same time, but it is **released while
  a thread waits on a socket**. So threads give real concurrency for waiting work.
- I used `concurrent.futures.ThreadPoolExecutor` because it's simple, works the same everywhere, and
  each check stays an ordinary blocking function that's easy to test.
- The pool is capped (default 100, max 500) and never bigger than the number of ports. Each thread
  costs memory (its own stack), and too many open connections can hit the OS file-descriptor limit or
  look like a flood to the network.
- **asyncio** runs many connections on one thread with an event loop. It scales to thousands of
  connections more cheaply than threads, but every function in the chain has to be `async`. That's
  the v0.2.0 plan, with a benchmark to prove whether it's worth it.
- **multiprocessing** would be the wrong tool: it's for CPU-bound work, and adds process start-up
  and data-copying costs for no gain here.

## Timeouts

- Every network call has a timeout. Without one, a single dropped packet can make a scan hang for a
  minute or more (the OS default TCP connect timeout).
- `settimeout()` on the socket covers the connect; `http.client` and `subprocess.run(timeout=...)`
  get their own.
- The timeout decides the result of a scan: **open** = handshake completed, **closed** = reset
  received ("connection refused"), **filtered** = nothing came back before the timeout, usually a
  firewall silently dropping packets.
- Trade-off: a short timeout is fast but may call a slow port "filtered" on a busy network; a long
  one is accurate but slow. Default is 0.5 s per port; the user can change it.
- Worst case for a scan is roughly `ports / workers x timeout`, which is why the worker pool matters.

## Sockets

- A socket is an endpoint for network communication. NetScope uses `AF_INET`/`AF_INET6` (IPv4/IPv6)
  with `SOCK_STREAM` (TCP).
- `connect_ex()` returns an error number instead of raising, which makes it cheap to sort results:
  0 is open; "connection refused" is closed. That error number differs by OS (111 on Linux, 61 on
  macOS, 10061 on Windows), so the code checks all three. Anything else is treated as filtered.
- This is a **full TCP connect scan** (complete three-way handshake, then close). A "SYN scan" like
  nmap's default needs raw sockets and root, so I chose the approach that works for any user.
- Every socket is closed in a `try ... finally` block, so a scan of thousands of ports doesn't
  leak file descriptors.
- **Local IP trick:** "connecting" a UDP socket sends nothing, but makes the OS choose the outgoing
  interface, and `getsockname()` then reveals its IP. I connect to `192.0.2.1`, an address reserved
  for documentation, so even by mistake nothing real is contacted.
- **Ping without admin rights:** raw ICMP sockets need root/admin, so NetScope calls the system
  `ping` binary (which has the needed permission) and parses its output. If that's unavailable it
  times TCP connections instead, where even a "refused" reply proves the host is alive.

## DNS

- `socket.getaddrinfo()` asks the operating system's resolver, so results match what other programs
  see: it uses the hosts file, local caches and the configured DNS servers.
- A forward lookup returns A (IPv4) and AAAA (IPv6) records. `getaddrinfo` returns one entry per
  socket type and protocol, so the results are de-duplicated.
- A reverse lookup (`gethostbyaddr`) asks for the PTR record of an IP, which may not exist even when
  the forward record does; that isn't an error in the tool.
- "localhost" can resolve to `::1` first. A real bug I hit: the scanner connected to `::1` while my
  test servers listened on `127.0.0.1`, so everything showed closed. I now prefer IPv4 when both
  exist.

## A real bug worth talking about: thread safety

During a threaded scan, port 5432 was labelled "mysql" instead of "postgresql". The cause was
`socket.getservbyport()`, which on some platforms uses a shared C buffer and **isn't thread-safe**,
so two threads looking up names at once could get each other's answer. The fix was a `threading.Lock`
around the call plus `functools.lru_cache` so each port is only looked up once, and a regression test
that looks up many ports from many threads at once.

## Guard rails and responsible use

- `ipaddress` classifies the target before any traffic: loopback and private ranges are allowed;
  carrier-grade NAT (`100.64.0.0/10`) is neither private nor global in Python's `ipaddress`, so it's
  handled explicitly and requires `--i-own-this`; public ranges larger than /24 are refused unless
  that flag is given; nothing above 1,024 addresses is ever scanned.
- Refusals use exit code 3 so scripts can tell "refused" apart from errors (4) and findings (1).
- Port scanning someone else's network without permission can break the law (Canada's Criminal
  Code s. 342.1, the US CFAA, the UK Computer Misuse Act) and most acceptable-use policies.

## Testing approach

- The **feature code returns dataclasses** and doesn't print, so tests check data, not text.
- Subprocess-based features (ping, traceroute) take an injectable `runner`, and the parsers are tested
  on **sample output** in English, French, German and Russian in the Windows, macOS and Linux formats,
  including raw cp850/cp866 bytes, since Windows tools write in the console code page.
- Port scans and HTTP checks run against **real servers on `127.0.0.1`** started by pytest fixtures,
  so the socket code is genuinely exercised.
- An autouse fixture makes any connection or DNS lookup to a non-local address fail the test. That
  keeps the suite fast, repeatable and safe to run on CI.
- CLI tests check every command's `--help`, argument errors (exit 2), guard-rail refusals (exit 3),
  the full exit-code matrix, Ctrl-C (130), and JSON/HTML report saving.
- HTTPS is tested against local servers with test-only certificates (one expired), so the
  certificate-failure path is exercised for real without leaving the machine.

## Likely questions and answers

**Why Python instead of nmap?**
To learn how it works underneath: sockets, timeouts, concurrency, DNS and TLS. nmap is the right tool
for real assessments; NetScope is small, readable, scriptable and easy to extend.

**What's the difference between TCP and UDP?**
TCP is connection-oriented: a three-way handshake (SYN, SYN-ACK, ACK), ordered delivery and
retransmission. UDP just sends datagrams with no handshake or delivery guarantee. That's why a TCP
connect scan gets a clear open/closed answer and a UDP scan mostly doesn't.

**What happens during `connect()`?**
The client sends SYN; an open port replies SYN-ACK and the client completes with ACK; a closed port
replies RST (connection refused); a firewall may drop the SYN, so nothing comes back until the timeout.

**What is a port?**
A 16-bit number (0-65535) that identifies which program on a host gets a connection. 0-1023 are
"well-known" ports (22 SSH, 80 HTTP, 443 HTTPS), registered ports go up to 49151, and the rest are
dynamic/ephemeral ports the OS gives to outgoing connections.

**Why does ping sometimes fail when the website works?**
Many servers and firewalls drop ICMP. That's why NetScope can fall back to a TCP connection, which
tests the service you actually care about.

**How does traceroute work?**
It sends packets with TTL 1, 2, 3, ... Each router decreases the TTL and, when it hits zero, drops the
packet and returns an ICMP "time exceeded" message, which reveals that router's address. A `*` means a
router didn't answer, not necessarily that the path is broken.

**How do you know when a certificate expires?**
After the TLS handshake, `ssl` gives the peer certificate as a dictionary; its `notAfter` field is
parsed with `ssl.cert_time_to_seconds()`, compared with the current UTC time, and turned into days left.

**Why have exit codes?**
So NetScope works in scripts and CI: `netscope http https://mysite --json || alert` can tell
"site down" (1) apart from "couldn't even run the check" (4).

**What's `schema_version` for?**
Saved JSON reports are a contract. If a field changes in a later release, tools that read old reports
(like the planned diff mode) can check the version instead of guessing.

**How would you make it faster?**
asyncio for higher concurrency with less memory, smarter timeouts (measure the round-trip time first
and adapt), and scanning the most common ports first. Always with a rate limit, so faster doesn't
mean ruder.

**How did you make it cross-platform?**
Standard library only; the OS-specific parts (ping and traceroute command flags, "connection refused"
error numbers) are isolated in small functions with tests per OS; and CI runs on all three.

**What would you do differently?**
Start with the asyncio engine behind the same interface, add IPv6 from day one, and use pytest-socket
for the network guard instead of a hand-written fixture. These are on the v0.2.0 roadmap.
