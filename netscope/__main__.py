"""Command-line interface: ``python -m netscope`` or the ``netscope`` script.

Subcommands::

    netscope ping HOST [--count N] [--timeout S] [--method auto|icmp|tcp] [--port P]
    netscope scan TARGET [--ports SPEC] [--timeout S] [--workers N] [--show-closed]
                         [--i-own-this] [--max-probes N]
    netscope dns NAME_OR_IP [--reverse]
    netscope trace HOST [--max-hops N] [--timeout S]
    netscope info
    netscope http URL [--timeout S] [--deadline S] [--no-redirects] [--head]
    netscope latency [--count N]

Every subcommand also accepts ``--json`` (print JSON instead of a table),
``--save FILE.json|FILE.html`` (write a report) and ``--force`` (replace an
existing report file).

Exit codes (documented in the README so scripts can rely on them):

    0    OK
    1    findings: the check ran and found a problem (host down, some packets
         lost, no router answered, HTTP error, certificate expired or invalid,
         https -> http redirect...)
    2    usage error: bad arguments
    3    refused by a guard rail (e.g. a large public range without --i-own-this)
    4    network error: the check couldn't run (unknown host - in every command -,
         tool missing, no route, or an unexpected error)
    130  stopped with Ctrl-C

The handlers below only collect results and format them; the real work is in
the feature modules (ping.py, portscan.py, ...), which keeps this file easy to
read and the logic easy to test.

Added in v0.1.0
"""
from __future__ import annotations

import argparse
import ipaddress
import math
import socket
import sys
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Optional, Sequence

from . import RESPONSIBLE_USE, __version__
from . import dns as dns_mod
from . import hosts as hosts_mod
from . import httpcheck, latency, netinfo, portscan, safety, trace as trace_mod
from .output import envelope, fmt_ms, format_pairs, format_table, paint, to_json, use_color
from .ping import PingUnavailable, ping as do_ping
from .report import check_report_path, save_report

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_REFUSED, EXIT_NETWORK = 0, 1, 2, 3, 4
EXIT_INTERRUPTED = 130   # the usual code for "stopped with Ctrl-C"

MAX_TIMEOUT = 60.0       # seconds; anything longer is almost certainly a typo
MAX_PROBES = 65_536      # default cap on hosts x ports in one scan


@dataclass
class Outcome:
    """What a subcommand produced: data for JSON/reports, text for people, and an exit code."""

    data: Any
    text: str
    code: int = EXIT_OK


class CommandError(Exception):
    """A problem we can explain in one line, with the exit code to use."""

    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


def _host_errors(exc: Exception) -> CommandError:
    """Same message and exit code for a bad or unknown host in every command."""
    if isinstance(exc, hosts_mod.UnknownHost):
        return CommandError(str(exc), EXIT_NETWORK)
    return CommandError(str(exc), EXIT_USAGE)


# --------------------------------------------------------------------------- ping

def cmd_ping(args: argparse.Namespace, color: bool) -> Outcome:
    try:
        result = do_ping(args.host, count=args.count, timeout=args.timeout,
                         method=args.method, port=args.port)
    except PingUnavailable as exc:
        raise CommandError(f"system ping unavailable: {exc}. Try --method tcp.", EXIT_NETWORK)
    except (hosts_mod.InvalidHost, hosts_mod.UnknownHost, ValueError) as exc:
        raise _host_errors(exc)
    how = "system ping (ICMP)" if result.method == "icmp" else f"TCP connect to port {result.port}"
    if not result.reachable:
        status = paint("unreachable", "red", color)
    elif result.partial_loss:
        status = paint("reachable, with packet loss", "yellow", color)
    else:
        status = paint("reachable", "green", color)
    target = result.host if result.address in (None, result.host) else f"{result.host} ({result.address})"
    lines = [f"PING {target} using {how}: {status}", ""]
    lines.append(format_table(
        ["SENT", "RECEIVED", "LOSS", "MIN", "AVG", "MAX", "JITTER"],
        [[result.sent, result.received, f"{result.loss_percent:g}%", fmt_ms(result.min_ms),
          fmt_ms(result.avg_ms), fmt_ms(result.max_ms), fmt_ms(result.jitter_ms)]]))
    if result.duplicates:
        lines.append(f"\nNote: {result.duplicates} duplicate repl"
                     f"{'y' if result.duplicates == 1 else 'ies'} ignored (not counted as received).")
    if result.error:
        lines.append(f"\nNote: {result.error}")
    healthy = result.reachable and not result.partial_loss
    return Outcome(result.to_dict(), "\n".join(lines), EXIT_OK if healthy else EXIT_FINDINGS)


# --------------------------------------------------------------------------- scan

def parse_target(target: str) -> tuple[safety.Network, Optional[str]]:
    """Turn "localhost", "192.168.1.10" or "192.168.1.0/28" into (network, name).

    Only the *network* is built here - it's just two numbers, however large
    the range. The list of addresses is made later (``iter_hosts``), after
    the guard rail has checked the size, so "10.0.0.0/8" or "::/64" is
    refused instantly instead of using gigabytes of memory first.
    """
    if "/" in target:
        try:
            return ipaddress.ip_network(target.strip(), strict=False), None
        except ValueError as exc:
            raise CommandError(f"invalid network '{target}': {exc}", EXIT_USAGE)
    try:
        name = hosts_mod.validate_host(target)
        ip, _ = portscan.resolve_target(name)
    except (hosts_mod.InvalidHost, hosts_mod.UnknownHost) as exc:
        raise _host_errors(exc)
    return ipaddress.ip_network(ip), name


def iter_hosts(network: safety.Network) -> Iterator[str]:
    """Addresses in ``network`` one at a time; a single-address range yields that address."""
    found = False
    for host in network.hosts():
        found = True
        yield str(host)
    if not found:  # /32, /128 (and /31, /127 on older Pythons) have no "hosts"
        yield str(network.network_address)


def cmd_scan(args: argparse.Namespace, color: bool) -> Outcome:
    try:
        ports = portscan.parse_ports(args.ports)
    except ValueError as exc:
        raise CommandError(f"--ports: {exc}", EXIT_USAGE)
    network, name = parse_target(args.target)

    # Guard rail: decide before a single packet is sent (and before the range
    # is turned into a list of addresses).
    decision = safety.check_target(network, i_own_this=args.i_own_this)
    if not decision.allowed:
        raise CommandError(f"refused: {decision.message}\n{RESPONSIBLE_USE}", EXIT_REFUSED)
    hosts = list(iter_hosts(network))   # at most MAX_HOSTS + 2, checked above
    probes = len(hosts) * len(ports)
    if probes > args.max_probes:
        raise CommandError(f"refused: {len(hosts)} addresses x {len(ports)} ports = {probes:,} "
                           f"connection attempts, more than the limit of {args.max_probes:,}. "
                           "Scan fewer ports or a smaller range, or raise the limit with "
                           "--max-probes.", EXIT_REFUSED)
    if decision.message:
        print(paint(f"Warning: {decision.message}", "yellow", use_color(sys.stderr)), file=sys.stderr)

    scans: list[portscan.ScanResult] = []
    for ip in hosts:
        # For a single named host, keep the name the user typed (e.g. "localhost").
        shown_name = name if name and len(hosts) == 1 else ip
        try:
            scans.append(portscan.scan_ports(shown_name, ports, timeout=args.timeout,
                                             workers=args.workers, resolver=_fixed_resolver(ip)))
        except portscan.TooManyOpenFiles as exc:
            raise CommandError(f"{exc.strerror}. Try a lower --workers value.", EXIT_NETWORK)

    lines: list[str] = []
    for scan in scans:
        shown = scan.results if args.show_closed else scan.open_ports
        if len(hosts) > 1 and not shown:
            continue  # on a range, only list hosts that have something to show
        counts = scan.counts()
        lines.append(f"Scan of {scan.host} ({scan.ip}): {len(ports)} ports in {scan.duration_s:.2f}s - "
                     f"{counts['open']} open, {counts['closed']} closed, {counts['filtered']} filtered")
        if shown:
            state_color = {"open": "green", "closed": "dim", "filtered": "yellow"}
            lines.append(format_table(
                ["PORT", "STATE", "SERVICE", "TIME"],
                [[f"{r.port}/tcp", paint(r.state, state_color[r.state], color)
                  if color else r.state, r.service, fmt_ms(r.latency_ms)] for r in shown]))
        else:
            lines.append("No open ports found.")
        if scan.workers_used is not None:
            lines.append(f"Note: ran out of open files, so slowed down to {scan.workers_used} workers.")
        lines.append("")
    if len(hosts) > 1:
        up = sum(1 for s in scans if s.open_ports)
        lines.append(f"{len(hosts)} addresses scanned in {network} ({decision.kind}); "
                     f"{up} with open ports.")
    data = {"target": args.target, "kind": decision.kind, "ports_per_host": len(ports),
            "hosts": [s.to_dict(include_closed=args.show_closed) for s in scans]}
    return Outcome(data, "\n".join(lines).rstrip())


def _fixed_resolver(ip: str) -> Callable[[str], tuple[str, int]]:
    """A resolver that always returns ``ip``: the range was already expanded into addresses."""
    def resolve(_host: str) -> tuple[str, int]:
        return ip, _family(ip)
    return resolve


def _family(ip: str) -> int:
    return socket.AF_INET6 if ":" in ip else socket.AF_INET


# --------------------------------------------------------------------------- dns

def cmd_dns(args: argparse.Namespace, color: bool) -> Outcome:
    if dns_mod.is_ip_address(args.name):
        rev = dns_mod.reverse_lookup(args.name)
        text = format_pairs([("Address", rev.ip), ("Host name", rev.hostname),
                             ("Aliases", ", ".join(rev.aliases) or None)])
        if rev.error:
            text += f"\nNote: {rev.error}"
        # The address itself is fine; having no name for it is a finding.
        return Outcome({"reverse": [rev.to_dict()]}, text, EXIT_OK if rev.ok else EXIT_FINDINGS)

    result = dns_mod.lookup(args.name)
    if not result.ok:
        # An unknown host is exit code 4 in every command.
        return Outcome({"lookup": result.to_dict()}, f"DNS lookup for {args.name}: {result.error}",
                       EXIT_NETWORK)
    rows = [["A", ip] for ip in result.ipv4] + [["AAAA", ip] for ip in result.ipv6]
    data: dict[str, Any] = {"lookup": result.to_dict()}
    headers = ["TYPE", "ADDRESS"]
    if args.reverse:
        reverses = [dns_mod.reverse_lookup(ip) for ip in result.ipv4 + result.ipv6]
        data["reverse"] = [r.to_dict() for r in reverses]
        headers.append("REVERSE NAME")
        for row, rev in zip(rows, reverses):
            row.append(rev.hostname or "-")
    text = (f"DNS lookup for {args.name} ({fmt_ms(result.elapsed_ms)})\n\n"
            + format_table(headers, rows))
    return Outcome(data, text)


# --------------------------------------------------------------------------- trace

def cmd_trace(args: argparse.Namespace, color: bool) -> Outcome:
    try:
        result = trace_mod.trace(args.host, max_hops=args.max_hops, timeout=args.timeout)
    except trace_mod.TraceUnavailable as exc:
        raise CommandError(f"trace skipped: {exc}", EXIT_NETWORK)
    except (hosts_mod.InvalidHost, hosts_mod.UnknownHost) as exc:
        raise _host_errors(exc)
    if not result.hops:
        return Outcome(result.to_dict(), f"Trace to {args.host} failed: {result.error}", EXIT_NETWORK)
    rows = []
    for h in result.hops:
        address = h.address or "* (no reply)"
        if h.other_addresses:
            address += f" (also {', '.join(h.other_addresses)})"
        rows.append([h.number, address, fmt_ms(h.avg_ms)])
    target = args.host if result.address in (None, args.host) else f"{args.host} ({result.address})"
    text = f"Route to {target} (via {result.tool})\n\n" + format_table(["HOP", "ADDRESS", "TIME"], rows)
    if result.no_replies:
        text += "\n\nNo router answered at all (a firewall may be dropping the probes)."
        return Outcome(result.to_dict(), text, EXIT_FINDINGS)
    return Outcome(result.to_dict(), text)


# --------------------------------------------------------------------------- info

def cmd_info(args: argparse.Namespace, color: bool) -> Outcome:
    info = netinfo.collect()
    text = format_pairs([("Host name", info.hostname), ("Full name", info.fqdn),
                         ("Local IP", info.local_ip or "offline"), ("System", info.os)])
    if info.interfaces:
        rows = [[i.name, "up" if i.is_up else ("down" if i.is_up is False else "-"),
                 ", ".join(i.ipv4) or "-", i.mac or "-",
                 f"{i.speed_mbps} Mb/s" if i.speed_mbps else "-"] for i in info.interfaces]
        text += "\n\n" + format_table(["INTERFACE", "STATUS", "IPV4", "MAC", "SPEED"], rows)
    elif info.interfaces_note:
        text += f"\n\nInterfaces: {info.interfaces_note}"
    return Outcome(info.to_dict(), text)


# --------------------------------------------------------------------------- http

def cmd_http(args: argparse.Namespace, color: bool) -> Outcome:
    try:
        result = httpcheck.check_url(args.url, timeout=args.timeout, deadline=args.deadline,
                                     follow_redirects=not args.no_redirects,
                                     method="HEAD" if args.head else "GET")
    except ValueError as exc:
        raise CommandError(str(exc), EXIT_USAGE)
    if result.status is None and not result.cert_error:
        return Outcome(result.to_dict(), f"HTTP check of {result.url} failed: {result.error}", EXIT_NETWORK)

    pairs: list[tuple[str, Any]] = [("URL", result.final_url)]
    if result.status is not None:
        status_text = paint(f"{result.status} {result.reason}", "green" if result.ok else "red", color)
        pairs += [("Status", status_text), ("Response time", fmt_ms(result.response_ms)),
                  ("Total time", fmt_ms(result.total_ms)),
                  ("Body size", f"{result.body_bytes} bytes")]
    else:
        pairs.append(("Status", paint("not requested (certificate failed verification)", "red", color)))
    if result.redirects:
        pairs.append(("Redirects", " -> ".join(result.redirects)))
    if result.cert_error:
        pairs.append(("Certificate", paint(f"NOT trusted: {result.cert_error}", "red", color)))
    if result.cert:
        c = result.cert
        status_color = {"ok": "green", "warning": "yellow", "critical": "red", "expired": "red"}
        left = f"{c.days_left} days left, " if c.days_left is not None else ""
        expiry = f"{c.not_after or 'unknown'} ({left}{paint(c.status, status_color.get(c.status, 'dim'), color)})"
        label = "" if c.verified else " (unverified)"
        pairs += [(f"TLS{label}", c.tls_version), (f"Certificate for{label}", c.subject),
                  (f"Issued by{label}", c.issuer), (f"Expires{label}", expiry)]
    text = format_pairs(pairs)
    for finding in result.findings:
        text += "\n" + paint(f"Finding: {finding}", "yellow", color)
    if result.error and not result.cert_error:
        text += f"\nNote: {result.error}"
    shown = [[k, v] for k, v in result.headers.items() if k in httpcheck.INTERESTING_HEADERS]
    if shown:
        text += "\n\n" + format_table(["HEADER", "VALUE"], shown)
    findings = (not result.ok or result.cert_error is not None
                or (result.cert is not None and result.cert.status in ("critical", "expired")))
    return Outcome(result.to_dict(), text, EXIT_FINDINGS if findings else EXIT_OK)


# --------------------------------------------------------------------------- latency

def cmd_latency(args: argparse.Namespace, color: bool) -> Outcome:
    entries = latency.summary(count=args.count, timeout=args.timeout)
    rows = []
    for e in entries:
        r = e.result
        rows.append([e.name, f"{r.host}:{r.port}", fmt_ms(r.avg_ms), fmt_ms(r.min_ms),
                     fmt_ms(r.max_ms), f"{r.loss_percent:g}%", latency.rate_latency(r.avg_ms)])
    text = "Latency to public servers (TCP connect time)\n\n" + format_table(
        ["SERVER", "ADDRESS", "AVG", "MIN", "MAX", "LOSS", "RATING"], rows)
    all_down = all(not e.result.reachable for e in entries)
    return Outcome([e.to_dict() for e in entries], text, EXIT_NETWORK if all_down else EXIT_OK)


# --------------------------------------------------------------------------- argument parsing

HANDLERS: dict[str, Callable[[argparse.Namespace, bool], Outcome]] = {
    "ping": cmd_ping, "scan": cmd_scan, "dns": cmd_dns, "trace": cmd_trace,
    "info": cmd_info, "http": cmd_http, "latency": cmd_latency,
}

EPILOG = f"""exit codes: 0 ok, 1 findings, 2 usage error, 3 refused by guard rail,
4 network error (including unknown host), 130 stopped with Ctrl-C

{RESPONSIBLE_USE}"""


def _timeout(text: str) -> float:
    """A number of seconds: finite, above 0 and at most MAX_TIMEOUT ("nan" and "inf" are refused)."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{text}' is not a number") from None
    if not math.isfinite(value) or value <= 0 or value > MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(f"must be a number above 0 and at most {MAX_TIMEOUT:g}")
    return value


def _int_between(low: int, high: int) -> Callable[[str], int]:
    """An argparse type for a whole number from ``low`` to ``high``."""
    def parse(text: str) -> int:
        try:
            value = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{text}' is not a whole number") from None
        if not low <= value <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return value
    return parse


_count = _int_between(1, 100)
_port = _int_between(1, 65535)
_hops = _int_between(1, 64)
_workers = _int_between(1, 500)
_probes = _int_between(1, 10_000_000)


def build_parser() -> argparse.ArgumentParser:
    # Options every subcommand shares live on a "parent" parser.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="print JSON instead of a table")
    common.add_argument("--save", metavar="FILE",
                        help="also save a report (.json or .html); the folder must exist")
    common.add_argument("--force", action="store_true", help="let --save replace an existing file")

    parser = argparse.ArgumentParser(
        prog="netscope",
        description="NetScope: check reachability, ports, DNS, routes and websites on networks you own.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"netscope {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    def add(name: str, help_text: str, description: str) -> argparse.ArgumentParser:
        return sub.add_parser(name, parents=[common], help=help_text, description=description,
                              epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)

    p = add("ping", "check if a host is reachable and how fast it answers",
            "Ping a host with the system ping (ICMP), falling back to timing TCP connections "
            "when ping isn't available. No administrator rights needed.")
    p.add_argument("host", help="host name or IP address, e.g. 192.168.1.1 or localhost")
    p.add_argument("-c", "--count", type=_count, default=4, help="number of pings, 1-100 (default 4)")
    p.add_argument("-t", "--timeout", type=_timeout, default=2.0,
                   help=f"seconds to wait for each reply, up to {MAX_TIMEOUT:g} (default 2)")
    p.add_argument("--method", choices=["auto", "icmp", "tcp"], default="auto",
                   help="auto (default) tries ICMP then TCP")
    p.add_argument("--port", type=_port, default=80, help="port for the TCP method, 1-65535 (default 80)")

    p = add("scan", "scan TCP ports on a host or small range you own",
            f"Scan TCP ports with a pool of threads. Loopback and private networks are allowed; "
            f"carrier-grade NAT (100.64.0.0/10) and public ranges larger than /24 are refused "
            f"unless you pass --i-own-this. {RESPONSIBLE_USE}")
    p.add_argument("target", help="host, IP or CIDR range, e.g. localhost, 192.168.1.10, 192.168.1.0/28")
    p.add_argument("-p", "--ports", default="common",
                   help="ports: 'common' (default), 'all', or a list like 22,80,8000-8100")
    p.add_argument("-t", "--timeout", type=_timeout, default=portscan.DEFAULT_TIMEOUT,
                   help=f"seconds to wait per port (default {portscan.DEFAULT_TIMEOUT:g}; "
                        "2 on Windows, which retries refused connections)")
    p.add_argument("-w", "--workers", type=_workers, default=portscan.DEFAULT_WORKERS,
                   help=f"ports checked at the same time, 1-500 (default {portscan.DEFAULT_WORKERS})")
    p.add_argument("--show-closed", action="store_true", help="list closed and filtered ports too")
    p.add_argument("--i-own-this", action="store_true",
                   help="confirm you own, or have written permission to scan, this target")
    p.add_argument("--max-probes", type=_probes, default=MAX_PROBES,
                   help=f"most connection attempts (addresses x ports) in one scan "
                        f"(default {MAX_PROBES:,})")

    p = add("dns", "look up a host name's addresses, or an IP's name",
            "Forward lookup (A and AAAA records) for a name, or reverse lookup (PTR) for an IP, "
            "using the operating system's resolver.")
    p.add_argument("name", help="host name (example.com) or IP address (8.8.8.8)")
    p.add_argument("-r", "--reverse", action="store_true", help="also reverse-look-up each address found")

    p = add("trace", "show the routers between you and a host",
            "Traceroute-style hop list using the system's tracert/traceroute/tracepath, "
            "so no administrator rights are needed.")
    p.add_argument("host", help="host name or IP address")
    p.add_argument("-m", "--max-hops", type=_hops, default=trace_mod.DEFAULT_MAX_HOPS,
                   help=f"maximum hops, 1-64 (default {trace_mod.DEFAULT_MAX_HOPS})")
    p.add_argument("-t", "--timeout", type=_timeout, default=trace_mod.DEFAULT_TIMEOUT,
                   help="seconds to wait per hop (default 2)")

    add("info", "show this computer's host name, IP and interfaces",
        "Host name, local IP address and network interfaces (interfaces need psutil).")

    p = add("http", "check a website's status, speed, headers and certificate",
            "Request a URL and report the status code, response time, key headers and, "
            "for https, the TLS version and certificate expiry.")
    p.add_argument("url", help="URL, e.g. https://example.com (https:// is added if missing)")
    p.add_argument("-t", "--timeout", type=_timeout, default=httpcheck.DEFAULT_TIMEOUT,
                   help="seconds to wait on each step (default 5)")
    p.add_argument("--deadline", type=_timeout, default=None,
                   help="seconds for the whole check, redirects included (default 3 x timeout)")
    p.add_argument("--no-redirects", action="store_true", help="don't follow redirects")
    p.add_argument("--head", action="store_true", help="send HEAD instead of GET (no body)")

    p = add("latency", "latency summary to a few public servers",
            "Time TCP connections to Cloudflare, Google DNS and Quad9 to get a quick "
            "picture of your internet latency.")
    p.add_argument("-c", "--count", type=_count, default=3, help="connections per server (default 3)")
    p.add_argument("-t", "--timeout", type=_timeout, default=2.0, help="seconds per attempt (default 2)")
    return parser


def _safe_stdout() -> None:
    """Never crash on a character the console can't show (e.g. cp1252 on Windows):
    print it as an escape such as "\\u4e2d" instead."""
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(errors="backslashreplace")
        except (ValueError, OSError):
            pass


def _is_terminal() -> bool:
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def run(argv: Optional[Sequence[str]] = None) -> int:
    """Parse the arguments, run one subcommand, print/save its output, return the exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)  # exits with code 2 on bad arguments
    if not args.command:
        parser.print_help()
        return EXIT_USAGE
    if args.save:
        # Check the report path BEFORE doing any work, so a typo isn't found
        # only after a long scan.
        try:
            check_report_path(args.save, args.force)
        except ValueError as exc:
            parser.error(f"--save: {exc}")

    _safe_stdout()
    color = use_color() and not args.json
    try:
        outcome = HANDLERS[args.command](args, color)
    except CommandError as exc:
        print(f"netscope {args.command}: {exc}", file=sys.stderr)
        return exc.code

    document = envelope(args.command, outcome.data)
    # Save first, so the report isn't lost if printing fails.
    saved = None
    if args.save:
        try:
            saved = save_report(args.save, document, force=args.force)
        except (OSError, ValueError) as exc:
            # The check itself still ran: warn, but keep its exit code.
            print(f"Warning: could not save report: {exc}", file=sys.stderr)
    try:
        # Plain-ASCII JSON when redirected to a file or pipe, so it's valid
        # whatever encoding the console would have used.
        print(to_json(document, ascii_only=not _is_terminal()) if args.json else outcome.text)
    except BrokenPipeError:
        # The reader went away (e.g. piped into "head"); that's not our error.
        sys.stderr.close()
        return outcome.code
    if saved:
        print(f"Report saved to {saved}", file=sys.stderr)
    return outcome.code


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point: like ``run``, but never shows a traceback."""
    try:
        return run(argv)
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        return EXIT_INTERRUPTED
    except Exception as exc:  # last resort: one readable line instead of a traceback
        print(f"netscope: unexpected error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return EXIT_NETWORK


if __name__ == "__main__":
    sys.exit(main())
