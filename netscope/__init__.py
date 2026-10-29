"""NetScope: a small, friendly command-line toolkit for checking networks you own.

Each feature lives in its own module so it can be read, tested and explained
on its own:

    ping.py      is a host reachable, and how fast does it answer?
    portscan.py  which TCP ports are open on a host?
    dns.py       what addresses does a name point to (and back again)?
    trace.py     which routers does traffic pass through on the way?
    netinfo.py   what does this computer's own network setup look like?
    httpcheck.py does a website answer, how fast, and when does its certificate expire?
    latency.py   how quickly do a few well-known public servers answer?

The command-line interface (``__main__.py``) only parses arguments and prints
results; the real work happens in the modules above.

Added in v0.1.0
"""

__version__ = "0.1.0"

# Shown by the CLI and the README. Scanning other people's networks can break
# the law or a school/work policy, so the tool says so up front.
RESPONSIBLE_USE = (
    "Only scan or probe networks and devices you own or have written permission to test."
)
