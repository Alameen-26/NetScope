# Test data

- `ping_*.txt` / `ping_*.bin`, `tracert_*.bin`, `traceroute_*.txt`: output of
  the system tools in different languages and formats. The `.bin` files hold
  raw bytes in the Windows console code page (cp850 for German and French,
  cp866 for Russian), exactly as `ping.exe`/`tracert.exe` write them. They are stored
  base64-encoded (`*.bin.b64`) so the repository holds only text files; the
  tests decode them back to the original bytes.
- `expired_*.pem`, `valid_*.pem`: self-signed certificates and keys for
  `localhost` / `127.0.0.1`, used only by the local HTTPS test servers. The
  "expired" one ran out on 2021-01-01. These keys protect nothing.
