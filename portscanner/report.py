"""
HTML Report Generator for PortHawk.
Generates a self-contained, styled HTML report from scan results.
"""

import time
from .scanner import ScanResult


def generate_html_report(result: ScanResult, extra: dict = None) -> str:
    """
    Generate a complete standalone HTML report.
    extra = {"whois": str, "dns": dict, "traceroute": list, "http_headers": dict, "ssl": dict}
    """
    extra = extra or {}
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    open_count = len(result.open_ports)

    # Build ports table rows
    port_rows = ""
    for p in result.ports:
        if p.state != "open":
            continue
        badge = f'<span class="badge open">OPEN</span>'
        port_rows += f"""
        <tr>
          <td><strong>{p.port}</strong></td>
          <td>{badge}</td>
          <td>{p.service or "—"}</td>
          <td>{p.latency_ms}ms</td>
          <td class="banner">{_esc(p.banner) or "—"}</td>
        </tr>"""

    if not port_rows:
        port_rows = '<tr><td colspan="5" style="text-align:center;color:#888">No open ports found</td></tr>'

    # Whois section
    whois_html = ""
    if extra.get("whois"):
        whois_html = f"""
        <section>
          <h2>🔍 WHOIS</h2>
          <pre class="code">{_esc(extra['whois'])}</pre>
        </section>"""

    # DNS section
    dns_html = ""
    if extra.get("dns"):
        d = extra["dns"]
        ips = ", ".join(d.get("ips", d.get("A", []))) or "—"
        rev  = d.get("reverse", d.get("PTR", "")) or "—"
        dns_html = f"""
        <section>
          <h2>🌐 DNS Lookup</h2>
          <table><tr><th>Type</th><th>Value</th></tr>
          <tr><td>A (IP)</td><td>{_esc(ips)}</td></tr>
          <tr><td>PTR (Reverse)</td><td>{_esc(rev)}</td></tr>
          </table>
        </section>"""

    # Traceroute section
    tr_html = ""
    if extra.get("traceroute"):
        rows = ""
        for hop in extra["traceroute"]:
            rows += f"<tr><td>{hop['hop']}</td><td>{hop['ip']}</td><td>{hop.get('hostname','')}</td><td>{hop.get('latency_ms',0)}ms</td></tr>"
        tr_html = f"""
        <section>
          <h2>🛤️ Traceroute</h2>
          <table><tr><th>Hop</th><th>IP</th><th>Hostname</th><th>Latency</th></tr>
          {rows}</table>
        </section>"""

    # HTTP Headers section
    http_html = ""
    if extra.get("http_headers"):
        h = extra["http_headers"]
        if h.get("status"):
            rows = f'<tr><td>Status</td><td>{_esc(h["status"])}</td></tr>'
            for k, v in (h.get("headers") or {}).items():
                rows += f"<tr><td>{_esc(k)}</td><td>{_esc(str(v))}</td></tr>"
            http_html = f"""
            <section>
              <h2>🌍 HTTP Headers</h2>
              <table><tr><th>Header</th><th>Value</th></tr>{rows}</table>
            </section>"""

    # SSL section
    ssl_html = ""
    if extra.get("ssl"):
        s = extra["ssl"]
        if s:
            sans = ", ".join(s.get("sans", [])) or "—"
            ssl_html = f"""
            <section>
              <h2>🔒 SSL/TLS Certificate</h2>
              <table>
              <tr><th>Field</th><th>Value</th></tr>
              <tr><td>Common Name</td><td>{_esc(s.get('common_name',''))}</td></tr>
              <tr><td>Issuer</td><td>{_esc(s.get('issuer',''))}</td></tr>
              <tr><td>TLS Version</td><td>{_esc(s.get('tls_version',''))}</td></tr>
              <tr><td>Cipher</td><td>{_esc(s.get('cipher',''))}</td></tr>
              <tr><td>Expires</td><td>{_esc(s.get('not_after',''))}</td></tr>
              <tr><td>SANs</td><td>{_esc(sans)}</td></tr>
              </table>
            </section>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PortHawk Report — {_esc(result.host)}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --green: #3fb950;
    --yellow: #d29922; --red: #f85149; --blue: #58a6ff;
    --accent: #1f6feb;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.1rem; margin: 2rem 0 0.75rem; color: var(--blue); border-bottom: 1px solid var(--border); padding-bottom: 0.4rem; }}
  .meta {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 2rem; }}
  .stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; }}
  .stat .val {{ font-size: 2rem; font-weight: 700; color: var(--green); }}
  .stat .lbl {{ font-size: 0.75rem; color: var(--muted); margin-top: 0.2rem; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }}
  th {{ background: #21262d; padding: 0.6rem 1rem; text-align: left; font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 0.6rem 1rem; border-top: 1px solid var(--border); font-size: 0.9rem; }}
  tr:hover td {{ background: #1c2128; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  .badge.open {{ background: #1a4a2e; color: var(--green); border: 1px solid #238636; }}
  .banner {{ font-family: monospace; font-size: 0.8rem; color: var(--muted); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  pre.code {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap; color: var(--muted); max-height: 300px; overflow-y: auto; }}
  section {{ margin-bottom: 1.5rem; }}
  footer {{ margin-top: 3rem; color: var(--muted); font-size: 0.75rem; text-align: center; }}
  .hawk {{ font-size: 2rem; }}
</style>
</head>
<body>

<h1><span class="hawk">🦅</span> PortHawk Scan Report</h1>
<p class="meta">Generated: {now} &nbsp;|&nbsp; Target: <strong>{_esc(result.host)}</strong> ({_esc(result.ip)}) &nbsp;|&nbsp; Type: {result.scan_type.upper()} &nbsp;|&nbsp; Duration: {result.duration}s</p>

<div class="stats">
  <div class="stat"><div class="val">{open_count}</div><div class="lbl">Open Ports</div></div>
  <div class="stat"><div class="val">{len(result.ports)}</div><div class="lbl">Ports Scanned</div></div>
  <div class="stat"><div class="val">{result.duration}s</div><div class="lbl">Duration</div></div>
  <div class="stat"><div class="val">{result.scan_type.upper()}</div><div class="lbl">Scan Type</div></div>
</div>

<section>
  <h2>🔌 Open Ports</h2>
  <table>
    <tr><th>Port</th><th>State</th><th>Service</th><th>Latency</th><th>Banner / Version</th></tr>
    {port_rows}
  </table>
</section>

{dns_html}
{whois_html}
{ssl_html}
{http_html}
{tr_html}

<footer>PortHawk v2.0 — Only scan systems you own or have permission to test.</footer>
</body>
</html>"""

    return html


def _esc(text: str) -> str:
    """HTML escape."""
    if not text:
        return ""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
