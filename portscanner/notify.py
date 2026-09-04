"""
Notifications: Telegram, Email alerts.
PDF + XML report generation.
"""

import json
import smtplib
import ssl
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


# ─── TELEGRAM ───────────────────────────────────────────────────────────────

def send_telegram(bot_token: str, chat_id: str, message: str, timeout: float = 10.0) -> bool:
    """Send scan results to Telegram."""
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown",
    }).encode()
    try:
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = json.loads(r.read())
            return resp.get("ok", False)
    except Exception as e:
        print(f"  Telegram error: {e}")
        return False


def format_telegram_message(result, findings=None) -> str:
    """Format scan result for Telegram."""
    lines = [
        f"🦅 *PortHawk Scan Report*",
        f"🎯 Target: `{result.host}` ({result.ip})",
        f"⏱ Duration: {result.duration}s",
        f"🔓 Open ports: {len(result.open_ports)}",
        "",
    ]
    for p in result.open_ports:
        info = p.version or p.banner or ""
        lines.append(f"  • `{p.port}/tcp` {p.service} {info[:30]}")

    if findings:
        vulns = [f for f in findings if f.get("vuln")]
        if vulns:
            lines.append(f"\n⚠️ *Vulnerabilities Found: {len(vulns)}*")
            for v in vulns[:5]:
                lines.append(f"  🔴 Port {v['port']}: {v['name']}")

    lines.append(f"\n_Scan by PortHawk v2.0_")
    return "\n".join(lines)


# ─── EMAIL ──────────────────────────────────────────────────────────────────

def send_email(
    smtp_host: str,
    smtp_port: int,
    sender: str,
    password: str,
    recipient: str,
    subject: str,
    body: str,
) -> bool:
    """Send scan results via email."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = recipient
        msg.attach(MIMEText(body, "html"))

        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx) as server:
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())
        return True
    except Exception as e:
        print(f"  Email error: {e}")
        return False


def format_email_body(result, findings=None) -> str:
    """Format HTML email body."""
    open_rows = ""
    for p in result.open_ports:
        info = p.version or p.banner or "—"
        open_rows += f"<tr><td>{p.port}/tcp</td><td>{p.service}</td><td>{info[:60]}</td></tr>"

    vuln_rows = ""
    if findings:
        for f in [x for x in findings if x.get("vuln")]:
            vuln_rows += f"<tr style='color:red'><td>{f['port']}</td><td>{f['name']}</td><td>{f['detail'][:80]}</td></tr>"

    return f"""
    <html><body style='font-family:sans-serif'>
    <h2>🦅 PortHawk Scan Report</h2>
    <p><b>Target:</b> {result.host} ({result.ip})<br>
    <b>Duration:</b> {result.duration}s<br>
    <b>Open Ports:</b> {len(result.open_ports)}</p>
    <h3>Open Ports</h3>
    <table border='1' cellpadding='5'>
    <tr><th>Port</th><th>Service</th><th>Version/Banner</th></tr>
    {open_rows}
    </table>
    {'<h3>Vulnerabilities</h3><table border=1 cellpadding=5><tr><th>Port</th><th>Check</th><th>Detail</th></tr>' + vuln_rows + '</table>' if vuln_rows else ''}
    <p><i>PortHawk v2.0</i></p>
    </body></html>
    """


# ─── XML OUTPUT ─────────────────────────────────────────────────────────────

def to_xml(result, findings=None) -> str:
    """Generate Nmap-compatible XML output."""
    root = ET.Element("nmaprun", {
        "scanner": "porthawk",
        "args": f"porthawk {result.host}",
        "start": str(int(result.start_time)),
        "version": "2.0",
    })

    host_el = ET.SubElement(root, "host")
    ET.SubElement(host_el, "status", state="up")
    ET.SubElement(host_el, "address", addr=result.ip, addrtype="ipv4")

    hostnames = ET.SubElement(host_el, "hostnames")
    ET.SubElement(hostnames, "hostname", name=result.host, type="user")

    ports_el = ET.SubElement(host_el, "ports")
    for p in result.open_ports:
        port_el = ET.SubElement(ports_el, "port", protocol="tcp", portid=str(p.port))
        ET.SubElement(port_el, "state", state=p.state)
        ET.SubElement(port_el, "service", name=p.service, product=p.version or "")
        if p.banner:
            script = ET.SubElement(port_el, "script", id="banner")
            script.set("output", p.banner)

    if findings:
        scripts = ET.SubElement(host_el, "hostscript")
        for f in [x for x in findings if x.get("vuln")]:
            s = ET.SubElement(scripts, "script", id=f["name"].lower().replace(" ", "-"))
            s.set("output", f["detail"])

    times = ET.SubElement(host_el, "times")
    runstats = ET.SubElement(root, "runstats")
    finished = ET.SubElement(runstats, "finished",
        time=str(int(result.end_time)),
        elapsed=str(result.duration))

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


# ─── PDF REPORT ─────────────────────────────────────────────────────────────

def to_pdf_html(result, findings=None) -> str:
    """
    Generate print-ready HTML that can be saved as PDF via browser.
    (Pure Python — no external PDF lib needed)
    """
    from .report import generate_html_report
    extra = {}
    if findings:
        extra["vuln_findings"] = findings
    html = generate_html_report(result, extra)
    # Add print stylesheet
    html = html.replace("</head>",
        "<style>@media print{body{background:#fff;color:#000}}</style></head>")
    return html
