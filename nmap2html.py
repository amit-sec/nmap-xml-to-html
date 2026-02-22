#!/usr/bin/env python3
"""
nmap2html.py  -  Professional Nmap XML to HTML Report Generator
================================================================
Coded by  : Amit Prajapati & Claude AI
Inspired by / extends: nmap-parse (github.com/jonathonorr/nmap-parse)

Enhancements:
  * Zero pip dependencies (pure Python 3.9 stdlib)
  * Multi-file input (glob / directory / individual XMLs)
  * Beautiful dark-themed HTML report with:
      - Executive summary cards + bar charts
      - Per-host cards with OS, MAC vendor, uptime, hostname
      - Full port tables with service/version/CPE/scripts
      - Risk-based row colouring
      - Live search + status filter
      - Unique open ports section
      - Service matrix (which IPs expose each service)
      - CSV export (all open ports)
      - Clipboard copy in IP:PORT format
  * CLI compatible with nmap-parse flags (-p, --service, -r, etc.)

Usage:
  python3 nmap2html.py scan.xml
  python3 nmap2html.py scans/ -o report.html -r
  python3 nmap2html.py a.xml b.xml -p 80,443 -o filtered.html
  python3 nmap2html.py -i scan.xml
"""

import os, sys, re, copy, ipaddress, argparse, glob
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict


# =====================================================
#  CONSTANTS
# =====================================================
PROTOCOLS = ["tcp", "udp"]

RISKY_PORTS = {"21","23","69","110","111","135","137","139","445",
               "512","513","514","1099","1433","2049","3389","4848",
               "5900","5985","6379","8443","27017","50000"}
INTERESTING_PORTS = {"22","25","53","80","443","3306","5432",
                     "8080","8888","9200","9300","11211","15672"}


# =====================================================
#  DATA MODELS  (mirrors nmap-parse class structure)
# =====================================================

class NmapPort:
    def __init__(self, protocol, port_id, service, product="",
                 version="", extrainfo="", ostype="", method="",
                 conf="", cpe=None, scripts=None, state="open", reason=""):
        self.protocol  = protocol
        self.portId    = int(port_id)
        self.service   = service
        self.product   = product
        self.version   = version
        self.extrainfo = extrainfo
        self.ostype    = ostype
        self.method    = method
        self.conf      = conf
        self.cpe       = cpe or []
        self.scripts   = scripts or []
        self.state     = state
        self.reason    = reason
        self.matched   = True

    @property
    def version_string(self):
        parts = [self.product, self.version, self.extrainfo]
        return " ".join(p for p in parts if p).strip()


class NmapHost:
    def __init__(self, ip):
        self.ip            = ip
        self.hostname      = ""
        self.alive         = False
        self.reason        = ""
        self.ports         = []
        self.os_matches    = []
        self.mac           = ""
        self.mac_vendor    = ""
        self.uptime_secs   = ""
        self.last_boot     = ""
        self.distance      = ""
        self.host_scripts  = []
        self.start_ts      = ""
        self.end_ts        = ""
        self.filesWithHost = []
        self.matched       = True

    def getState(self):
        return "up" if self.alive else "down"

    def getHostname(self):
        return self.hostname if self.hostname and self.hostname != self.ip else ""

    def addPort(self, port):
        for p in self.ports:
            if p.portId == port.portId and p.protocol == port.protocol:
                if not p.service:
                    p.service = port.service
                return
        self.ports.append(port)

    def getUniquePortIds(self, protocol="", port_filter=None, service_filter=None):
        port_filter    = port_filter or []
        service_filter = service_filter or []
        ids = set()
        for p in self.ports:
            if p.state != "open":
                continue
            if protocol and p.protocol != protocol:
                continue
            if port_filter and p.portId not in port_filter:
                continue
            if service_filter and p.service not in service_filter:
                continue
            ids.add(p.portId)
        return sorted(ids)

    @property
    def os_name(self):
        return self.os_matches[0]["name"] if self.os_matches else ""

    @property
    def os_accuracy(self):
        return self.os_matches[0]["accuracy"] if self.os_matches else ""


class NmapService:
    def __init__(self, name):
        self.name  = name
        self.hosts = []
        self.ports = []


class NmapFilters:
    def __init__(self, default=True):
        self.hosts         = []
        self.ports         = []
        self.services      = []
        self.mustHavePorts = default
        self.onlyAlive     = default

    def portFilterSet(self):    return bool(self.ports)
    def serviceFilterSet(self): return bool(self.services)
    def hostFilterSet(self):    return bool(self.hosts)
    def areFiltersSet(self):
        return any([self.hostFilterSet(), self.portFilterSet(),
                    self.serviceFilterSet(), self.mustHavePorts, self.onlyAlive])

    def checkHost(self, ip):
        if not self.hostFilterSet():
            return True
        if ip in self.hosts:
            return True
        for f in self.hosts:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(f, strict=False):
                    return True
            except ValueError:
                pass
        return False


# =====================================================
#  PARSER
# =====================================================

class NmapOutput:
    """Parses one or more Nmap XML files into structured objects."""

    def __init__(self, xml_files):
        self.FilesImported       = []
        self.FilesFailedToImport = []
        self.Hosts               = {}
        self.Services            = []
        self.ScanMeta            = []
        self._parse_files(xml_files)

    @staticmethod
    def find_xml_files(path, recurse=False):
        if os.path.isfile(path):
            return [path]
        files = []
        if recurse:
            for root, _, fnames in os.walk(path):
                for f in fnames:
                    if f.endswith(".xml"):
                        files.append(os.path.join(root, f))
        else:
            files = [os.path.join(path, f)
                     for f in os.listdir(path) if f.endswith(".xml")]
        return files

    def _parse_files(self, xml_files):
        for i, fpath in enumerate(xml_files):
            fpath = os.path.abspath(os.path.expanduser(fpath))
            if fpath in self.FilesImported:
                continue
            print(f"  [{i+1}/{len(xml_files)}] {fpath}")
            try:
                tree = ET.parse(fpath)
            except Exception as e:
                print(f"  [WARN] Failed to parse: {e}", file=sys.stderr)
                self.FilesFailedToImport.append(fpath)
                continue
            self.FilesImported.append(fpath)
            self._parse_tree(tree, fpath)

    def _parse_tree(self, tree, source_file):
        root = tree.getroot()
        meta = {
            "file":    source_file,
            "args":    root.get("args", ""),
            "version": root.get("version", ""),
            "start":   root.get("startstr", ""),
            "scanner": root.get("scanner", "nmap"),
        }
        si = root.find("scaninfo")
        if si is not None:
            meta["type"]        = si.get("type", "")
            meta["protocol"]    = si.get("protocol", "")
            meta["numservices"] = si.get("numservices", "")
        finished = root.find("runstats/finished")
        if finished is not None:
            meta["end"]     = finished.get("timestr", "")
            meta["elapsed"] = finished.get("elapsed", "0")
            meta["summary"] = finished.get("summary", "")
        hosts_el = root.find("runstats/hosts")
        if hosts_el is not None:
            meta["total"] = hosts_el.get("total", "0")
            meta["up"]    = hosts_el.get("up", "0")
            meta["down"]  = hosts_el.get("down", "0")
        self.ScanMeta.append(meta)

        for host_el in root.findall("host"):
            self._parse_host(host_el, source_file)

    def _parse_host(self, host_el, source_file):
        ipv4 = host_el.find("address[@addrtype='ipv4']")
        ipv6 = host_el.find("address[@addrtype='ipv6']")
        ip_el = ipv4 if ipv4 is not None else ipv6
        if ip_el is None:
            return
        ip = ip_el.get("addr", "")
        if not ip:
            return

        if ip not in self.Hosts:
            self.Hosts[ip] = NmapHost(ip)
        host = self.Hosts[ip]

        if source_file not in host.filesWithHost:
            host.filesWithHost.append(source_file)

        status_el = host_el.find("status")
        if status_el is not None:
            host.alive  = status_el.get("state", "") == "up"
            host.reason = status_el.get("reason", "")

        mac_el = host_el.find("address[@addrtype='mac']")
        if mac_el is not None:
            host.mac        = mac_el.get("addr", "")
            host.mac_vendor = mac_el.get("vendor", "")

        host.start_ts = host_el.get("starttime", "")
        host.end_ts   = host_el.get("endtime", "")

        hn = host_el.find(".//hostname")
        if hn is not None and (not host.hostname or host.hostname == ip):
            host.hostname = hn.get("name", "")

        for osm in host_el.findall("os/osmatch"):
            match = {"name": osm.get("name",""), "accuracy": osm.get("accuracy","")}
            if match not in host.os_matches:
                host.os_matches.append(match)

        up_el = host_el.find("uptime")
        if up_el is not None:
            host.uptime_secs = up_el.get("seconds","")
            host.last_boot   = up_el.get("lastboot","")

        dist_el = host_el.find("distance")
        if dist_el is not None:
            host.distance = dist_el.get("value","")

        for sc in host_el.findall("hostscript/script"):
            entry = {"id": sc.get("id",""), "output": sc.get("output","")}
            if entry not in host.host_scripts:
                host.host_scripts.append(entry)

        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            state  = state_el.get("state","")  if state_el is not None else ""
            reason = state_el.get("reason","") if state_el is not None else ""

            svc_el = port_el.find("service")
            svc_name = product = version = extrainfo = ostype = method = conf = ""
            cpe_list = []
            if svc_el is not None:
                svc_name  = svc_el.get("name","")
                product   = svc_el.get("product","")
                version   = svc_el.get("version","")
                extrainfo = svc_el.get("extrainfo","")
                ostype    = svc_el.get("ostype","")
                method    = svc_el.get("method","")
                conf      = svc_el.get("conf","")
                cpe_list  = [c.text for c in svc_el.findall("cpe") if c.text]

            scripts = [{"id": sc.get("id",""), "output": sc.get("output","")}
                       for sc in port_el.findall("script")]

            port = NmapPort(
                protocol  = port_el.get("protocol",""),
                port_id   = port_el.get("portid","0"),
                service   = svc_name, product=product, version=version,
                extrainfo = extrainfo, ostype=ostype, method=method,
                conf=conf, cpe=cpe_list, scripts=scripts,
                state=state, reason=reason,
            )
            host.addPort(port)

            if state == "open":
                self._add_service(svc_name, ip, int(port_el.get("portid","0")))

    def _add_service(self, name, ip, port_id):
        svc = next((s for s in self.Services if s.name == name), None)
        if svc is None:
            svc = NmapService(name)
            self.Services.append(svc)
        if ip not in svc.hosts:
            svc.hosts.append(ip)
        if port_id not in svc.ports:
            svc.ports.append(port_id)

    def getHosts(self, filters=None):
        if filters is None:
            filters = NmapFilters(default=False)
        result = []
        for ip in self._sorted_ips():
            host = copy.deepcopy(self.Hosts[ip])
            if filters.onlyAlive and not host.alive:
                continue
            if not filters.checkHost(ip):
                continue
            if filters.mustHavePorts and not host.ports:
                continue
            for p in host.ports:
                p.matched = True
                if filters.portFilterSet() and p.portId not in filters.ports:
                    p.matched = False
                if filters.serviceFilterSet() and p.service not in filters.services:
                    p.matched = False
            result.append(host)
        return result

    def getAliveHosts(self, filters=None):
        return [h.ip for h in self.getHosts(filters) if h.alive]

    def getServices(self, filters=None):
        if filters is None:
            return self.Services
        result = []
        for svc in self.Services:
            if filters.serviceFilterSet() and svc.name not in filters.services:
                continue
            if filters.portFilterSet() and not any(p in filters.ports for p in svc.ports):
                continue
            result.append(svc)
        return result

    def getUniquePortIds(self, protocol="combined", filters=None):
        all_ids = set()
        for host in self.getHosts(filters):
            pf = filters.ports    if filters else []
            sf = filters.services if filters else []
            if protocol in ("tcp","udp"):
                all_ids |= set(host.getUniquePortIds(protocol, pf, sf))
            else:
                all_ids |= set(host.getUniquePortIds("tcp", pf, sf))
                all_ids |= set(host.getUniquePortIds("udp", pf, sf))
        return sorted(all_ids)

    def _sorted_ips(self):
        try:
            return sorted(self.Hosts.keys(),
                          key=lambda ip: [int(x) for x in ip.split(".")])
        except Exception:
            return sorted(self.Hosts.keys())


# =====================================================
#  STATS
# =====================================================

def compute_stats(nmap_out, filters):
    hosts = nmap_out.getHosts(filters)
    open_c = filtered_c = closed_c = up = down = 0
    svc_cnt  = defaultdict(int)
    port_cnt = defaultdict(int)

    for host in hosts:
        if host.alive: up   += 1
        else:          down += 1
        for p in host.ports:
            if p.state == "open":
                open_c += 1
                svc_cnt[p.service or "unknown"] += 1
                port_cnt[str(p.portId)] += 1
            elif p.state == "filtered": filtered_c += 1
            elif p.state == "closed":   closed_c   += 1

    return {
        "hosts_up":       up,
        "hosts_down":     down,
        "total_open":     open_c,
        "total_filtered": filtered_c,
        "total_closed":   closed_c,
        "top_services":   sorted(svc_cnt.items(), key=lambda x: -x[1])[:12],
        "top_ports":      sorted(port_cnt.items(), key=lambda x: -x[1])[:12],
        "unique_tcp":     nmap_out.getUniquePortIds("tcp", filters),
        "unique_udp":     nmap_out.getUniquePortIds("udp", filters),
    }


# =====================================================
#  HTML HELPERS
# =====================================================

def esc(text):
    return (str(text)
            .replace("&","&amp;").replace("<","&lt;")
            .replace(">","&gt;").replace('"',"&quot;"))

def state_badge(state):
    cls_map = {"open":"open-badge","closed":"closed-badge","filtered":"filtered-badge"}
    cls = cls_map.get(state, "unknown-badge")
    return f'<span class="badge {cls}">{esc(state)}</span>'

def host_badge(status):
    cls = "host-up" if status == "up" else "host-down"
    return f'<span class="hbadge {cls}">{status.upper()}</span>'

def row_class(port_id):
    s = str(port_id)
    if s in RISKY_PORTS:       return "row-risky"
    if s in INTERESTING_PORTS: return "row-interesting"
    return ""

def bar_chart(items, css_extra=""):
    if not items:
        return '<p class="dim" style="font-size:12px">No data</p>'
    max_val = items[0][1] if items else 1
    html = ""
    for label, cnt in items:
        pct = int(cnt / max_val * 100)
        html += (f'<div class="bar-row">'
                 f'<span class="bar-lbl">{esc(label)}</span>'
                 f'<div class="bar-track"><div class="bar-fill {css_extra}" style="width:{pct}%"></div></div>'
                 f'<span class="bar-cnt">{cnt}</span></div>')
    return html


# =====================================================
#  HOST CARD
# =====================================================

def render_host_card(host, idx):
    open_ports     = [p for p in host.ports if p.state == "open"]
    closed_ports   = [p for p in host.ports if p.state == "closed"]
    filtered_ports = [p for p in host.ports if p.state == "filtered"]

    pills = ""
    for p in open_ports[:24]:
        label = p.service or str(p.portId)
        tip   = esc(p.version_string)
        pills += (f'<span class="ppill" title="{tip}">'
                  f'{p.portId}/{p.protocol} {esc(label)}</span>')
    if len(open_ports) > 24:
        pills += f'<span class="ppill more">+{len(open_ports)-24} more</span>'

    port_rows = ""
    for p in sorted(host.ports, key=lambda p: (p.state != "open", p.protocol, p.portId)):
        sc_html = ""
        for sc in p.scripts:
            sc_html += (f'<div class="sc-wrap"><span class="sc-id">{esc(sc["id"])}</span>'
                        f'<pre class="sc-out">{esc(sc["output"][:400])}</pre></div>')
        port_rows += (
            f'<tr class="{row_class(p.portId)}">'
            f'<td><strong>{p.portId}</strong></td>'
            f'<td>{esc(p.protocol.upper())}</td>'
            f'<td>{state_badge(p.state)}</td>'
            f'<td>{esc(p.service)}</td>'
            f'<td>{esc(p.version_string)}</td>'
            f'<td class="cpe-cell">{esc(", ".join(p.cpe))}</td>'
            f'<td>{sc_html}</td></tr>'
        )

    hsc_html = ""
    for sc in host.host_scripts:
        hsc_html += (f'<div class="sc-wrap"><span class="sc-id">{esc(sc["id"])}</span>'
                     f'<pre class="sc-out">{esc(sc["output"][:600])}</pre></div>')

    # Meta row parts
    os_html   = (f'<div class="mi"><span class="ml">OS</span>{esc(host.os_name)}'
                 f'{"<span class=acc>("+esc(host.os_accuracy)+"%)</span>" if host.os_accuracy else ""}'
                 f'</div>') if host.os_name else ""
    mac_html  = (f'<div class="mi"><span class="ml">MAC</span>{esc(host.mac)}'
                 f'{"<span class=dim>("+esc(host.mac_vendor)+")</span>" if host.mac_vendor else ""}'
                 f'</div>') if host.mac else ""
    boot_html = (f'<div class="mi"><span class="ml">Last Boot</span>{esc(host.last_boot)}</div>'
                 ) if host.last_boot else ""
    dist_html = (f'<div class="mi"><span class="ml">Hops</span>{esc(host.distance)}</div>'
                 ) if host.distance else ""
    hn = host.getHostname()
    hn_html = f'<span class="hn">{esc(hn)}</span>' if hn else ""
    no_open = '<em class="no-open">No open ports detected</em>' if not open_ports else ""

    return f"""
<div class="host-card" id="host-{idx}" data-status="{host.getState()}">
  <div class="hdr">
    <div class="htitle">
      <h2>{esc(host.ip)}</h2>{hn_html}{host_badge(host.getState())}
    </div>
    <div class="hmeta">
      {os_html}{mac_html}{boot_html}{dist_html}
      <div class="mi counts">
        <span class="cnt open-cnt">{len(open_ports)} open</span>
        <span class="cnt filt-cnt">{len(filtered_ports)} filtered</span>
        <span class="cnt close-cnt">{len(closed_ports)} closed</span>
      </div>
    </div>
  </div>
  <div class="pills">{pills}{no_open}</div>
  {"<div class='hsc-section'><h4>Host Scripts</h4>" + hsc_html + "</div>" if hsc_html else ""}
  <div class="tbl-wrap">
    <table class="ptbl">
      <thead>
        <tr><th>Port</th><th>Proto</th><th>State</th>
            <th>Service</th><th>Product / Version</th><th>CPE</th><th>Scripts</th></tr>
      </thead>
      <tbody>
        {port_rows if port_rows else '<tr><td colspan="7" class="nodata">No port data</td></tr>'}
      </tbody>
    </table>
  </div>
</div>"""


# =====================================================
#  SECTION RENDERERS
# =====================================================

def render_service_matrix(nmap_out, filters):
    services = sorted(nmap_out.getServices(filters),
                      key=lambda s: (-len(s.hosts), s.name))[:30]
    if not services:
        return ""
    rows = ""
    for svc in services:
        host_tags = "".join(f'<span class="svc-ip">{esc(ip)}</span>' for ip in svc.hosts)
        rows += (f'<tr><td><strong>{esc(svc.name or "(unknown)")}</strong></td>'
                 f'<td class="mono">{esc(", ".join(str(p) for p in sorted(svc.ports)))}</td>'
                 f'<td><span class="cnt open-cnt">{len(svc.hosts)}</span></td>'
                 f'<td class="svc-hosts">{host_tags}</td></tr>')
    return (f'<div class="section-card"><h3 class="sec-title">🔧 Service Matrix'
            f' <span class="dim">(top 30)</span></h3>'
            f'<div class="tbl-wrap"><table class="ptbl">'
            f'<thead><tr><th>Service</th><th>Ports</th><th>Hosts</th><th>IPs Exposed</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div></div>')


def render_unique_ports(stats):
    tcp = esc(",".join(str(p) for p in stats["unique_tcp"])) or "—"
    udp = esc(",".join(str(p) for p in stats["unique_udp"])) or "—"
    return (f'<div class="section-card"><h3 class="sec-title">🔌 Unique Open Ports</h3>'
            f'<div class="uports-grid">'
            f'<div class="uport-box">'
            f'<div class="uport-label">TCP '
            f'<button class="ebtn" style="padding:2px 8px;font-size:10px;margin-left:6px" '
            f'onclick="copyPorts(\'tcp-ports\')" title="Copy TCP ports">📋 Copy</button>'
            f'</div>'
            f'<div class="uport-val mono" id="tcp-ports">{tcp}</div></div>'
            f'<div class="uport-box">'
            f'<div class="uport-label">UDP '
            f'<button class="ebtn" style="padding:2px 8px;font-size:10px;margin-left:6px" '
            f'onclick="copyPorts(\'udp-ports\')" title="Copy UDP ports">📋 Copy</button>'
            f'</div>'
            f'<div class="uport-val mono" id="udp-ports">{udp}</div></div>'
            f'</div></div>')


def render_scan_info(nmap_out):
    if not nmap_out.ScanMeta:
        return ""
    rows = ""
    for m in nmap_out.ScanMeta:
        rows += (f'<tr>'
                 f'<td class="mono">{esc(os.path.basename(m.get("file","?")))}</td>'
                 f'<td>{esc(m.get("start",""))}</td>'
                 f'<td>{esc(m.get("end",""))}</td>'
                 f'<td>{esc(m.get("elapsed",""))}s</td>'
                 f'<td>{esc(m.get("type",""))}/{esc(m.get("protocol",""))}</td>'
                 f'<td>{esc(m.get("version",""))}</td>'
                 f'<td class="mono" style="font-size:10px;max-width:280px;word-break:break-all">'
                 f'{esc(m.get("args",""))}</td></tr>')
    return (f'<div class="section-card"><h3 class="sec-title">📋 Scan Files</h3>'
            f'<div class="tbl-wrap"><table class="ptbl">'
            f'<thead><tr><th>File</th><th>Start</th><th>End</th><th>Elapsed</th>'
            f'<th>Type</th><th>Ver</th><th>Command</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div></div>')


# =====================================================
#  FULL HTML PAGE
# =====================================================

CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;
  --text:#c9d1d9;--dim:#8b949e;
  --accent:#58a6ff;--green:#3fb950;--red:#f85149;
  --orange:#d29922;--purple:#bc8cff;--cyan:#39c5cf;
  --radius:10px;--shadow:0 4px 24px rgba(0,0,0,.5)
}
html{scroll-behavior:smooth}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
     background:var(--bg);color:var(--text);font-size:14px;line-height:1.6}
/* Layout */
.wrapper{display:flex;min-height:100vh}
.sidebar{width:230px;min-width:230px;background:var(--bg2);border-right:1px solid var(--border);
         position:sticky;top:0;height:100vh;overflow-y:auto;display:flex;flex-direction:column}
.slogo{padding:18px 16px 12px;font-size:17px;font-weight:700;color:var(--accent);
       border-bottom:1px solid var(--border)}
.slogo small{display:block;font-size:10px;color:var(--dim);font-weight:400;margin-top:2px}
.ssec{padding:10px 12px 4px;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--dim)}
.nav-host{display:block;padding:7px 16px;color:var(--text);text-decoration:none;
          border-left:3px solid transparent;font-size:12px;line-height:1.4;transition:.15s}
.nav-host:hover{background:var(--bg3);border-left-color:var(--accent)}
.nav-host.down{opacity:.45}
.nav-open{float:right;background:var(--bg3);border-radius:10px;padding:0 6px;
          font-size:10px;color:var(--green)}
.main{flex:1;padding:28px 32px;overflow-x:auto}
/* Report header */
.rhead{background:linear-gradient(135deg,var(--bg2),#1c2333);border:1px solid var(--border);
       border-radius:var(--radius);padding:26px 30px;margin-bottom:22px;box-shadow:var(--shadow)}
.rtitle{font-size:23px;font-weight:700;color:var(--accent);margin-bottom:4px}
.rsub{color:var(--dim);font-size:12px;margin-bottom:14px}
.mgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(185px,1fr));gap:10px}
.mc{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:10px 14px}
.mclbl{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);margin-bottom:3px}
.mcval{font-size:12px;word-break:break-all}
/* Stat cards */
.srow{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:12px;margin-bottom:22px}
.sc{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);
    padding:16px 18px;text-align:center;box-shadow:var(--shadow);transition:transform .15s}
.sc:hover{transform:translateY(-2px)}
.scn{font-size:34px;font-weight:800;line-height:1}
.scl{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);margin-top:4px}
.sc.blue .scn{color:var(--accent)} .sc.green .scn{color:var(--green)}
.sc.red  .scn{color:var(--red)}   .sc.orange .scn{color:var(--orange)}
.sc.purple .scn{color:var(--purple)} .sc.cyan .scn{color:var(--cyan)}
/* Charts */
.cgrid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:22px}
@media(max-width:800px){.cgrid{grid-template-columns:1fr}.sidebar{display:none}}
.cc{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:16px}
.ctitle{font-size:13px;font-weight:600;margin-bottom:11px}
.bar-row{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.bar-lbl{width:80px;font-size:11px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;
         white-space:nowrap;flex-shrink:0}
.bar-track{flex:1;height:9px;background:var(--bg3);border-radius:5px;overflow:hidden}
.bar-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--cyan));
          border-radius:5px;transition:width .4s}
.bar-fill.pf{background:linear-gradient(90deg,var(--purple),#ff79c6)}
.bar-cnt{font-size:11px;color:var(--dim);width:26px;text-align:right}
/* Section card */
.section-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);
              margin-bottom:22px;box-shadow:var(--shadow)}
.sec-title{font-size:15px;font-weight:700;padding:14px 22px;
           border-bottom:1px solid var(--border);color:var(--text)}
/* Filter bar */
.fbar{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;align-items:center}
.fbar input{flex:1;min-width:200px;background:var(--bg2);border:1px solid var(--border);
            color:var(--text);border-radius:8px;padding:8px 13px;font-size:13px;outline:none}
.fbar input:focus{border-color:var(--accent)}
.fbtn{background:var(--bg3);border:1px solid var(--border);color:var(--dim);border-radius:8px;
      padding:7px 13px;font-size:12px;cursor:pointer;transition:.15s}
.fbtn:hover,.fbtn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
/* Legend */
.legend{display:flex;gap:14px;flex-wrap:wrap;padding:4px 0 12px;font-size:11px;color:var(--dim)}
.li{display:flex;align-items:center;gap:5px}
.ld{width:10px;height:10px;border-radius:2px}
.ld-r{background:rgba(248,81,73,.5);border:1px solid var(--red)}
.ld-i{background:rgba(63,185,80,.3);border:1px solid var(--green)}
/* Host card */
.host-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);
           margin-bottom:20px;box-shadow:var(--shadow);overflow:hidden}
.hdr{background:linear-gradient(135deg,var(--bg3),#1a2030);padding:15px 20px;
     display:flex;justify-content:space-between;align-items:flex-start;
     flex-wrap:wrap;gap:10px;border-bottom:1px solid var(--border)}
.htitle h2{font-size:18px;font-weight:700;color:var(--accent);display:inline;margin-right:8px}
.hn{font-size:12px;color:var(--dim)}
.hbadge{display:inline-block;padding:2px 9px;border-radius:12px;
        font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;margin-left:7px}
.hbadge.host-up{background:rgba(63,185,80,.15);color:var(--green);border:1px solid var(--green)}
.hbadge.host-down{background:rgba(248,81,73,.15);color:var(--red);border:1px solid var(--red)}
.hmeta{display:flex;flex-wrap:wrap;gap:12px;align-items:center}
.mi{font-size:11px;color:var(--dim)}
.ml{color:var(--dim);font-size:9px;text-transform:uppercase;letter-spacing:.6px;margin-right:4px}
.acc{color:var(--orange);font-size:10px}
.counts{display:flex;gap:7px}
.cnt{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.open-cnt{background:rgba(63,185,80,.15);color:var(--green)}
.filt-cnt{background:rgba(210,153,34,.15);color:var(--orange)}
.close-cnt{background:rgba(139,148,158,.1);color:var(--dim)}
/* Pills */
.pills{padding:11px 20px;display:flex;flex-wrap:wrap;gap:5px}
.ppill{background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.25);
       color:var(--accent);border-radius:6px;padding:2px 9px;
       font-size:11px;font-family:monospace;cursor:default;transition:.15s}
.ppill:hover{background:rgba(88,166,255,.2)}
.ppill.more{background:var(--bg3);color:var(--dim);border-color:var(--border)}
.no-open{color:var(--dim);font-size:12px;font-style:italic}
/* Port table */
.tbl-wrap{overflow-x:auto;padding:0 0 4px}
.ptbl{width:100%;border-collapse:collapse;font-size:12.5px}
.ptbl thead tr{background:var(--bg3)}
.ptbl th{padding:9px 13px;text-align:left;font-size:10px;text-transform:uppercase;
         letter-spacing:.8px;color:var(--dim);border-bottom:1px solid var(--border);white-space:nowrap}
.ptbl td{padding:8px 13px;border-bottom:1px solid rgba(48,54,61,.5);vertical-align:top}
.ptbl tr:last-child td{border-bottom:none}
.ptbl tr:hover td{background:rgba(88,166,255,.04)}
.ptbl tr.row-risky td{background:rgba(248,81,73,.04)}
.ptbl tr.row-interesting td{background:rgba(63,185,80,.03)}
.cpe-cell,.mono{font-family:monospace;font-size:11px;color:var(--dim)}
.nodata{text-align:center;color:var(--dim);padding:18px;font-style:italic}
/* Badges */
.badge{display:inline-flex;align-items:center;gap:3px;padding:2px 8px;border-radius:10px;
       font-size:11px;font-weight:600}
.open-badge{background:rgba(63,185,80,.15);color:var(--green)}
.closed-badge{background:rgba(139,148,158,.1);color:var(--dim)}
.filtered-badge{background:rgba(210,153,34,.15);color:var(--orange)}
.unknown-badge{background:var(--bg3);color:var(--dim)}
/* Scripts */
.hsc-section{padding:11px 20px;border-top:1px solid var(--border)}
.hsc-section h4{font-size:11px;color:var(--purple);text-transform:uppercase;
                letter-spacing:.6px;margin-bottom:6px}
.sc-wrap{margin:5px 0}
.sc-id{background:rgba(188,140,255,.15);color:var(--purple);border-radius:4px;
       padding:1px 7px;font-size:11px;font-family:monospace}
.sc-out{background:var(--bg);border:1px solid var(--border);border-radius:6px;
        padding:7px 11px;font-size:11px;color:var(--dim);white-space:pre-wrap;
        word-break:break-all;margin-top:3px;max-height:140px;overflow-y:auto}
/* Unique ports */
.uports-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:16px 22px}
.uport-box{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:13px}
.uport-label{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);margin-bottom:6px}
.uport-val{font-size:12px;line-height:1.8;word-break:break-all}
/* Service matrix */
.svc-ip{display:inline-block;background:rgba(88,166,255,.1);color:var(--accent);
        border:1px solid rgba(88,166,255,.2);border-radius:4px;
        padding:1px 7px;font-size:11px;font-family:monospace;margin:2px}
.svc-hosts{max-width:500px}
/* Footer */
.footer{text-align:center;padding:20px;color:var(--dim);font-size:11px;
        border-top:1px solid var(--border);margin-top:26px}
.dim{color:var(--dim)}
/* Export bar */
.export-bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;
            padding:12px 18px;background:var(--bg3);border-bottom:1px solid var(--border)}
.export-bar span{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.8px;margin-right:4px}
.ebtn{display:inline-flex;align-items:center;gap:6px;background:var(--bg2);
      border:1px solid var(--border);color:var(--text);border-radius:8px;
      padding:7px 14px;font-size:12px;cursor:pointer;transition:.15s;font-weight:500}
.ebtn:hover{border-color:var(--accent);color:var(--accent)}
.ebtn.green-btn:hover{border-color:var(--green);color:var(--green)}
.ebtn.purple-btn:hover{border-color:var(--purple);color:var(--purple)}
/* Toast */
.toast{position:fixed;bottom:28px;right:28px;background:#1f2937;color:#f9fafb;
       border:1px solid var(--border);border-radius:10px;padding:12px 20px;
       font-size:13px;box-shadow:0 8px 32px rgba(0,0,0,.5);
       opacity:0;transform:translateY(10px);transition:.3s;z-index:9999;pointer-events:none}
.toast.show{opacity:1;transform:translateY(0)}
/* Credit */
.credit{font-size:11px;color:var(--dim);margin-top:4px}
.credit strong{color:var(--accent)}
/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg2)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--dim)}
"""

JS = """
// ── Live search ──
function filterHosts(){
  const q = document.getElementById('hostSearch').value.toLowerCase();
  document.querySelectorAll('.host-card').forEach(card => {
    card.style.display = card.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

// ── Status filter ──
function filterByStatus(status, btn){
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.host-card').forEach(card => {
    if(status === 'all'){ card.style.display = ''; return; }
    card.style.display = (card.dataset.status === status) ? '' : 'none';
  });
}

// ── Toast notification ──
function showToast(msg){
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2500);
}

// ── CSV Export ──
function exportCSV(){
  const data = window.__SCAN_DATA__ || [];
  if(!data.length){ showToast('No data to export'); return; }
  const headers = ['IP','Hostname','Port','Protocol','State','Service','Product','Version','Extra Info','CPE','OS','MAC','Vendor'];
  const escape  = v => '"' + String(v).replace(/"/g,'""') + '"';
  const rows    = data.map(r => [
    r.ip, r.hostname, r.port, r.protocol, r.state,
    r.service, r.product, r.version, r.extrainfo,
    r.cpe, r.os, r.mac, r.vendor
  ].map(escape).join(','));
  const csv  = [headers.join(','), ...rows].join('\\n');
  const blob = new Blob([csv], {type:'text/csv'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = 'nmap_report.csv';
  a.click();
  URL.revokeObjectURL(url);
  showToast('✅ CSV exported — ' + rows.length + ' rows');
}

// ── Copy IP:PORT to clipboard ──
function copyIPPort(){
  const data = window.__SCAN_DATA__ || [];
  if(!data.length){ showToast('No data to copy'); return; }
  const lines = data.map(r => r.ip + ':' + r.port);
  // deduplicate, preserve order
  const unique = [...new Set(lines)];
  navigator.clipboard.writeText(unique.join('\\n')).then(() => {
    showToast('📋 Copied ' + unique.length + ' IP:PORT entries');
  }).catch(() => {
    // fallback for non-HTTPS
    const ta = document.createElement('textarea');
    ta.value = unique.join('\\n');
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select(); document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('📋 Copied ' + unique.length + ' IP:PORT entries');
  });
}

// ── Copy unique ports list to clipboard ──
function copyPorts(elemId){
  const el = document.getElementById(elemId);
  if(!el || !el.textContent.trim() || el.textContent.trim() === '—'){
    showToast('No ports to copy'); return;
  }
  navigator.clipboard.writeText(el.textContent.trim()).then(() => {
    showToast('📋 Ports copied to clipboard');
  }).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = el.textContent.trim();
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select(); document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('📋 Ports copied to clipboard');
  });
}

// ── Count-up animation ──
document.querySelectorAll('.scn').forEach(el => {
  const t = parseInt(el.textContent);
  if(isNaN(t) || t < 2) return;
  let v = 0; const step = Math.max(1, Math.ceil(t/30));
  const id = setInterval(() => {
    v += step;
    if(v >= t){ el.textContent = t; clearInterval(id); } else { el.textContent = v; }
  }, 25);
});

// ── Sidebar active link ──
const obs = new IntersectionObserver(entries => {
  entries.forEach(e => {
    const link = document.querySelector('.nav-host[href="#' + e.target.id + '"]');
    if(link) link.style.borderLeftColor = e.isIntersecting ? 'var(--accent)' : 'transparent';
  });
}, {threshold:0.2});
document.querySelectorAll('.host-card').forEach(c => obs.observe(c));
"""


def build_export_json(nmap_out, filters):
    """Build a JS-safe JSON array of all open ports for CSV export."""
    import json
    rows = []
    for host in nmap_out.getHosts(filters):
        for p in host.ports:
            if p.state != "open":
                continue
            rows.append({
                "ip":        host.ip,
                "hostname":  host.getHostname(),
                "port":      p.portId,
                "protocol":  p.protocol,
                "state":     p.state,
                "service":   p.service,
                "product":   p.product,
                "version":   p.version,
                "extrainfo": p.extrainfo,
                "cpe":       "; ".join(p.cpe),
                "os":        host.os_name,
                "mac":       host.mac,
                "vendor":    host.mac_vendor,
            })
    return json.dumps(rows, ensure_ascii=False)


def generate_html(nmap_out, stats, filters, source_label):
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hosts = nmap_out.getHosts(filters)
    m     = nmap_out.ScanMeta[0] if nmap_out.ScanMeta else {}

    # Build export JSON (injected into HTML as a JS variable)
    export_json = build_export_json(nmap_out, filters)

    # Sidebar nav
    nav = ""
    for i, h in enumerate(hosts):
        open_c = sum(1 for p in h.ports if p.state == "open")
        hn     = h.getHostname()
        nav += (f'<a href="#host-{i}" class="nav-host {h.getState()}">'
                f'{esc(h.ip)}'
                f'{"<br><small>" + esc(hn) + "</small>" if hn else ""}'
                f'<span class="nav-open">{open_c}</span></a>\n')

    cards = "\n".join(render_host_card(h, i) for i, h in enumerate(hosts))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Nmap Report — {esc(source_label)}</title>
<!-- Coded by Amit Prajapati & Claude AI -->
<style>{CSS}</style>
</head>
<body>
<div class="wrapper">

<aside class="sidebar">
  <div class="slogo">🔍 Nmap Report<small>Generated {now}</small>
    <div class="credit">by <strong>Amit Prajapati</strong> &amp; Claude AI</div>
  </div>
  <div class="ssec">Hosts ({len(hosts)})</div>
  {nav or '<div style="padding:12px 16px;color:var(--dim);font-size:12px">No hosts</div>'}
</aside>

<main class="main">

<!-- Export Bar -->
<div class="export-bar">
  <span>Export</span>
  <button class="ebtn green-btn" onclick="exportCSV()" title="Download all open ports as CSV">
    ⬇ CSV
  </button>
  <button class="ebtn purple-btn" onclick="copyIPPort()" title="Copy all open ports as IP:PORT to clipboard">
    📋 Copy IP:PORT
  </button>
</div>

<div class="rhead">
  <div class="rtitle">Nmap Security Scan Report</div>
  <div class="rsub">Source: <code>{esc(source_label)}</code></div>
  <div class="mgrid">
    <div class="mc"><div class="mclbl">Scan Start</div><div class="mcval">{esc(m.get("start","N/A"))}</div></div>
    <div class="mc"><div class="mclbl">Scan End</div><div class="mcval">{esc(m.get("end","N/A"))}</div></div>
    <div class="mc"><div class="mclbl">Duration</div><div class="mcval">{esc(m.get("elapsed","0"))}s</div></div>
    <div class="mc"><div class="mclbl">Scan Type</div><div class="mcval">{esc(m.get("type","?"))}/{esc(m.get("protocol","?"))}</div></div>
    <div class="mc"><div class="mclbl">Nmap Version</div><div class="mcval">{esc(m.get("version","?"))}</div></div>
    <div class="mc"><div class="mclbl">Files Loaded</div><div class="mcval">{len(nmap_out.FilesImported)}</div></div>
  </div>
</div>

<div class="srow">
  <div class="sc blue">  <div class="scn">{len(hosts)}</div>              <div class="scl">Total Hosts</div></div>
  <div class="sc green"> <div class="scn">{stats["hosts_up"]}</div>       <div class="scl">Hosts Up</div></div>
  <div class="sc red">   <div class="scn">{stats["hosts_down"]}</div>     <div class="scl">Hosts Down</div></div>
  <div class="sc green"> <div class="scn">{stats["total_open"]}</div>     <div class="scl">Open Ports</div></div>
  <div class="sc orange"><div class="scn">{stats["total_filtered"]}</div> <div class="scl">Filtered</div></div>
  <div class="sc purple"><div class="scn">{len(nmap_out.Services)}</div>  <div class="scl">Services</div></div>
</div>

<div class="cgrid">
  <div class="cc"><div class="ctitle">📊 Top Services</div>{bar_chart(stats["top_services"])}</div>
  <div class="cc"><div class="ctitle">🔌 Top Open Ports</div>{bar_chart(stats["top_ports"],"pf")}</div>
</div>

{render_scan_info(nmap_out)}
{render_unique_ports(stats)}
{render_service_matrix(nmap_out, filters)}

<h2 style="font-size:17px;font-weight:700;margin:22px 0 12px;color:var(--text);
            border-bottom:1px solid var(--border);padding-bottom:8px">🖥️ Host Details</h2>

<div class="fbar">
  <input type="text" id="hostSearch"
         placeholder="🔍  Filter by IP, hostname, service, port, version..."
         oninput="filterHosts()"/>
  <button class="fbtn active" onclick="filterByStatus('all',this)">All</button>
  <button class="fbtn"        onclick="filterByStatus('up',this)">Up</button>
  <button class="fbtn"        onclick="filterByStatus('down',this)">Down</button>
</div>

<div class="legend">
  <span class="li"><span class="ld ld-r"></span>High-risk port</span>
  <span class="li"><span class="ld ld-i"></span>Common port</span>
</div>

<div id="host-container">
  {cards or '<p class="dim" style="padding:20px">No hosts matched current filters.</p>'}
</div>

<div class="footer">
  Generated by <strong>nmap2html.py</strong> &bull;
  Coded by <strong>Amit Prajapati &amp; Claude AI</strong> &bull;
  {now} &bull; Nmap {esc(m.get("version",""))} &bull;
  {esc(m.get("summary",""))}
</div>
</main>
</div>

<!-- Toast -->
<div id="toast" class="toast"></div>

<!-- Scan data for export -->
<script>window.__SCAN_DATA__ = {export_json};</script>
<script>{JS}</script>
</body>
</html>"""


# =====================================================
#  CLI
# =====================================================

def collect_xml_files(inputs, recurse):
    files = []
    for inp in inputs:
        expanded = glob.glob(inp, recursive=recurse)
        targets  = expanded if expanded else [inp]
        for t in targets:
            if os.path.isdir(t):
                files.extend(NmapOutput.find_xml_files(t, recurse))
            elif os.path.isfile(t):
                files.append(t)
            else:
                print(f"[WARN] Not found: {t}", file=sys.stderr)
    seen, result = set(), []
    for f in files:
        af = os.path.abspath(f)
        if af not in seen:
            seen.add(af); result.append(af)
    return result


def main():
    p = argparse.ArgumentParser(
        prog="nmap2html",
        description="Nmap XML to Beautiful HTML Report  (zero pip deps, Python 3.9+)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 nmap2html.py scan.xml
  python3 nmap2html.py scans/ -r -o report.html
  python3 nmap2html.py a.xml b.xml -p 22,80,443
  python3 nmap2html.py -i scan.xml --service ssh,http
        """
    )
    p.add_argument("inputs", nargs="*",
                   help="Nmap XML file(s) or directory")
    p.add_argument("-i","--input", dest="input_flag", metavar="FILE/DIR",
                   help="Input file or dir (alternative to positional)")
    p.add_argument("-o","--output", metavar="FILE",
                   help="Output HTML file (default: <first_input>.html)")
    p.add_argument("-r","--recurse", action="store_true",
                   help="Recurse subdirectories when a dir is given")
    p.add_argument("-p","--port", dest="ports", metavar="PORTS",
                   help="Port filter e.g. 80 or 80,443")
    p.add_argument("--service", dest="services", metavar="SVCS",
                   help="Service filter e.g. http or http,ssh")
    p.add_argument("--host", dest="hosts", metavar="HOSTS",
                   help="Host/CIDR filter e.g. 192.168.1.1 or 10.0.0.0/24")
    p.add_argument("--only-alive", action="store_true",
                   help="Only include alive hosts in report")
    p.add_argument("--must-have-ports", action="store_true",
                   help="Exclude hosts with no port data")
    args = p.parse_args()

    raw_inputs = list(args.inputs)
    if args.input_flag:
        raw_inputs.append(args.input_flag)
    if not raw_inputs:
        p.print_help(); sys.exit(1)

    xml_files = collect_xml_files(raw_inputs, args.recurse)
    if not xml_files:
        print("[ERROR] No Nmap XML files found.", file=sys.stderr); sys.exit(1)

    filters = NmapFilters(default=False)
    if args.ports:
        filters.ports    = [int(x.strip()) for x in args.ports.split(",") if x.strip().isdigit()]
    if args.services:
        filters.services = [s.strip() for s in args.services.split(",")]
    if args.hosts:
        filters.hosts    = [h.strip() for h in args.hosts.split(",")]
    if args.only_alive:
        filters.onlyAlive = True
    if args.must_have_ports:
        filters.mustHavePorts = True

    out_file = args.output or (os.path.splitext(xml_files[0])[0] + ".html")

    print(f"[*] Found {len(xml_files)} XML file(s)")
    nmap_out = NmapOutput(xml_files)
    print(f"[*] Loaded {len(nmap_out.FilesImported)} file(s) | "
          f"{len(nmap_out.Hosts)} host(s) | {len(nmap_out.Services)} service(s)")

    stats = compute_stats(nmap_out, filters)
    print(f"[*] Open: {stats['total_open']} | Filtered: {stats['total_filtered']} | "
          f"Up: {stats['hosts_up']} | Down: {stats['hosts_down']}")

    source_label = (", ".join(os.path.basename(f) for f in xml_files[:3])
                    + ("..." if len(xml_files) > 3 else ""))

    html = generate_html(nmap_out, stats, filters, source_label)
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write(html)

    print(f"[OK] Report saved -> {out_file}")


if __name__ == "__main__":
    main()
