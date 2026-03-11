#!/usr/bin/env python3
"""
nmap2html.py  -  Professional Nmap XML to HTML Report Generator
================================================================
Coded by  : Amit Prajapati
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

import os, sys, re, copy, json, ipaddress, argparse, glob, logging
import xml.etree.ElementTree as ET
from html import escape as esc
from datetime import datetime
from collections import defaultdict

log = logging.getLogger("nmap2html")


# =====================================================
#  CONSTANTS
# =====================================================
PROTOCOLS = ["tcp", "udp"]
SERVICE_MATRIX_LIMIT = 30

# Ports that are flagged and highlighted in the HTML report.
# Single merged set — no separate "interesting" category.
# Logic: if it's worth a reviewer's attention for ANY reason
# (dangerous protocol, database, remote mgmt, or uncommon exposure),
# it belongs here. Ports that are universally expected on every
# network (22 SSH, 80 HTTP, 443 HTTPS, 53 DNS, 161 SNMP) are
# excluded so the highlight stays meaningful.

RISKY_PORTS = {
    # ── Dangerous / legacy plaintext protocols ─────────────────────────
    "13",           # Daytime — info leak, amplification
    "19",           # Chargen — UDP amplification DDoS
    "21",           # FTP — plaintext creds, anon login, bounce attacks
    "23",           # Telnet — fully plaintext, no encryption
    "39",           # Resource Location Protocol — legacy, rarely legit
    "69",           # TFTP — unauthenticated file read/write
    "79",           # Finger — user enumeration
    "80",           # HTTP — plaintext web, included because prod should be HTTPS
    "110",          # POP3 — plaintext email retrieval
    "111",          # RPCbind/portmapper — exposes RPC services
    "119",          # NNTP — legacy news protocol, rarely needed
    "177",          # XDMCP — X Display remote login, plaintext
    "512",          # rexec — plaintext remote execution
    "513",          # rlogin — trust-based auth, trivially bypassed
    "514",          # rsh / syslog — unauth remote shell or log injection
    "515",          # LPD printer — remote print abuse, info leak
    "1701",         # L2TP — VPN without IPsec = plaintext tunnel
    "1723",         # PPTP — broken VPN protocol (MS-CHAPv2 crackable)

    # ── X11 / graphical remote access ──────────────────────────────────
    "6000",         # X11 display :0
    "6001",         # X11 display :1
    "6002",         # X11 display :2
    "6003",         # X11 display :3
    "6004",         # X11 display :4
    "6005",         # X11 display :5
    "6006",         # X11 display :6
    "6007",         # X11 display :7
    "6008",         # X11 display :8
    "6009",         # X11 display :9
    "6010",         # X11 display :10
    "6011",         # X11 display :11
    "6012",         # X11 display :12
    "6013",         # X11 display :13
    "6014",         # X11 display :14
    "6015",         # X11 display :15
    "6016",         # X11 display :16
    "6017",         # X11 display :17
    "6018",         # X11 display :18
    "6019",         # X11 display :19
    "6020",         # X11 display :20
    "6021",         # X11 display :21
    "6022",         # X11 display :22
    "6023",         # X11 display :23
    "6024",         # X11 display :24
    "6025",         # X11 display :25
    "6026",         # X11 display :26
    "6027",         # X11 display :27
    "6028",         # X11 display :28
    "6029",         # X11 display :29
    "6030",         # X11 display :30
    "6031",         # X11 display :31
    "6032",         # X11 display :32
    "6033",         # X11 display :33
    "6034",         # X11 display :34
    "6035",         # X11 display :35
    "6036",         # X11 display :36
    "6037",         # X11 display :37
    "6038",         # X11 display :38
    "6039",         # X11 display :39
    "6040",         # X11 display :40
    "6041",         # X11 display :41
    "6042",         # X11 display :42
    "6043",         # X11 display :43
    "6044",         # X11 display :44
    "6045",         # X11 display :45
    "6046",         # X11 display :46
    "6047",         # X11 display :47
    "6048",         # X11 display :48
    "6049",         # X11 display :49
    "6050",         # X11 display :50
    "6051",         # X11 display :51
    "6052",         # X11 display :52
    "6053",         # X11 display :53
    "6054",         # X11 display :54
    "6055",         # X11 display :55
    "6056",         # X11 display :56
    "6057",         # X11 display :57
    "6058",         # X11 display :58
    "6059",         # X11 display :59
    "6060",         # X11 display :60
    "6061",         # X11 display :61
    "6062",         # X11 display :62
    "6063",         # X11 display :63

    # ── VNC / graphical remote desktop ─────────────────────────────────
    "5900",         # VNC display :0 — often no auth or weak password
    "5901",         # VNC display :1
    "5902",         # VNC display :2
    "5903",         # VNC display :3
    "5904",         # VNC display :4
    "5905",         # VNC display :5
    "5906",         # VNC display :6

    # ── Windows / SMB attack surface ───────────────────────────────────
    "135",          # MSRPC endpoint mapper — DCOM/WMI exploitation
    "137",          # NetBIOS Name Service — enumeration, poisoning
    "138",          # NetBIOS Datagram — enumeration
    "139",          # NetBIOS Session / SMB — EternalBlue, pass-the-hash
    "445",          # SMB direct — ransomware, lateral movement
    "3389",         # RDP — brute force, BlueKeep (CVE-2019-0708)

    # ── Remote management & admin interfaces ───────────────────────────
    "623",          # IPMI/BMC — remote out-of-band management, often default creds
    "664",          # IPMI over SSL
    "1099",         # Java RMI — remote code execution
    "2049",         # NFS — unauthenticated mount if misconfigured
    "4848",         # GlassFish admin console
    "5985",         # WinRM HTTP — remote PowerShell, lateral movement
    "5986",         # WinRM HTTPS
    "8080",         # HTTP alternate — dev servers, admin panels, Jenkins
    "8443",         # HTTPS alternate — admin consoles (Tomcat, etc.)
    "8888",         # Jupyter Notebook — unauthenticated code execution
    "9090",         # Prometheus / Cockpit — metrics or web admin
    "9443",         # VMware / misc admin HTTPS
    "10000",        # Webmin — Linux web admin panel
    "50000",        # SAP / Jenkins slave port

    # ── Databases ──────────────────────────────────────────────────────
    "1433",         # Microsoft SQL Server
    "1434",         # MSSQL browser — UDP instance enumeration
    "1521",         # Oracle Database
    "1522",         # Oracle Database (alt)
    "3306",         # MySQL / MariaDB
    "5432",         # PostgreSQL
    "5433",         # PostgreSQL (alt)
    "6379",         # Redis — unauthenticated by default
    "7474",         # Neo4j browser
    "7687",         # Neo4j Bolt protocol
    "8086",         # InfluxDB
    "9042",         # Cassandra CQL
    "9160",         # Cassandra Thrift
    "11211",        # Memcached — unauthenticated, UDP amplification
    "15672",        # RabbitMQ management UI
    "27017",        # MongoDB — unauthenticated by default (older versions)
    "27018",        # MongoDB shard
    "27019",        # MongoDB config server
    "28015",        # RethinkDB
    "50070",        # Hadoop NameNode web UI
    "50075",        # Hadoop DataNode web UI

    # ── Search & analytics ─────────────────────────────────────────────
    "9200",         # Elasticsearch HTTP — often no auth
    "9300",         # Elasticsearch cluster transport
    "5601",         # Kibana — exposes full ES data if ES is open

    # ── Message queues & streaming ─────────────────────────────────────
    "4369",         # Erlang port mapper (RabbitMQ/CouchDB) — cluster takeover
    "5672",         # AMQP (RabbitMQ)
    "9092",         # Apache Kafka
    "2181",         # ZooKeeper — unauthenticated config/data access

    # ── Containers & virtualisation ────────────────────────────────────
    "2375",         # Docker daemon (unencrypted) — full host takeover
    "2376",         # Docker daemon (TLS) — still worth reviewing
    "2377",         # Docker Swarm
    "4243",         # Docker alt
    "8500",         # Consul HTTP — service mesh config, key/value store
    "8501",         # Consul HTTPS

    # ── C2 / reverse shell / malware indicators ────────────────────────
    "4444",         # Metasploit default listener
    "4445",         # Metasploit alt
    "5554",         # Metasploit / Sasser worm
    "6667",         # IRC — classic C2 channel, botnets
    "6668",         # IRC alt
    "6669",         # IRC alt
    "9001",         # Tor relay / misc backdoors
    "31337",        # Elite/Back Orifice — legacy RAT

    # ── Industrial / SCADA ─────────────────────────────────────────────
    "102",          # Siemens S7 (ISO-TSAP) — ICS/SCADA
    "502",          # Modbus — ICS protocol, no auth
    "503",          # Modbus alt
    "789",          # Moxa NPort — serial device server
    "4840",         # OPC-UA — industrial automation
    "20000",        # DNP3 — SCADA protocol
    "44818",        # EtherNet/IP — Rockwell/Allen-Bradley PLCs

    # ── Miscellaneous high-risk ────────────────────────────────────────
    "7",            # Echo — amplification / reconnaissance
    "17",           # Quote of the Day — amplification
    "25",           # SMTP — open relay check, phishing infrastructure
    "53",           # DNS — open resolver = DDoS amplification (UDP)
    "88",           # Kerberos — ticket attacks if exposed externally
    "389",          # LDAP — directory enumeration, injection
    "636",          # LDAPS — still worth reviewing
    "593",          # HTTP RPC — DCOM over HTTP
    "3128",         # Squid proxy — open proxy abuse
    "3268",         # LDAP Global Catalog
    "3269",         # LDAP Global Catalog SSL
    "8009",         # Apache AJP — Ghostcat (CVE-2020-1938)
}

# Port range helper — used to generate X11 / VNC ranges above dynamically
# (ranges already expanded into the set; this is for documentation only)
_RISKY_PORT_RANGES = {
    "5900-5906": "VNC displays :0–:6",
    "6000-6063": "X11 displays :0–:63",
}

INTERESTING_PORTS = set()   # Merged into RISKY_PORTS — no longer used separately


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
        self.filesWithHost = set()
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
        return any((self.hostFilterSet(), self.portFilterSet(),
                    self.serviceFilterSet(), self.mustHavePorts, self.onlyAlive))

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
        self._services_map       = {}   # name -> NmapService  (O(1) lookup)
        self.ScanMeta            = []
        self._parse_files(xml_files)

    @property
    def Services(self):
        return list(self._services_map.values())

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
            log.info("  [%d/%d] %s", i + 1, len(xml_files), fpath)
            try:
                # Read raw bytes first so we can strip the DOCTYPE declaration
                # that Nmap injects — it references a remote DTD and causes
                # XMLParser to choke on Python 3.8+ builds that removed the
                # internal `.parser` shim used by expat's reset() path.
                with open(fpath, "rb") as raw:
                    data = raw.read()
                # Remove DOCTYPE line(s) which reference nmap.dtd and trigger
                # the 'XMLParser has no attribute parser' error on some builds.
                import re as _re
                data = _re.sub(rb'<!DOCTYPE[^>]*(?:>|\[.*?\]>)', b'', data,
                               flags=_re.DOTALL)
                root_el = ET.fromstring(data)
                tree = ET.ElementTree(root_el)
            except Exception as e:
                log.warning("Failed to parse %s: %s", fpath, e)
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
            host.filesWithHost.add(source_file)

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
        if name not in self._services_map:
            self._services_map[name] = NmapService(name)
        svc = self._services_map[name]
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
        def sort_key(ip):
            try:
                return (0, ipaddress.ip_address(ip))
            except ValueError:
                return (1, ip)
        return sorted(self.Hosts.keys(), key=sort_key)


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
    """html.escape wrapper that accepts any type."""
    from html import escape
    return escape(str(text) if text is not None else "")

def state_badge(state):
    cls_map = {"open":"open-badge","closed":"closed-badge","filtered":"filtered-badge"}
    cls = cls_map.get(state, "unknown-badge")
    return f'<span class="badge {cls}">{esc(state)}</span>'

def host_badge(status):
    cls = "host-up" if status == "up" else "host-down"
    return f'<span class="hbadge {cls}">{status.upper()}</span>'

def row_class(port_id):
    return ""  # Risky port highlighting moved to the Risky Findings summary panel

def bar_chart(items, css_extra=""):
    if not items:
        return '<p class="dim" style="font-size:12px">No data</p>'
    max_val = items[0][1]
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
            raw = sc["output"]
            truncated = len(raw) > 400
            display = raw[:400]
            sc_html += (f'<div class="sc-wrap"><span class="sc-id">{esc(sc["id"])}</span>'
                        f'<pre class="sc-out">{esc(display)}'
                        f'{"<span class=trunc-note>… [truncated — see Raw Scan Data]</span>" if truncated else ""}'
                        f'</pre></div>')
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
        raw = sc["output"]
        truncated = len(raw) > 600
        display = raw[:600]
        hsc_html += (f'<div class="sc-wrap"><span class="sc-id">{esc(sc["id"])}</span>'
                     f'<pre class="sc-out">{esc(display)}'
                     f'{"<span class=trunc-note>… [truncated — see Raw Scan Data]</span>" if truncated else ""}'
                     f'</pre></div>')

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
                      key=lambda s: (-len(s.hosts), s.name))[:SERVICE_MATRIX_LIMIT]
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
            f' <span class="dim">(top {SERVICE_MATRIX_LIMIT})</span></h3>'
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
/* Truncation note */
.trunc-note{display:block;color:var(--orange);font-size:10px;font-style:italic;margin-top:3px}
/* Risky findings panel */
.risky-panel{border-color:rgba(248,81,73,.4)!important}
.risky-panel .sec-title{color:var(--red)}
.risky-counts{display:inline-flex;gap:6px;margin-left:12px;vertical-align:middle}
.risky-clean{display:flex;align-items:center;gap:10px;padding:16px 22px;
             background:rgba(63,185,80,.06);border:1px solid rgba(63,185,80,.3);
             border-radius:var(--radius);margin-bottom:22px;color:var(--green);font-size:13px}
.risky-clean-icon{font-size:20px}
.sev-badge{display:inline-block;padding:2px 8px;border-radius:10px;
           font-size:11px;font-weight:700;letter-spacing:.4px}
.sev-critical{background:rgba(188,0,0,.25);color:#ff6b6b;border:1px solid rgba(255,80,80,.4)}
.sev-high    {background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.sev-medium  {background:rgba(210,153,34,.15);color:var(--orange);border:1px solid rgba(210,153,34,.3)}
.rf-ip{display:inline-block;background:rgba(248,81,73,.08);color:var(--red);
       border:1px solid rgba(248,81,73,.2);border-radius:4px;
       padding:1px 7px;font-size:11px;font-family:monospace;margin:2px;
       text-decoration:none;transition:.15s}
.rf-ip:hover{background:rgba(248,81,73,.2)}
.rf-hn{color:var(--dim);font-family:sans-serif}
.rf-hosts-cell{max-width:420px}
.rf-count{background:var(--bg3);border:1px solid var(--border);border-radius:10px;
          padding:1px 8px;font-size:11px;color:var(--text)}
/* Raw scan data */
.raw-host{border-bottom:1px solid var(--border)}
.raw-host:last-child{border-bottom:none}
.raw-summary{padding:11px 22px;cursor:pointer;display:flex;align-items:center;gap:10px;
             font-size:13px;list-style:none;user-select:none}
.raw-summary::-webkit-details-marker{display:none}
.raw-summary:hover{background:var(--bg3)}
.raw-ip{font-family:monospace;font-weight:700;color:var(--accent)}
.raw-count{margin-left:auto;font-size:11px;color:var(--dim);background:var(--bg3);
           border-radius:10px;padding:1px 8px}
.raw-ctx{color:var(--purple);min-width:110px}
.raw-out{max-height:none;white-space:pre-wrap;word-break:break-all}
.raw-tbl td{vertical-align:top}
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

// ── Raw scan data expand/collapse ──
function expandAllRaw(){
  document.querySelectorAll('.raw-host').forEach(d => d.open = true);
}
function collapseAllRaw(){
  document.querySelectorAll('.raw-host').forEach(d => d.open = false);
}
"""


def build_export_json(nmap_out, filters):
    """Build a JS-safe JSON array of all open ports for CSV export."""
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


def render_raw_scan_data(nmap_out):
    """Render a collapsible section showing the complete raw script output for every host."""
    hosts_html = ""
    for ip, host in nmap_out.Hosts.items():
        # Collect all scripts: host-level + per-port
        entries = []
        for sc in host.host_scripts:
            entries.append(("host-script", sc["id"], sc["output"]))
        for p in host.ports:
            for sc in p.scripts:
                entries.append((f"{p.portId}/{p.protocol}", sc["id"], sc["output"]))
        if not entries:
            continue
        rows = ""
        for context, sc_id, output in entries:
            rows += (f'<tr>'
                     f'<td class="mono raw-ctx">{esc(context)}</td>'
                     f'<td><span class="sc-id">{esc(sc_id)}</span></td>'
                     f'<td><pre class="sc-out raw-out">{esc(output)}</pre></td>'
                     f'</tr>')
        hn = host.getHostname()
        label = f"{ip}" + (f" ({hn})" if hn else "")
        hosts_html += f"""
<details class="raw-host">
  <summary class="raw-summary">
    <span class="raw-ip">{esc(ip)}</span>
    {"<span class='hn'>" + esc(hn) + "</span>" if hn else ""}
    <span class="raw-count">{len(entries)} script result{"s" if len(entries) != 1 else ""}</span>
  </summary>
  <div class="tbl-wrap">
    <table class="ptbl raw-tbl">
      <thead><tr><th>Context</th><th>Script ID</th><th>Output</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</details>"""

    if not hosts_html:
        return ""

    return f"""
<div class="section-card" id="raw-scan-data">
  <h3 class="sec-title" style="display:flex;justify-content:space-between;align-items:center">
    🗂️ Raw Scan Data
    <span class="dim" style="font-size:11px;font-weight:400">Full untruncated script output per host</span>
  </h3>
  <div style="padding:0 22px 14px">
    <button class="ebtn" onclick="expandAllRaw()" style="margin-right:8px">⊞ Expand All</button>
    <button class="ebtn" onclick="collapseAllRaw()">⊟ Collapse All</button>
  </div>
  {hosts_html}
</div>"""


def render_risky_findings(hosts):
    """
    Build a summary table of every open risky port across all hosts,
    grouped by port — shown once before the individual host cards.
    """
    # Collect: port_id -> { service, product, [(ip, hostname)] }
    findings = {}
    for host in hosts:
        for p in host.ports:
            if p.state != "open":
                continue
            if str(p.portId) not in RISKY_PORTS:
                continue
            key = (p.portId, p.protocol)
            if key not in findings:
                findings[key] = {
                    "service": p.service or "unknown",
                    "version": p.version_string,
                    "hosts":   []
                }
            hn = host.getHostname()
            findings[key]["hosts"].append((host.ip, hn))

    if not findings:
        return (
            '<div class="risky-panel risky-clean">'
            '<span class="risky-clean-icon">✅</span>'
            '<span>No risky ports detected across all hosts</span>'
            '</div>'
        )

    # Severity label per port
    C2_PORTS     = {"4444","4445","5554","6667","6668","6669","9001","31337"}
    CRITICAL_SVC = {"3389","5900","5901","5902","5903","5904","5905","5906",
                    "23","21","512","513","514","445","139","2375","8888"}

    def severity(port_id):
        s = str(port_id)
        if s in C2_PORTS:      return ("CRITICAL", "sev-critical")
        if s in CRITICAL_SVC:  return ("HIGH",     "sev-high")
        return                         ("MEDIUM",   "sev-medium")

    rows = ""
    for (port_id, proto), info in sorted(findings.items()):
        sev_label, sev_cls = severity(port_id)
        host_tags = "".join(
            f'<a href="#host-{i}" class="rf-ip" title="{esc(hn)}">'
            f'{esc(ip)}'
            f'{"<span class=rf-hn> ("+esc(hn)+")</span>" if hn else ""}'
            f'</a>'
            for i, (ip, hn) in enumerate(info["hosts"])
        )
        rows += (
            f'<tr>'
            f'<td><strong class="mono">{port_id}</strong></td>'
            f'<td class="mono dim">{esc(proto.upper())}</td>'
            f'<td>{esc(info["service"])}</td>'
            f'<td class="dim" style="font-size:11px">{esc(info["version"])}</td>'
            f'<td><span class="sev-badge {sev_cls}">{sev_label}</span></td>'
            f'<td><span class="rf-count">{len(info["hosts"])}</span></td>'
            f'<td class="rf-hosts-cell">{host_tags}</td>'
            f'</tr>'
        )

    total_findings = sum(len(v["hosts"]) for v in findings.values())

    return f"""
<div class="section-card risky-panel" id="risky-findings">
  <h3 class="sec-title" style="display:flex;justify-content:space-between;align-items:center">
    <span>⚠️ Risky Ports Detected
      <span class="risky-counts">
        <span class="sev-badge sev-critical" style="font-size:10px">
          {sum(1 for (pid,_) in findings if str(pid) in C2_PORTS)} CRITICAL
        </span>
        <span class="sev-badge sev-high" style="font-size:10px">
          {sum(1 for (pid,_) in findings if str(pid) not in C2_PORTS and str(pid) in {"3389","5900","5901","5902","5903","5904","5905","5906","23","21","512","513","514","445","139","2375","8888"})} HIGH
        </span>
        <span class="sev-badge sev-medium" style="font-size:10px">
          {sum(1 for (pid,_) in findings if str(pid) not in C2_PORTS and str(pid) not in {"3389","5900","5901","5902","5903","5904","5905","5906","23","21","512","513","514","445","139","2375","8888"})} MEDIUM
        </span>
      </span>
    </span>
    <span class="dim" style="font-size:11px;font-weight:400">{len(findings)} unique port(s) &bull; {total_findings} total exposure(s)</span>
  </h3>
  <div class="tbl-wrap">
    <table class="ptbl">
      <thead>
        <tr>
          <th>Port</th><th>Proto</th><th>Service</th>
          <th>Version</th><th>Severity</th><th>Hosts</th><th>IPs Affected</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>"""


def generate_html(nmap_out, stats, filters, source_label):
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hosts = nmap_out.getHosts(filters)
    m     = nmap_out.ScanMeta[0] if nmap_out.ScanMeta else {}

    # Build export JSON (injected into HTML as a JS variable)
    export_json = build_export_json(nmap_out, filters)

    # Raw scan data section
    raw_section = render_raw_scan_data(nmap_out)

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

    # Risky findings summary section
    risky_section = render_risky_findings(hosts)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Nmap Report — {esc(source_label)}</title>
<!-- Coded by Amit Prajapati -->
<style>{CSS}</style>
</head>
<body>
<div class="wrapper">

<aside class="sidebar">
  <div class="slogo">🔍 Nmap Report<small>Generated {now}</small>
    <div class="credit">by <strong>Amit Prajapati</strong></div>
  </div>
  <div class="ssec">Hosts ({len(hosts)})</div>
  {nav or '<div style="padding:12px 16px;color:var(--dim);font-size:12px">No hosts</div>'}
  <div class="ssec" style="margin-top:8px">Quick Links</div>
  <a href="#risky-findings" class="nav-host" style="color:var(--red)">⚠️ Risky Findings</a>
  <a href="#raw-scan-data" class="nav-host" style="color:var(--purple)">🗂️ Raw Scan Data</a>
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
{risky_section}
{render_unique_ports(stats)}
{render_service_matrix(nmap_out, filters)}
{raw_section}

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

<div id="host-container">
  {cards or '<p class="dim" style="padding:20px">No hosts matched current filters.</p>'}
</div>

<div class="footer">
  Generated by <strong>nmap2html.py</strong> &bull;
  Coded by <strong>Amit Prajapati</strong> &bull;
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
                log.warning("[WARN] Not found: %s", t)
    seen, result = set(), []
    for f in files:
        af = os.path.abspath(f)
        if af not in seen:
            seen.add(af)
            result.append(af)
    return result


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )
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
    p.add_argument("--version", action="version", version="%(prog)s 2.0  — Coded by Amit Prajapati")
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
        log.error("[ERROR] No Nmap XML files found.")
        sys.exit(1)

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

    log.info("[*] Found %d XML file(s)", len(xml_files))
    nmap_out = NmapOutput(xml_files)
    log.info("[*] Loaded %d file(s) | %d host(s) | %d service(s)",
             len(nmap_out.FilesImported), len(nmap_out.Hosts), len(nmap_out.Services))

    stats = compute_stats(nmap_out, filters)
    log.info("[*] Open: %d | Filtered: %d | Up: %d | Down: %d",
             stats['total_open'], stats['total_filtered'],
             stats['hosts_up'], stats['hosts_down'])

    source_label = (", ".join(os.path.basename(f) for f in xml_files[:3])
                    + ("..." if len(xml_files) > 3 else ""))

    html = generate_html(nmap_out, stats, filters, source_label)
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write(html)

    log.info("[OK] Report saved -> %s", out_file)


if __name__ == "__main__":
    main()
