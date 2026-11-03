#!/usr/bin/env python3
"""Firewall (CEF) tracer checks against the running stack. Reads tracer/.env for the password.

Besides spot checks, it parses samples/03_firewall_cef.log a second time in plain Python (independent
of the Logstash config) and compares every record with the indexed document.
"""
import base64, collections, datetime, json, os, re, sys, urllib.error, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
# The password comes from the ES_PASSWORD environment variable if set (deployed stack), else from tracer/.env.
env = {} if os.environ.get("ES_PASSWORD") else dict(l.strip().split("=", 1) for l in open(os.path.join(HERE, ".env")) if "=" in l)
env["ES_PASSWORD"] = os.environ.get("ES_PASSWORD") or env["ES_PASSWORD"]
AUTH = "Basic " + base64.b64encode(f"elastic:{env['ES_PASSWORD']}".encode()).decode()
BASE = os.environ.get("ES_URL", "http://127.0.0.1:9200")   # for a TLS stack: ES_URL=https://127.0.0.1:9200 SSL_CERT_FILE=~/logbox/certs/ca.crt
SAMPLE = os.path.join(HERE, "..", "samples", "03_firewall_cef.log")
INDEX = "logs-logbox.firewall"


def es(path, body=None):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": AUTH, "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req))


def docs(index):
    try:
        return es(f"/{index}/_search", {"size": 1000, "query": {"match_all": {}}})["hits"]["hits"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        raise


def get(d, path):
    for k in path.split("."):
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def as_list(v):
    return [] if v is None else (v if isinstance(v, list) else [v])


results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


# ---------------------------------------------------------------- independent parse of the sample
ESC = {"n": "\n", "r": "", "=": "=", "|": "|", "\\": "\\"}


def unesc(v):
    return re.sub(r"\\(.)", lambda m: ESC.get(m.group(1), m.group(0)), v, flags=re.S)


HDR = re.compile(r"^(?P<ts>[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d) (?P<host>\S+) CEF:(?P<ver>\d+)\|(?P<vendor>(?:[^|\\]|\\.)*)\|"
                 r"(?P<product>(?:[^|\\]|\\.)*)\|(?P<dver>(?:[^|\\]|\\.)*)\|(?P<sig>(?:[^|\\]|\\.)*)\|"
                 r"(?P<name>(?:[^|\\]|\\.)*)\|(?P<sev>[^|]*)\|(?P<ext>.*)$")
expected = []
for line in open(SAMPLE, encoding="utf-8").read().split("\n"):
    if not line.strip():
        continue
    m = HDR.match(line)
    ext = {}
    for part in re.split(r"\s+(?=[A-Za-z0-9_.]+=)", m["ext"]):
        k, v = part.split("=", 1)
        ext[k] = unesc(v.rstrip())
    expected.append({"line": line, "m": m, "ext": ext})

data = docs(INDEX)
rej = docs("logs-rejects")
fw_rej = [r for r in rej if get(r["_source"], "event.dataset") == "logbox.firewall"]
src = sorted((d["_source"] for d in data), key=lambda s: get(s, "org.metadata.pipeline.record_seq"))

check("240 lines in, 240 documents out, 0 firewall rejects", len(src) == 240 and not fw_rej, f"data={len(src)} rejects={len(fw_rej)}")
check("record_seq contiguous 1..240", [get(s, "org.metadata.pipeline.record_seq") for s in src] == list(range(1, 241)))
check("ids unique, 64 hex", len({d["_id"] for d in data}) == 240 and all(len(d["_id"]) == 64 for d in data))
allowed = {"@timestamp", "message", "tags", "agent", "event", "observer", "source", "destination", "network", "url", "user",
           "user_agent", "file", "rule", "log", "related", "org", "ecs"}
tops = {k for s in src for k in s}
check("no non-ECS top-level field, no host.* at all (decision 2)", tops <= allowed and "host" not in tops, f"{sorted(tops)}")

# ---------------------------------------------------------------- time
epoch = [s for s, e in zip(src, expected) if e["ext"]["rt"].isdigit()]
text = [s for s, e in zip(src, expected) if not e["ext"]["rt"].isdigit()]
check("212 epoch rt -> source-zone, 28 text rt -> assumed-zone", len(epoch) == 212 and len(text) == 28
      and all(get(s, "org.metadata.pipeline.timestamp_basis") == "source-zone" for s in epoch)
      and all(get(s, "org.metadata.pipeline.timestamp_basis") == "assumed-zone" for s in text))
check("event.timezone only on the 28 text-rt records", all(get(s, "event.timezone") for s in text) and not any(get(s, "event.timezone") for s in epoch))
check("@timestamp ends with Z", all(s["@timestamp"].endswith("Z") for s in src))
ok_ts = True
tz_note = env.get("FW_SOURCE_TIMEZONE", "UTC")
for s, e in zip(src, expected):
    rt = e["ext"]["rt"]
    if rt.isdigit():
        want = datetime.datetime.fromtimestamp(int(rt) / 1000, datetime.timezone.utc)
    else:
        want = datetime.datetime.strptime(rt, "%b %d %Y %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    got = datetime.datetime.fromisoformat(s["@timestamp"].replace("Z", "+00:00"))
    if got != want:
        ok_ts = False
check("every @timestamp equals rt converted to UTC (millis kept for epoch)", ok_ts)
check("syslog prefix time kept as written", all(get(s, "org.metadata.firewall.syslog_timestamp") == e["m"]["ts"] for s, e in zip(src, expected)))
check("rt text kept as written", all(get(s, "org.metadata.firewall.rt") == e["ext"]["rt"] for s, e in zip(src, expected)))

# ---------------------------------------------------------------- header
check("event.code counts", dict(collections.Counter(get(s, "event.code") for s in src)) ==
      {"TRAFFIC-ALLOW": 77, "TRAFFIC-DENY": 37, "VPN-LOGIN": 37, "URL-BLOCK": 34, "AV-7781": 28, "IPS-30211": 13, "IPS-50017": 7, "IPS-41923": 7})
check("observer.* from header and dvchost", all(get(s, "observer.vendor") == "ExampleSec" and get(s, "observer.product") == "EdgeGuard NGFW"
      and get(s, "observer.hostname") == "fw-edge01.example.edu" and get(s, "observer.type") == "firewall" for s in src))
check("observer.version 4.2.1 x160 / 4.2.2 x80", collections.Counter(get(s, "observer.version") for s in src) == {"4.2.1": 160, "4.2.2": 80})
check("syslog host and cef_version kept as non-ECS fields", all(get(s, "org.metadata.firewall.syslog_host") == "fw-edge01" and get(s, "org.metadata.firewall.cef_version") == "0" for s in src))
check("message is the header name, unescaped (decision 5)", all(get(s, "message") == unesc(e["m"]["name"]).replace("\\", "\\") for s, e in zip(src, expected)))
names = {get(s, "message") for s in src}
check("escaped pipe and backslashes in header names undone", "SQL Injection Attempt | UNION SELECT" in names and "Directory Traversal ..\\..\\" in names
      and "Malware detected \\ quarantined" in names, str(sorted(n for n in names if "\\" in n or "|" in n)))

# ---------------------------------------------------------------- severity (simplification plan: kept as written)
check("severity kept exactly as written under org.metadata.firewall.severity on all 240 (229 numbers, 11 words); no event.severity",
      all(get(s, "org.metadata.firewall.severity") == e["m"]["sev"] and get(s, "event.severity") is None for s, e in zip(src, expected))
      and sum(1 for e in expected if e["m"]["sev"].isdigit()) == 229)

# ---------------------------------------------------------------- field-by-field against the independent parse
bad = collections.Counter()
for s, e in zip(src, expected):
    x = e["ext"]
    pairs = [("source.ip", x.get("src")), ("destination.ip", x.get("dst")), ("event.action", x.get("act")), ("event.outcome", x.get("outcome")),
             ("user.name", x.get("suser")), ("source.user.name", x.get("suser")), ("event.reason", x.get("msg")), ("url.original", x.get("request")),
             ("user_agent.original", x.get("requestClientApplication")), ("file.name", x.get("fname")), ("file.path", x.get("filePath")),
             ("network.transport", x["proto"].lower() if "proto" in x else None),
             ("source.port", int(x["spt"]) if "spt" in x else None), ("destination.port", int(x["dpt"]) if "dpt" in x else None),
             ("source.bytes", int(x["in"]) if "in" in x else None), ("destination.bytes", int(x["out"]) if "out" in x else None),
             # not mapped to ECS in the demo build: kept as written under org.metadata.firewall
             ("org.metadata.firewall.cs1", x.get("cs1")), ("org.metadata.firewall.cs2", x.get("cs2")), ("org.metadata.firewall.cs3", x.get("cs3")),
             ("org.metadata.firewall.cs1Label", x.get("cs1Label")), ("org.metadata.firewall.cs2Label", x.get("cs2Label")),
             ("org.metadata.firewall.cs3Label", x.get("cs3Label")),
             ("org.metadata.firewall.cat", x.get("cat")), ("org.metadata.firewall.fileHash", x.get("fileHash"))]
    for field, want in pairs:
        if get(s, field) != want:
            bad[field] += 1
            if bad[field] == 1:
                print("   first mismatch", field, "got", repr(get(s, field)), "want", repr(want), "seq", get(s, "org.metadata.pipeline.record_seq"))
check("all mapped fields equal the independent parse, all 240 records", not bad, str(dict(bad)))

# ---------------------------------------------------------------- escape traps
nguyen = [s for s in src if "nguyễn.an" in (get(s, "file.path") or "")]
check("trap 1: backslash-backslash-n is a backslash and the letter n, never a line break",
      len(nguyen) == 3 and all("\\nguyễn.an\\Downloads" in get(s, "file.path") and "\n" not in get(s, "file.path") for s in nguyen),
      repr(get(nguyen[0], "file.path")) if nguyen else "")
reasons_nl = [s for s in src if "\n" in (get(s, "event.reason") or "")]
check("10 real escaped newlines became line breaks in event.reason", len(reasons_nl) == 10 and all("\\n" not in get(s, "event.reason") for s in reasons_nl))
check("escaped equals undone in reason and url", not any("\\=" in (get(s, "event.reason") or "") + (get(s, "url.original") or "") for s in src)
      and any("servicedesk=ext 4357" in (get(s, "event.reason") or "") for s in src) and any("?id=1 UNION SELECT" in (get(s, "url.original") or "") for s in src))
check("path traversal request has single backslashes", any(get(s, "url.original") == "https://www.example.edu/files?path=..\\..\\..\\boot.ini" for s in src))
check("values with spaces, pipe and quotes intact", any(get(s, "file.name") == "payroll | Q3.xlsm" for s in src)
      and any(get(s, "user_agent.original") == 'Custom-Agent "Scanner" v2.1' for s in src)
      and any(get(s, "org.metadata.firewall.cat") == "Newly Registered Domain" for s in src))
check("non-ASCII names intact", {"nguyễn.an", "ólafur.j", "kowalski.ł", "josé.garcía", "müller.k"} <= {get(s, "user.name") for s in src})

# ---------------------------------------------------------------- not mapped in the demo build (simplification-plan-2026-11-01.md)
check("no event.category / event.type on any document (classification by signature id is not built)",
      not any(get(s, "event.category") or get(s, "event.type") for s in src))
check("cs3 geo kept whole under org.metadata (37), no source.geo", sum(1 for s in src if get(s, "org.metadata.firewall.geo") is None and get(s, "org.metadata.firewall.cs3Label") == "Geo") == 37
      and not any(get(s, "source.geo") for s in src))
check("user.name copied to source.user.name on 99 records only", sum(1 for s in src if get(s, "user.name")) == 99 and all(get(s, "user.name") == get(s, "source.user.name") for s in src))
check("file hash kept as written under org.metadata.firewall.fileHash (28); no file.hash, no related.hash, no rule.name",
      sum(1 for s in src if get(s, "org.metadata.firewall.fileHash")) == 28
      and not any(get(s, "file.hash") or get(s, "related.hash") or get(s, "rule.name") for s in src))
leftover_keys = {k for s in src for k in (get(s, "org.metadata.firewall") or {})}
check("only the expected keys under org.metadata.firewall (csN, labels and fileHash stay as written)", leftover_keys == {"rt", "syslog_timestamp", "syslog_host", "cef_version", "severity", "cat", "cs1", "cs1Label", "cs2", "cs2Label", "cs3", "cs3Label", "fileHash"}, str(sorted(leftover_keys)))
check("event.reason only where the line had msg (64)", sum(1 for s in src if get(s, "event.reason")) == 64)
check("related.ip is source then destination, once each", all(as_list(get(s, "related.ip")) == [v for v in (get(s, "source.ip"), get(s, "destination.ip")) if v] for s in src))
check("related.hosts holds the observer name; related.user the user", all(as_list(get(s, "related.hosts")) == ["fw-edge01.example.edu"] for s in src)
      and all(as_list(get(s, "related.user")) == as_list(get(s, "user.name")) for s in src))
check("agent.name and pipeline.host set", all(get(s, "agent.name") == "logstash-firewall" and get(s, "org.metadata.pipeline.host") for s in src))

m = es(f"/{INDEX}/_mapping")[INDEX]["mappings"]["properties"]
check("mapping types: ip, long, keyword, wildcard (no event.severity: severity stays under org.metadata)", m["source"]["properties"]["ip"]["type"] == "ip" and m["source"]["properties"]["bytes"]["type"] == "long"
      and m["event"]["properties"]["code"]["type"] == "keyword"
      and m["event"]["properties"]["reason"]["type"] == "wildcard" and m["related"]["properties"]["hash"]["type"] == "keyword")

print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
