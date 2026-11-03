#!/usr/bin/env python3
"""Syslog tracer checks against the running stack (reads tracer/.env for the password)."""
import base64, json, os, sys, urllib.request, collections

# The password comes from the ES_PASSWORD environment variable if set (deployed stack), else from tracer/.env.
env = {} if os.environ.get("ES_PASSWORD") else dict(l.strip().split("=", 1) for l in open(os.path.join(os.path.dirname(__file__), ".env")) if "=" in l)
env["ES_PASSWORD"] = os.environ.get("ES_PASSWORD") or env["ES_PASSWORD"]
AUTH = "Basic " + base64.b64encode(f"elastic:{env['ES_PASSWORD']}".encode()).decode()
BASE = os.environ.get("ES_URL", "http://127.0.0.1:9200")   # for a TLS stack: ES_URL=https://127.0.0.1:9200 SSL_CERT_FILE=~/logbox/certs/ca.crt

def es(path, body=None, method=None):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode() if body else None,
                                 method=method or ("POST" if body else "GET"),
                                 headers={"Authorization": AUTH, "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req))

def docs(index):
    try:
        return [h for h in es(f"/{index}/_search", {"size": 1000, "query": {"match_all": {}}})["hits"]["hits"]]
    except urllib.error.HTTPError as e:
        if e.code == 404:       # the index does not exist yet: nothing was written to it
            return []
        raise

def get(d, path):
    for k in path.split("."):
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d

results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))

data = docs("logs-logbox.syslog")
rej = docs("logs-rejects")
src = [d["_source"] for d in data]
check("records indexed + rejected = 230", len(data) + len(rej) == 230, f"data={len(data)} rejects={len(rej)}")
check("no rejects for the real sample", len(rej) == 0, "; ".join(f"{get(r['_source'],'org.metadata.reject.stage')}" for r in rej))
seqs = sorted(get(s, "org.metadata.pipeline.record_seq") for s in src)
check("record_seq contiguous 1..230", seqs == list(range(1, 231)), f"min={seqs[0]} max={seqs[-1]}")
check("document ids unique and deterministic length (64 hex)", len({d['_id'] for d in data}) == len(data) and all(len(d['_id']) == 64 for d in data))

# timestamps
ts = [s["@timestamp"] for s in src]
check("@timestamp ends with Z on every document", all(t.endswith("Z") for t in ts))
check("all timestamps on 2026-10-14", all(t.startswith("2026-10-14") for t in ts), f"{min(ts)} .. {max(ts)}")
first = next(s for s in src if get(s, "event.original").startswith("Oct 14 00:02:17"))
check("RFC3164 time converted: Oct 14 00:02:17 -> 2026-10-14T00:02:17.000Z", first["@timestamp"] == "2026-10-14T00:02:17.000Z", first["@timestamp"])
check("event.timezone UTC + basis on RFC3164", get(first, "event.timezone") == "UTC" and get(first, "org.metadata.pipeline.timestamp_basis") == "assumed-zone-and-year")
r5 = [s for s in src if get(s, "event.original").startswith("<")]
check("19 RFC5424 records, basis source-zone, no event.timezone",
      len(r5) == 19 and all(get(s, "org.metadata.pipeline.timestamp_basis") == "source-zone" and get(s, "event.timezone") is None for s in r5))
check("RFC5424 millisecond time kept", any(s["@timestamp"] == "2026-10-14T00:11:53.303Z" for s in r5))
check("event.created present and is a date string", all(isinstance(get(s, "event.created"), str) for s in src), str(get(first, "event.created")))

# header
check("host.name is the origin host, never the collector",
      all(get(s, "host.name") and get(s, "host.name") != (os.environ.get("PIPELINE_HOST") or env["PIPELINE_HOST"]) and "tracer" not in get(s, "host.name") for s in src),
      f"hosts={sorted({get(s,'host.name') for s in src})}")
check("host.name kept exactly as logged (short and FQDN both present)",
      any(get(s, "host.name") == "mail01" for s in src) and any(get(s, "host.name") == "mail01.example.edu" for s in src))
check("process.pid is a number", all(isinstance(get(s, "process.pid"), int) for s in src if get(s, "process.pid") is not None))
check("agent.name and pipeline.host set", all(get(s, "agent.name") == "logstash-syslog" and get(s, "org.metadata.pipeline.host") for s in src))
check("log.file.path set (ECS-mode file input)", all(get(s, "log.file.path") for s in src), str(get(first, "log.file.path")))

# R4: top-level fields
allowed = {"@timestamp", "message", "tags", "agent", "host", "event", "process", "user", "source", "destination", "client",
           "server", "network", "observer", "url", "http", "email", "error", "file", "log", "related", "org", "ecs"}
tops = {k for s in src for k in s}
check("no non-ECS top-level field (R4)", tops <= allowed, f"unexpected={sorted(tops - allowed)} all={sorted(tops)}")

# message bodies are NOT parsed in the demo build (simplification-plan-2026-11-01.md)
import re
HDR3164 = re.compile(r"^[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d \S+ (?:[^\s:\[]+(?:\[\d+\])?: ?)?")
r3 = [s for s in src if not get(s, "event.original").startswith("<")]
check("RFC3164: message is exactly the text after the header, on all 211 records",
      len(r3) == 211 and all(get(s, "message") == get(s, "event.original")[HDR3164.match(get(s, "event.original")).end():] for s in r3
                              if "\n" not in get(s, "event.original")))
check("process.name is set on every RFC3164 record that has a program",
      all(get(s, "process.name") for s in r3), f"{sum(1 for s in r3 if not get(s, 'process.name'))} without")
BODY_FIELDS = ("event.action", "event.outcome", "event.category", "event.type", "source.ip", "source.port", "destination.ip", "client.ip",
               "log.level", "error.stack_trace", "error.type", "process.command_line", "process.working_directory", "user.effective", "file.path", "url")
check("no body-derived field on any document (action, outcome, category, type, addresses, log.level, stack trace, command, url)",
      not [(f, sum(1 for s in src if get(s, f) is not None)) for f in BODY_FIELDS if any(get(s, f) is not None for s in src)],
      str([(f, sum(1 for s in src if get(s, f) is not None)) for f in BODY_FIELDS if any(get(s, f) is not None for s in src)]))
sy_keys = {k for s in src for k in (get(s, "org.metadata.syslog") or {})}
check("only header leftovers under org.metadata.syslog (timestamp, sd_id)", sy_keys <= {"timestamp", "sd_id"}, str(sorted(sy_keys)))

# stack traces: three Java exceptions arrive as ONE document each (joined by the input), kept in message
tc = [s for s in src if get(s, "process.name") == "tomcat9" and "multiline" in (get(s, "tags") or [])]
check("3 tomcat9 records, each ONE document tagged multiline with the whole trace in message and event.original",
      len(tc) == 3 and all(get(s, "message").count("\n") == 5 and get(s, "event.original").count("\n") == 5 for s in tc))
check("records not tagged multiline have no line break in message", all("\n" not in get(s, "message") for s in src if "multiline" not in (get(s, "tags") or [])))
check("'invalid token' / 'Failed password' text untouched in message",
      any("invalid token" in get(s, "message") for s in src) and any("Failed password" in get(s, "message") for s in src))

# RFC5424 structured data
sdrec = [s for s in r5 if get(s, "log.syslog.structured_data.user")]
check("RFC5424: 11 records with structured data, user copied to user.name",
      len(sdrec) == 11 and all(get(s, "user.name") == get(s, "log.syslog.structured_data.user") for s in sdrec))
notes = {get(s, "log.syslog.structured_data.note") for s in sdrec}
print("     note values:", sorted(notes))
check("RFC5424: escapes undone", 'said "hello" ] then left' in notes and "path C:\\Temp\\x" in notes)
check("RFC5424: facility/severity from PRI", all(get(s, "log.syslog.severity.name") and get(s, "log.syslog.facility.name") is not None for s in r5),
      f"{ {get(s,'log.syslog.priority'): (get(s,'log.syslog.facility.name'), get(s,'log.syslog.severity.name')) for s in r5} }")
check("RFC5424: msgid / version", all(get(s, "log.syslog.msgid") and get(s, "log.syslog.version") == "1" for s in r5))

# related
check("related.hosts present on every record", all(get(s, "related.hosts") for s in src))

# mapping types
m = es("/logs-logbox.syslog/_mapping")["logs-logbox.syslog"]["mappings"]["properties"]
check("mapping: source.ip is ip, process.pid long, log.syslog.structured_data flattened",
      m["source"]["properties"]["ip"]["type"] == "ip" and m["process"]["properties"]["pid"]["type"] == "long"
      and m["log"]["properties"]["syslog"]["properties"]["structured_data"]["type"] == "flattened")
check("mapping: org.metadata strings are keyword", m["org"]["properties"]["metadata"]["properties"]["syslog"]["properties"]["timestamp"]["type"] == "keyword")

print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
