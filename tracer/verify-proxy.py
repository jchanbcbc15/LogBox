#!/usr/bin/env python3
"""Proxy (CSV) tracer checks against the running stack. Reads tracer/.env for the password.

  verify-proxy.py          checks the real sample (samples/04_proxy_export.csv), which was ingested
  verify-proxy.py --edge   checks tests/fixtures/proxy_edge.csv (ingested via PX_INPUT_PATH=/data/test_proxy_edge.csv)

The real-sample mode parses the CSV a second time with Python's csv module (independent of the Logstash
config) and compares every record with the indexed document.
"""
import base64, collections, csv, datetime, io, json, os, sys, urllib.error, urllib.request

EDGE = "--edge" in sys.argv
HERE = os.path.dirname(os.path.abspath(__file__))
# The password comes from the ES_PASSWORD environment variable if set (deployed stack), else from tracer/.env.
env = {} if os.environ.get("ES_PASSWORD") else dict(l.strip().split("=", 1) for l in open(os.path.join(HERE, ".env")) if "=" in l)
env["ES_PASSWORD"] = os.environ.get("ES_PASSWORD") or env["ES_PASSWORD"]
AUTH = "Basic " + base64.b64encode(f"elastic:{env['ES_PASSWORD']}".encode()).decode()
BASE = os.environ.get("ES_URL", "http://127.0.0.1:9200")   # for a TLS stack: ES_URL=https://127.0.0.1:9200 SSL_CERT_FILE=~/logbox/certs/ca.crt
SAMPLE = os.path.join(HERE, "..", "tests", "fixtures", "proxy_edge.csv") if EDGE else os.path.join(HERE, "..", "samples", "04_proxy_export.csv")
INDEX = "logs-logbox.proxy"


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


data = docs(INDEX)
rej = [r for r in docs("logs-rejects") if get(r["_source"], "event.dataset") == "logbox.proxy"]
src = sorted((d["_source"] for d in data), key=lambda s: get(s, "org.metadata.pipeline.record_seq"))
by_id = {get(s, "event.id"): s for s in src if get(s, "event.id")}

# =========================================================================================== edge fixture
if EDGE:
    rseq = {get(r["_source"], "org.metadata.pipeline.record_seq"): r["_source"] for r in rej}
    check("11 documents and 3 rejects (15 records: 3 rejected, 1 overwritten by a duplicate event_id)", len(src) == 11 and len(rej) == 3, f"data={len(src)} rejects={len(rej)}")
    stages = sorted((get(r["_source"], "org.metadata.reject.stage"), get(r["_source"], "error.type")) for r in rej)
    check("rejects: impossible date, unclosed quote, glued row", stages == [("proxy.csv.record", "malformed_record"), ("proxy.csv.record", "malformed_record"), ("proxy.date.timestamp", "invalid_time")], str(stages))
    check("no reject has stage unknown", all(get(r["_source"], "org.metadata.reject.stage") != "unknown" for r in rej))
    g = [r["_source"] for r in rej if "Line break outside quotes" in get(r["_source"], "error.message")]
    check("glued row: ONE reject holds both rows in event.original (nothing lost, but the good row is rejected with it)",
          len(g) == 1 and "0000909" in get(g[0], "event.original") and "not-a-time,0000910" in get(g[0], "event.original"))
    check("reject @timestamp is the ingest time (event.created), not an event time", all(get(r["_source"], "@timestamp") == get(r["_source"], "event.created") for r in rej))

    a = by_id["0000901"]
    check("url with port and fragment: kept whole in url.original; no url parts (not built in the demo build)",
          get(a, "url.original") == "https://host.example.com:8443/files/archive.tar.gz?x=1#frag"
          and all(get(a, "url." + k) is None for k in ("scheme", "domain", "port", "path", "query", "extension")))
    e = by_id["0000902"] if "0000902" in by_id else None
    check("empty cells create no field: a row with only time and id has no client, user, url, http.request, user_agent", e is not None and all(
        get(e, k) is None for k in ("client", "user", "url", "http", "user_agent", "related", "org.metadata.proxy.notes", "org.metadata.proxy.category", "org.metadata.proxy.bytes_sent")), "" if e is None else str(sorted(e)))
    u = by_id["0000903"]
    check("user-info in the url: url.original kept, no parts; '-' referrer not set", get(u, "url.original") == "http://user:pw@host.example.com/x"
          and all(get(u, "url." + k) is None for k in ("scheme", "domain", "path", "query")) and get(u, "http.request.referrer") is None)
    n = by_id["0000904"]
    check("url without a path: url.original kept, no parts", get(n, "url.original") is not None and all(get(n, "url." + k) is None for k in ("domain", "path", "extension")))
    b = by_id["0000906"]
    check("non-numeric status and bytes are kept as written, the document is not lost", get(b, "http.response.status_code") == "abc" and get(b, "org.metadata.proxy.bytes_sent") == "n/a")
    x = by_id["0000911"]
    check("a 14th cell is kept under its position name, not dropped", get(x, "org.metadata.proxy.column14") == "extra cell" and get(x, "org.metadata.proxy.notes") == "notes")
    d = by_id["0000915"]
    check("duplicate event_id: one document, the later row wins (known consequence of R20)", get(d, "org.metadata.proxy.notes") == "SECOND row with this event_id (this one wins)"
          and sum(1 for s in src if get(s, "event.id") == "0000915") == 1)
    ni = [s for s in src if not get(s, "event.id")]
    check("a row without event_id still gets a document (hash of the raw record)", len(ni) == 1 and get(ni[0], "url.original") == "https://example.com/noid")
    m = by_id["0000912"]
    check("notes keep backslashes, doubled quotes become one quote, line break and trailing spaces",
          get(m, "org.metadata.proxy.notes") == 'C:\\Users\\x\\n \\t "quoted" line one  \nline two  ' and "multiline" in as_list(get(m, "tags")))
    check("the last row (no line ending at end of file) was ingested", "0000913" in by_id)
    check("header row is not a document and record_seq of the first record is 2", min(get(s, "org.metadata.pipeline.record_seq") for s in src + [r["_source"] for r in rej]) == 2)
    print()
    print(f"{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)

# =========================================================================================== real sample
rows = list(csv.DictReader(io.StringIO(open(SAMPLE, encoding="utf-8", newline="").read())))
N = len(rows)
check(f"{N} records in, {N} documents out, 0 proxy rejects", len(src) == N == 225 and not rej, f"data={len(src)} rejects={len(rej)}")
check("record_seq 2..226 contiguous (the header row is number 1)", [get(s, "org.metadata.pipeline.record_seq") for s in src] == list(range(2, N + 2)))
check("ids unique, 64 hex", len({d["_id"] for d in data}) == N and all(len(d["_id"]) == 64 for d in data))
allowed = {"@timestamp", "tags", "agent", "event", "observer", "client", "user", "http", "url", "user_agent", "log", "related", "org", "ecs"}
tops = {k for s in src for k in s}
check("no non-ECS top-level field; no message, no host", tops <= allowed and "message" not in tops and "host" not in tops, str(sorted(tops)))

# ---- id: the same record always gets the same _id (dataset + event_id), checked against an independent hash
import hashlib
# The fingerprint filter hashes "|field name|value|" for each source field, so the field names are part of the text.
check("_id = SHA-256(dataset + event_id), recomputed independently", all(
    d["_id"] == hashlib.sha256(("|[event][dataset]|logbox.proxy|[event][id]|" + get(d["_source"], "event.id") + "|").encode()).hexdigest() for d in data))

# ---- time
check("@timestamp ends with Z, basis source-zone, no event.timezone", all(s["@timestamp"].endswith("Z") and get(s, "org.metadata.pipeline.timestamp_basis") == "source-zone"
      and get(s, "event.timezone") is None for s in src))
ok_ts = True
for s, r in zip(src, rows):
    want = datetime.datetime.fromisoformat(r["event_time"].replace("Z", "+00:00"))
    if datetime.datetime.fromisoformat(s["@timestamp"].replace("Z", "+00:00")) != want:
        ok_ts = False
check("every @timestamp equals event_time (milliseconds kept)", ok_ts)
check("event_time text kept as written", all(get(s, "org.metadata.proxy.event_time") == r["event_time"] for s, r in zip(src, rows)))

# ---- common fields
check("dataset, kind, observer.type, agent.name", all(get(s, "event.dataset") == "logbox.proxy" and get(s, "event.kind") == "event" and get(s, "observer.type") == "proxy"
      and get(s, "agent.name") == "logstash-proxy" and get(s, "org.metadata.pipeline.host") for s in src))
check("no event.category / event.type (the constant pair is not set in the demo build)", all(get(s, "event.category") is None and get(s, "event.type") is None for s in src))
check("no event.outcome (decision 4); no http.response.bytes (decision 1); no event.action", all(get(s, "event.outcome") is None and get(s, "http.response.bytes") is None and get(s, "event.action") is None for s in src))
check("no host.* and no observer.hostname (the file has no device name)", all(get(s, "host") is None and get(s, "observer.hostname") is None for s in src))

# ---- field-by-field against the independent parse
import re
def parts(url):
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#@:]+)(?::([0-9]+))?(/[^?#]*)?(?:\?([^#]*))?(?:#.*)?$", url)
    if not m:
        return {}
    ext = re.search(r"\.([A-Za-z0-9]{1,10})$", m[4] or "")
    return {"scheme": m[1], "domain": m[2], "path": m[4], "query": m[5], "extension": ext[1] if ext and "/" not in ext[0] else None}

bad = collections.Counter()
for s, r in zip(src, rows):
    p = parts(r["url"]) if r["url"] else {}
    pairs = [("event.id", r["event_id"] or None), ("client.ip", r["client_ip"] or None), ("user.name", r["username"] or None),
             ("user.full_name", r["display_name"] or None), ("http.request.method", r["http_method"] or None), ("url.original", r["url"] or None),
             ("http.response.status_code", int(r["status_code"])), ("org.metadata.proxy.bytes_sent", int(r["bytes_sent"])),
             ("user_agent.original", r["user_agent"] or None),
             ("http.request.referrer", None if r["referrer"] in ("", "-") else r["referrer"]),
             ("org.metadata.proxy.category", r["category"] or None), ("org.metadata.proxy.notes", r["notes"] or None),
             ]
    for field, want in pairs:
        if get(s, field) != want:
            bad[field] += 1
            if bad[field] == 1:
                print("   first mismatch", field, "got", repr(get(s, field)), "want", repr(want), "seq", get(s, "org.metadata.pipeline.record_seq"))
check("all mapped fields equal the independent parse, all 225 records (notes byte for byte)", not bad, str(dict(bad)))
check("event.original equals the raw record text (CRLF removed)", all(
    get(s, "event.original").startswith(r["event_time"] + "," + r["event_id"] + ",") for s, r in zip(src, rows)))

# ---- decisions 1 to 3 in numbers
check("decision 2: referrer absent on the 48 '-' and the 51 empty records", sum(1 for s in src if get(s, "http.request.referrer") is None) == 99
      and not any(get(s, "http.request.referrer") == "-" for s in src))
check("url parts are not built: no url.scheme/domain/port/path/query/extension on any document; url.original is the URL as logged",
      not any(get(s, "url." + k) is not None for s in src for k in ("scheme", "domain", "port", "path", "query", "extension"))
      and all(get(s, "url.original") == (r["url"] or None) for s, r in zip(src, rows)))
check("percent-encoding is untouched in url.original", any(get(s, "url.original", ).endswith("id=987&title=%22breaking%22") for s in src))

# ---- notes: the sample's test cases
notes = [get(s, "org.metadata.proxy.notes") for s in src]
check("168 non-empty notes, 57 records without the field", sum(1 for n in notes if n) == 168 and sum(1 for n in notes if n is None) == 57)
ml = [s for s in src if "\n" in (get(s, "org.metadata.proxy.notes") or "")]
check("21 multi-line notes, each ONE document with line breaks intact, tagged multiline", len(ml) == 21 and all(get(s, "org.metadata.proxy.notes") == "Multi-line note:\nline two\nline three" for s in ml)
      and all("multiline" in as_list(get(s, "tags")) for s in ml) and sum(1 for s in src if "multiline" in as_list(get(s, "tags"))) == 21)
check("15 notes with trailing spaces kept", sum(1 for n in notes if n and n != n.rstrip()) == 15 and "Trailing spaces   " in notes)
check("literal backslashes untouched (no unescape): \\t \\n \\\" and C:\\Users", any(n and n.startswith('Literal escape sequences: \\t \\n \\"') for n in notes)
      and sum(1 for n in notes if n and "C:\\Users\\müller.k\\AppData\\Local\\Temp\\new_file.txt" in n) == 11)
check("emoji, Japanese, German, em dash, JSON and formula text intact", all(any(n == w for n in notes) for w in
      ["Emoji test 🔒✅🚫", 'User reported "slow page" — ticket #4521', "Größe überschritten; Datei abgelehnt", '{"reason": "policy", "rule": "R-12", "tags": ["dlp", "pii"]}',
       '=HYPERLINK("http://198.51.100.66/x","click")', 'Quoted, comma, and "double quotes" all in one']) and any(n and "ファイル" in n or (n and any(ord(c) > 0x3000 for c in n)) for n in notes))
check("display names with comma and quotes intact", {"Kowalski, Łukasz", 'O\'Brien, Siobhán "Shiv"', "李伟 (Li Wei)"} <= {get(s, "user.full_name") for s in src})
check("referrer with doubled quotes is one quote", sum(1 for s in src if get(s, "http.request.referrer") == 'https://search.example.com/?q="logbox+login"') == 63)
check("event_id keeps its leading zeros as text", all(isinstance(get(s, "event.id"), str) and len(get(s, "event.id")) == 7 for s in src))
check("status codes are numbers: 200 x91, 407 x23", collections.Counter(get(s, "http.response.status_code") for s in src)[200] == 91 and collections.Counter(get(s, "http.response.status_code") for s in src)[407] == 23)
check("related.ip is the client; related.user is the username", all(as_list(get(s, "related.ip")) == [get(s, "client.ip")] and as_list(get(s, "related.user")) == [get(s, "user.name")] for s in src))
leftover = {k for s in src for k in (get(s, "org.metadata.proxy") or {})}
check("only these keys left under org.metadata.proxy", leftover == {"event_time", "bytes_sent", "category", "notes"}, str(sorted(leftover)))

m = es(f"/{INDEX}/_mapping")[INDEX]["mappings"]["properties"]
check("mapping types: ip, long (status, bytes, port), keyword (id, full_name), wildcard (url.original)", m["client"]["properties"]["ip"]["type"] == "ip"
      and m["http"]["properties"]["response"]["properties"]["status_code"]["type"] == "long"
      and m["org"]["properties"]["metadata"]["properties"]["proxy"]["properties"]["bytes_sent"]["type"] == "long"
      and m["event"]["properties"]["id"]["type"] == "keyword" and m["user"]["properties"]["full_name"]["type"] == "keyword"
      and m["url"]["properties"]["original"]["type"] == "wildcard" and "path" not in m["url"]["properties"])

print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
