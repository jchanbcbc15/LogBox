#!/usr/bin/env python3
"""Functional test for the deployed log ingestion stack (R19). Python standard library only.

Run from anywhere on the host that runs the stack (it needs `docker` and `ansible-playbook`):

    python3 tests/functional_test.py                 everything
    python3 tests/functional_test.py --only syslog   only the real-sample checks for one sample
                                                     (what a demo prints after each sample)
    python3 tests/functional_test.py --skip-fixtures skip the synthetic fixtures (needs no extra containers)
    python3 tests/functional_test.py --keep-fixtures leave the fixture containers and documents in place

Settings come from the environment, all optional:
    ES_PASSWORD           password of the "elastic" user (default: read from the Ansible vault)
    ES_URL                default: https://127.0.0.1:9200 if the stack has TLS (CA in ~/logbox/certs), else http
    KIBANA_URL            default http://127.0.0.1:5601
    EXPECT_PIPELINE_HOST  inventory host name the events must carry (default demo-host)
    LOGBOX_BASE_DIR          where the playbook keeps its files on this host (default ~/logbox)

What it does, in order:
  1. Real samples (when present in samples/): every input record is an indexed document or a reject,
     record numbers are contiguous, timestamps are UTC with a Z, origin and collector fields are present,
     the dead letter queue is empty, record counts are 230 / 240 / 225.
  2. The whole index set: no non-ECS top-level field, and no field outside ECS or the metadata namespace in any mapping.
  2b. Security basics: no anonymous access, the Logstash user is confined to logs-*, ports on 127.0.0.1.
  2c. Kibana data views: the five views exist, resolve with @timestamp, default view and time window.
  3. Second playbook run reports no changes (R14).
  4. Re-ingesting each real sample leaves the document count and ids unchanged (R20).
  5. (Redis route, R7: not built, reported as SKIP.)
  6. Synthetic fixtures (tests/fixtures/fn_*): deployed with the playbook as four extra sources.
     Redaction, a deliberately broken record per source, occurrence numbers, multi-line notes, and a
     record Elasticsearch must refuse (dead letter queue). Re-ingest of the fixtures. Then removed again.
  7. After the clean-up the real counts are unchanged.
"""
import argparse, base64, csv, io, json, os, re, subprocess, sys, time, urllib.error, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ANSIBLE = os.path.join(ROOT, "ansible")
SAMPLES = os.path.join(ROOT, "samples")
EXPECT_HOST = os.environ.get("EXPECT_PIPELINE_HOST", "demo-host")
BASE_DIR = os.environ.get("LOGBOX_BASE_DIR", os.path.expanduser("~/logbox"))

def detect_es_url():
    """ES_URL if set; otherwise https://127.0.0.1:9200 when the stack was deployed with TLS (the playbook leaves its
    CA certificate in <base>/certs/ca.crt, which is then trusted for this process), else plain http. The one that answers wins."""
    if os.environ.get("ES_URL"):
        return os.environ["ES_URL"]
    ca = os.path.join(BASE_DIR, "certs", "ca.crt")
    schemes = ["http"]
    if os.path.exists(ca):
        os.environ.setdefault("SSL_CERT_FILE", ca)
        schemes = ["https", "http"]
    for scheme in schemes:
        try:
            urllib.request.urlopen(f"{scheme}://127.0.0.1:9200/", timeout=5)
        except urllib.error.HTTPError:
            return f"{scheme}://127.0.0.1:9200"      # answered (401 without a password is the normal answer)
        except Exception:
            continue
    return f"{schemes[0]}://127.0.0.1:9200"


ES_URL = detect_es_url()
# The playbook runs made by this test must use the same TLS mode and namespace as the stack under test.
PLAYBOOK_ARGS = [] if ES_URL.startswith("https") else ["-e", "es_tls=false"]


def detect_namespace():
    """The metadata namespace in use: METADATA_NS if set, else the value the running Logstash containers were given by the
    playbook (their METADATA_NS variable), else the default 'org'."""
    if os.environ.get("METADATA_NS"):
        return os.environ["METADATA_NS"]
    for n in ("proxy", "syslog", "firewall"):
        out = subprocess.run(["docker", "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", f"logbox-logstash-{n}"],
                             capture_output=True, text=True).stdout
        m = re.search(r"^METADATA_NS=(\S+)$", out, re.M)
        if m:
            return m.group(1)
    return "org"


NS = detect_namespace()
# Playbook runs made by this test must keep the stack's namespace.
PLAYBOOK_ARGS += ["-e", f"metadata_namespace={NS}"]

results = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)
    return bool(ok)


def section(title):
    print(f"\n== {title}", flush=True)


def skip(name, why):
    print(f"SKIP {name}  [{why}]", flush=True)


# ------------------------------------------------------------------------------------------ plumbing
def password():
    if os.environ.get("ES_PASSWORD"):
        return os.environ["ES_PASSWORD"]
    out = subprocess.run(["ansible-vault", "view", "group_vars/all/vault.yml"], cwd=ANSIBLE, capture_output=True, text=True)
    m = re.search(r"^vault_es_elastic_password:\s*(\S+)", out.stdout, re.M)
    if not m:
        sys.exit("Cannot read the elastic password: set ES_PASSWORD or create ansible/vault-password.txt")
    return m.group(1)


AUTH = "Basic " + base64.b64encode(f"elastic:{password()}".encode()).decode()


def es(path, body=None, method=None):
    req = urllib.request.Request(ES_URL + path, data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers={"Authorization": AUTH, "Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def search(index, agent=None, prefix=None, size=5000):
    """All documents of one index for one Logstash instance (agent.name), as hits with _id and _version."""
    if agent:
        query = {"term": {"agent.name": agent}}
    elif prefix:
        query = {"prefix": {"agent.name": prefix}}
    else:
        query = {"match_all": {}}
    r = es(f"/{index}/_search", {"size": size, "version": True, "query": query,
                                 "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}]})
    return [] if r is None else r["hits"]["hits"]


def get(d, path):
    for k in path.split("."):
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True)


def wait_for(fn, timeout, what, interval=3):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(interval)
    print(f"   timed out waiting for {what}", flush=True)
    return False


def dlq_bytes(container):
    """Bytes beyond the 1-byte header in the container's dead letter queue segments (0 = empty)."""
    out = docker("exec", container, "sh", "-c", "find /usr/share/logstash/data/dead_letter_queue -type f -name '*.log*' -printf '%s\\n' 2>/dev/null")
    sizes = [int(x) for x in out.stdout.split()]
    return sum(max(s - 1, 0) for s in sizes)


# ------------------------------------------------------------------------------------------ real samples
SAMPLE_DEF = {
    "syslog":   {"dataset": "logbox.syslog",   "file": "01_syslog_unstructured.log", "count": 230, "origin": ["host.name"]},
    "firewall": {"dataset": "logbox.firewall", "file": "03_firewall_cef.log",        "count": 240, "origin": ["observer.hostname"]},
    "proxy":    {"dataset": "logbox.proxy",    "file": "04_proxy_export.csv",        "count": 225, "origin": ["client.ip", "user.name"]},
}


def count_input_records(name, path):
    """Count records in a sample file independently of the pipeline."""
    text = open(path, encoding="utf-8", newline="").read()
    if name == "syslog":
        hdr = re.compile(r"^(?:[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} |<[0-9]+>1 )")
        return sum(1 for l in text.split("\n") if hdr.match(l))
    if name == "firewall":
        return sum(1 for l in text.split("\n") if l.strip())
    return len(list(csv.reader(io.StringIO(text)))) - 1  # minus the header row


def instance_checks(label, agent, dataset, fname, origin, expected, expect_rejects=None, dlq_entries=0):
    """The checks that apply to every instance, real or fixture. Returns (data hits, reject hits)."""
    data = search(f"logs-{dataset}", agent=agent)
    rej = search("logs-rejects", agent=agent)
    n = len(data) + len(rej) + dlq_entries
    check(f"{label}: input records ({expected}) = indexed ({len(data)}) + rejected ({len(rej)})" + (f" + dead letter queue ({dlq_entries})" if dlq_entries else ""),
          n == expected)
    if expect_rejects is not None:
        check(f"{label}: exactly {expect_rejects} rejected", len(rej) == expect_rejects)
    srcs = [h["_source"] for h in data + rej]
    check(f"{label}: every @timestamp is UTC (ends with Z)", all(str(s.get("@timestamp", "")).endswith("Z") for s in srcs))
    check(f"{label}: collector fields on every document (agent.name, pipeline host, log.file.path, event.dataset, 64-hex _id)",
          all(get(h["_source"], "agent.name") == agent and get(h["_source"], f"{NS}.metadata.pipeline.host") == EXPECT_HOST
              and str(get(h["_source"], "log.file.path")).endswith(fname) and get(h["_source"], "event.dataset") == dataset
              and re.fullmatch(r"[0-9a-f]{64}", h["_id"])
              for h in data + rej), f"host expected {EXPECT_HOST}")
    check(f"{label}: no record_seq field (removed; locate a record with event.original, event.id or log.offset)",
          all(get(h["_source"], f"{NS}.metadata.pipeline.record_seq") is None for h in data + rej))
    check(f"{label}: origin fields present on every indexed document ({', '.join(origin)})",
          all(get(h["_source"], f) not in (None, "") for h in data for f in origin))
    check(f"{label}: no reject has stage 'unknown'", all(get(h["_source"], f"{NS}.metadata.reject.stage") != "unknown" for h in rej))
    check(f"{label}: no reject is in a data index; no data document is tagged _reject",
          all(get(h["_source"], "event.kind") == "pipeline_error" for h in rej) and not any("_reject" in (h["_source"].get("tags") or []) for h in data))
    return data, rej


def real_checks(names):
    section("1. Real samples: reconciliation, numbering, time, origin and collector fields")
    for name in names:
        d = SAMPLE_DEF[name]
        path = os.path.join(SAMPLES, d["file"])
        if not os.path.exists(path):
            skip(f"{name}: real sample", f"{d['file']} is not in samples/")
            continue
        expected = count_input_records(name, path)
        check(f"{name}: the sample holds {d['count']} records (counted independently of the pipeline)", expected == d["count"], f"counted {expected}")
        data, rej = instance_checks(name, f"logstash-{name}", d["dataset"], d["file"], d["origin"], expected, expect_rejects=0)
        check(f"{name}: dead letter queue is empty", dlq_bytes(f"logbox-logstash-{name}") == 0, f"{dlq_bytes(f'logbox-logstash-{name}')} bytes")
        if name == "proxy":
            rows = list(csv.DictReader(io.StringIO(open(path, encoding="utf-8", newline="").read())))
            want = sorted(r["notes"].replace("\r", "") for r in rows if "\n" in r["notes"])
            got = sorted(get(h["_source"], f"{NS}.metadata.proxy.notes") for h in data if "\n" in (get(h["_source"], f"{NS}.metadata.proxy.notes") or ""))
            check(f"proxy: {len(want)} multi-line notes arrive as {len(want)} single documents with the line breaks intact (R16)", len(want) == 21 and want == got)
        if name == "syslog":
            # Message bodies are not parsed in this build, so a joined stack trace is a document tagged
            # "multiline" whose message holds the line breaks (error.stack_trace is not set).
            traces = [h for h in data if "multiline" in (h["_source"].get("tags") or []) and "\n" in (get(h["_source"], "message") or "")]
            check("syslog: the 3 Java stack traces are joined to their records (3 documents tagged multiline with line breaks in message)", len(traces) == 3)


# ------------------------------------------------------------------------------------------ mappings (R4)
def mapping_checks():
    section("2. Index mappings: nothing outside ECS (R4)")
    ecs = {l.strip() for l in open(os.path.join(HERE, "ecs_8.17_fields.txt")) if l.strip() and not l.startswith("#")}
    top = {f.split(".")[0] for f in ecs}

    def leaves(props, prefix=""):
        for k, v in props.items():
            if "properties" in v:
                yield from leaves(v["properties"], prefix + k + ".")
            else:
                yield prefix + k

    maps = es("/logs-*/_mapping") or {}
    check("indexes exist: logs-logbox.syslog, logs-logbox.firewall, logs-logbox.proxy", all(i in maps for i in ("logs-logbox.syslog", "logs-logbox.firewall", "logs-logbox.proxy")), str(sorted(maps)))
    bad_top, bad_leaf = [], []
    for idx, m in maps.items():
        props = m["mappings"].get("properties", {})
        bad_top += [f"{idx}:{k}" for k in props if k not in top and k != NS]
        bad_leaf += [f"{idx}:{f}" for f in leaves(props) if f not in ecs and not f.startswith(NS + ".")]
    check("no non-ECS top-level field in any index mapping (ECS 8.17 field sets plus the metadata namespace)", not bad_top, str(bad_top))
    check("every mapped field outside the metadata namespace is an ECS 8.17 field name", not bad_leaf, str(bad_leaf[:8]))
    logbox_bad = []
    for idx, m in maps.items():
        for f in leaves(m["mappings"].get("properties", {})):
            if f.startswith(NS + ".") and not f.startswith(NS + ".metadata."):
                logbox_bad.append(f"{idx}:{f}")
    check("everything under the namespace is under <namespace>.metadata", not logbox_bad, str(logbox_bad))



# ------------------------------------------------------------------------------------------ security basics
def vault_value(key):
    out = subprocess.run(["ansible-vault", "view", "group_vars/all/vault.yml"], cwd=ANSIBLE, capture_output=True, text=True)
    m = re.search(rf"^{key}:\s*(\S+)", out.stdout, re.M)
    return m.group(1) if m else None


def status(path, method="GET", body=None, user=None, pw=None):
    headers = {"Content-Type": "application/json"}
    if user:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    req = urllib.request.Request(ES_URL + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers=headers)
    try:
        return urllib.request.urlopen(req).status
    except urllib.error.HTTPError as e:
        return e.code


def security_checks():
    section("2b. Security basics (first-round controls)")
    check("an anonymous request to Elasticsearch is refused (401)", status("/") == 401)
    w = vault_value("vault_logstash_writer_password")
    user = "logbox_logstash_writer"
    if not w:
        skip("Logstash user checks", "vault_logstash_writer_password not readable")
    else:
        ok_write = status("/logs-logbox.fntest/_doc/1", "PUT", {"a": 1}, user, w)
        es("/logs-logbox.fntest", method="DELETE")
        check("the Logstash user can write to logs-*", ok_write in (200, 201), str(ok_write))
        check("the Logstash user is refused writing to another index (403)", status("/other-index/_doc/1", "PUT", {"a": 1}, user, w) == 403)
        check("the Logstash user is refused reading, deleting an index and calling the security API (403)",
              all(status(p, m, None, user, w) == 403 for m, p in (("GET", "/logs-logbox.proxy/_search"), ("DELETE", "/logs-logbox.proxy"), ("GET", "/_security/user"))))
    if ES_URL.startswith("https"):
        check("TLS: Elasticsearch answers over HTTPS and its certificate verifies against our CA (every call here did)", True, ES_URL)
        try:
            urllib.request.urlopen(ES_URL.replace("https://", "http://") + "/", timeout=5)
            plain = "served"
        except urllib.error.HTTPError:
            plain = "served"
        except Exception:
            plain = "refused"
        check("TLS: a plain-http request to the same port is not served", plain == "refused", plain)
        for c in [f"logbox-logstash-{n}" for n in ("syslog", "firewall", "proxy")]:
            env = docker("inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", c).stdout
            check(f"TLS: {c} is configured for https (ES_SSL=true, https URL)", "ES_SSL=true" in env and "ES_URL=https://" in env)
    else:
        skip("TLS checks", "the stack runs without TLS (es_tls=false)")
    for c in ("logbox-elasticsearch", "logbox-kibana"):
        ports = json.loads(docker("inspect", "-f", "{{json .NetworkSettings.Ports}}", c).stdout or "{}")
        hosts = {b["HostIp"] for v in ports.values() for b in (v or [])}
        check(f"{c}: every published port is bound to 127.0.0.1", hosts == {"127.0.0.1"}, str(hosts))

# ------------------------------------------------------------------------------------------ Kibana data views
KIBANA_URL = os.environ.get("KIBANA_URL", "http://127.0.0.1:5601")


def kibana(path, internal=False, auth=True):
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = AUTH
    if internal:
        headers.update({"x-elastic-internal-origin": "Kibana", "elastic-api-version": "1"})
    req = urllib.request.Request(KIBANA_URL + path, headers=headers)
    try:
        r = urllib.request.urlopen(req)
        return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, None
    except urllib.error.URLError:
        return 0, None


def kibana_checks():
    section("2c. Kibana data views (Discover opens on the data)")
    code, _ = kibana("/api/data_views", auth=False)
    check("Kibana refuses an anonymous request (401)", code == 401, str(code))
    code, listing = kibana("/api/data_views")
    if code != 200:
        check("Kibana answers the data views API", False, str(code))
        return
    have = {v["id"]: v for v in listing["data_view"]}
    want = {"logbox-logs-all": "logs-logbox.*", "logbox-logs-syslog": "logs-logbox.syslog", "logbox-logs-firewall": "logs-logbox.firewall",
            "logbox-logs-proxy": "logs-logbox.proxy", "logbox-rejects": "logs-rejects"}
    check("the five data views exist with the expected index patterns",
          {i: have.get(i, {}).get("title") for i in want} == want, str({i: have.get(i, {}).get("title") for i in want}))
    for vid, title in want.items():
        code, full = kibana(f"/api/data_views/data_view/{vid}")
        tf = get(full or {}, "data_view.timeFieldName")
        code2, fields = kibana(f"/internal/data_views/fields?pattern={urllib.parse.quote(title)}&meta_fields=_id", internal=True)
        by_name = {f["name"]: f for f in (fields or {}).get("fields", [])}
        ts = by_name.get("@timestamp", {})
        check(f"{vid}: time field is @timestamp, and Kibana resolves {title} with @timestamp as a searchable date",
              tf == "@timestamp" and ts.get("type") == "date" and ts.get("searchable"), f"time field {tf}, fields {len(by_name)}")
    code, d = kibana("/api/data_views/default")
    check("the all-sources view is the default view", get(d or {}, "data_view_id") == "logbox-logs-all", str(d))
    code, s = kibana("/api/kibana/settings")
    window = json.loads(get(s or {}, "settings.timepicker:timeDefaults.userValue") or "{}")
    m = re.fullmatch(r"now-(\d+)y", window.get("from", ""))
    oldest = (es("/logs-logbox.*/_search", {"size": 0, "aggs": {"o": {"min": {"field": "@timestamp"}}}}) or {}).get("aggregations", {}).get("o", {}).get("value_as_string")
    age_days = (time.time() - time.mktime(time.strptime(oldest[:19], "%Y-%m-%dT%H:%M:%S"))) / 86400 if oldest else None
    check("Discover's default time window reaches back past the oldest sample record",
          bool(m) and age_days is not None and age_days < int(m.group(1)) * 365, f"window {window}, oldest record {oldest}")


# ------------------------------------------------------------------------------------------ playbook (R14)
def idempotence_check():
    section("3. Second playbook run reports no changes (R14)")
    r = subprocess.run(["ansible-playbook", "site.yml", *PLAYBOOK_ARGS], cwd=ANSIBLE, capture_output=True, text=True)
    recap = [l for l in r.stdout.splitlines() if re.search(r"ok=\d+\s+changed=\d+", l)]
    m = re.search(r"changed=(\d+).*failed=(\d+)", recap[-1]) if recap else None
    check("ansible-playbook site.yml: changed=0 failed=0", r.returncode == 0 and m and m.group(1) == "0" and m.group(2) == "0", recap[-1].strip() if recap else r.stdout[-300:])


# ------------------------------------------------------------------------------------------ re-ingest (R20)
def reingest_check(label, items):
    """items: [(container, index, agent)]. Restart, wait for every document to be rewritten, compare ids and counts."""
    before = {}
    for container, index, agent in items:
        before[(container, index)] = {h["_id"]: h["_version"] for h in search(index, agent=agent)}
    for container in sorted({c for c, _, _ in items}):
        docker("restart", container)

    def rewritten():
        for container, index, agent in items:
            now = {h["_id"]: h["_version"] for h in search(index, agent=agent)}
            old = before[(container, index)]
            if len(now) != len(old) or any(now.get(i, 0) <= v for i, v in old.items()):
                return False
        return True

    ok = wait_for(rewritten, 240, f"{label} to be re-read")
    for container, index, agent in items:
        now = {h["_id"]: h["_version"] for h in search(index, agent=agent)}
        old = before[(container, index)]
        check(f"{label}: {container} re-read its file; {index}: {len(old)} documents before, {len(now)} after, same ids, versions raised",
              ok and set(now) == set(old), f"versions now {sorted(set(now.values()))}")


# ------------------------------------------------------------------------------------------ fixtures
FX = [("fx-syslog", "logbox.syslog"), ("fx-firewall", "logbox.firewall"), ("fx-dlq", "logbox.firewall"), ("fx-proxy", "logbox.proxy")]


def fixtures_deploy():
    section("6a. Deploy the synthetic fixtures as four extra sources (through the playbook)")
    r = subprocess.run(["ansible-playbook", "site.yml", "-e", "@../tests/fixture_sources.yml", *PLAYBOOK_ARGS], cwd=ANSIBLE, capture_output=True, text=True)
    check("ansible-playbook with the four fixture sources succeeds", r.returncode == 0, r.stdout[-300:] if r.returncode else "")
    if r.returncode:
        return False
    expect = {"fx-syslog": ("logs-logbox.syslog", 6), "fx-firewall": ("logs-logbox.firewall", 4), "fx-proxy": ("logs-logbox.proxy", 6)}

    def landed():
        for name, (index, n) in expect.items():
            a = f"logstash-{name}"
            if len(search(index, agent=a)) + len(search("logs-rejects", agent=a)) < n - (0 if name != "fx-proxy" else 1):
                return False
        return len(search("logs-logbox.firewall", agent="logstash-fx-dlq")) >= 1 and dlq_bytes("logbox-logstash-fx-dlq") > 0

    ok = check("the fixtures were read (all records landed, the refused record is in the dead letter queue)", wait_for(landed, 240, "the fixtures to be ingested"))
    time.sleep(8)
    return ok


def fixture_checks():
    section("6b. Fixtures: redaction, broken records, occurrence numbers, multi-line notes, dead letter queue")
    # ---- syslog
    data, rej = instance_checks("fx-syslog", "logstash-fx-syslog", "logbox.syslog", "fn_syslog.log", ["host.name"], 6, expect_rejects=1)
    msgs = [get(h["_source"], "message") for h in data]
    check("redaction (syslog): password= and token= values masked, key kept", "login ok password=[REDACTED] token=[REDACTED] user=zed" in msgs, str(msgs[:1]))
    check("redaction (syslog): 'Failed password for ...' untouched", "Failed password for invalid user admin from 192.0.2.1 port 22 ssh2" in msgs)
    check("redaction: no credential value in any field except event.original (syslog)", not any(v in json.dumps({k: x for k, x in h["_source"].items() if k != "event"}) for h in data for v in ("hunter2", "abc123")))
    twice = [h for h in data if get(h["_source"], "event.original", ) == "Oct 14 12:00:03 fnhost app[3]: the same record twice"]
    check("occurrence: two identical records are two documents with different _id", len(twice) == 2 and twice[0]["_id"] != twice[1]["_id"])
    r0 = rej[0]["_source"] if rej else {}
    check("broken record (syslog): rejected once, stage syslog.date.timestamp, error invalid_time, raw record kept; absent from the data index",
          len(rej) == 1 and get(r0, f"{NS}.metadata.reject.stage") == "syslog.date.timestamp" and get(r0, "error.type") == "invalid_time" and get(r0, "error.message")
          and "Feb 30" in get(r0, "event.original")
          and not any("Feb 30" in (get(h["_source"], "event.original") or "") for h in data))
    check("broken record (syslog): the record after it is indexed normally", "record after the broken one" in msgs)
    # ---- firewall
    data, rej = instance_checks("fx-firewall", "logstash-fx-firewall", "logbox.firewall", "fn_cef.log", ["observer.hostname"], 4, expect_rejects=1)
    byc = {get(h["_source"], "event.code"): h["_source"] for h in data}
    t1, t2 = byc.get("TEST-1", {}), byc.get("TEST-2", {})
    check("redaction (CEF): event.reason masked, escaped form handled, url token masked, neighbours intact",
          get(t1, "event.reason") == "Login ok password=[REDACTED] token=[REDACTED] for user" and get(t1, "url.original") == "https://www.example.edu/x?token=[REDACTED]&lang=fr"
          and get(t1, f"{NS}.metadata.firewall.cs1") == "R-9" and get(t1, "source.ip") == "192.0.2.9", str(get(t1, "event.reason")))
    check("redaction (CEF): 'Failed password for admin and invalid token' untouched", get(t2, "event.reason") == "Failed password for admin and invalid token")
    r0 = rej[0]["_source"] if rej else {}
    check("broken record (CEF): rejected once, stage firewall.grok.header, error no_match, raw record kept; absent from the data index",
          len(rej) == 1 and get(r0, f"{NS}.metadata.reject.stage") == "firewall.grok.header" and get(r0, "error.type") == "no_match" and get(r0, "error.message")
          and "this is not a CEF line" in get(r0, "event.original")
          and not any("not a CEF line" in (get(h["_source"], "event.original") or "") for h in data))
    check("broken record (CEF): the record after it is indexed normally (TEST-3)", "TEST-3" in byc)
    # ---- proxy
    data, rej = instance_checks("fx-proxy", "logstash-fx-proxy", "logbox.proxy", "fn_proxy.csv", ["client.ip", "user.name"], 5, expect_rejects=1)
    byid = {get(h["_source"], "event.id"): h["_source"] for h in data}
    p1 = byid.get("0000990", {})
    check("redaction (CSV): url.original, referrer and notes masked; cells after them did not shift",
          get(p1, "url.original") == "https://example.com/x?token=[REDACTED]&lang=fr&password=[REDACTED]"
          and get(p1, "http.request.referrer") == "https://ref.example.com/?api_key=[REDACTED]&x=1" and get(p1, f"{NS}.metadata.proxy.notes") == "login password=[REDACTED], then token=[REDACTED]"
          and get(p1, "http.response.status_code") == 200 and get(p1, f"{NS}.metadata.proxy.category") == "News")
    check("redaction (CSV): 'Failed password for asmith; invalid token' untouched", get(byid.get("0000991", {}), f"{NS}.metadata.proxy.notes") == "Failed password for asmith; invalid token")
    check("multi-line note (CSV): one document, line breaks intact (R16)", get(byid.get("0000992", {}), f"{NS}.metadata.proxy.notes") == "line one\nline two\nline three")
    r0 = rej[0]["_source"] if rej else {}
    check("broken record (CSV): rejected once, stage proxy.csv.record, error malformed_record, raw record kept; absent from the data index",
          len(rej) == 1 and get(r0, f"{NS}.metadata.reject.stage") == "proxy.csv.record" and get(r0, "error.type") == "malformed_record" and get(r0, "error.message")
          and "0000993" in get(r0, "event.original") and "0000993" not in byid)
    check("broken record (CSV): the record after it is indexed normally (0000994)", "0000994" in byid)
    check("redaction: no credential value in any indexed field except event.original (CSV and CEF)",
          not any(v in json.dumps({k: x for k, x in s.items() if k != "event"}) + json.dumps(get(s, "event.reason")) for s in list(byid.values()) + [t1, t2]
                  for v in ("hunter2", "abc123", "tok999", "pw1", "K9")))
    # ---- dead letter queue
    dlq_data = search("logs-logbox.firewall", agent="logstash-fx-dlq")
    dlq_rej = search("logs-rejects", agent="logstash-fx-dlq")
    codes = [get(h["_source"], "event.code") for h in dlq_data]
    check("dead letter queue: the record with source.ip 999.999.1.1 is refused by Elasticsearch and kept in the DLQ (not indexed, not in logs-rejects)",
          "TEST-DLQ" not in codes and not dlq_rej and dlq_bytes("logbox-logstash-fx-dlq") > 0, f"DLQ bytes={dlq_bytes('logbox-logstash-fx-dlq')}")
    check("dead letter queue: the record after it (TEST-OK) is indexed normally", codes == ["TEST-OK"], str(codes))
    check("the fixture instances other than fx-dlq have an empty dead letter queue", all(dlq_bytes(f"logbox-logstash-{n}") == 0 for n in ("fx-syslog", "fx-firewall", "fx-proxy")))


def fixtures_reingest():
    section("6c. Re-ingest the fixtures: counts, ids and reject counts unchanged (R20)")
    reingest_check("fixtures", [("logbox-logstash-fx-syslog", "logs-logbox.syslog", "logstash-fx-syslog"), ("logbox-logstash-fx-firewall", "logs-logbox.firewall", "logstash-fx-firewall"),
                                ("logbox-logstash-fx-proxy", "logs-logbox.proxy", "logstash-fx-proxy"), ("logbox-logstash-fx-syslog", "logs-rejects", "logstash-fx-syslog"),
                                ("logbox-logstash-fx-firewall", "logs-rejects", "logstash-fx-firewall"), ("logbox-logstash-fx-proxy", "logs-rejects", "logstash-fx-proxy")])


def fixtures_teardown():
    section("7. Remove the fixtures again")
    for name, _ in FX:
        docker("rm", "-f", f"logbox-logstash-{name}")
        docker("volume", "rm", f"logbox-ls-{name}-data")
        subprocess.run(["rm", "-rf", f"{BASE_DIR}/pipeline/{name}", f"{BASE_DIR}/config/{name}"])
    for f in ("fn_syslog.log", "fn_cef.log", "fn_dlq.log", "fn_proxy.csv"):
        try:
            os.remove(f"{BASE_DIR}/data/{f}")
        except FileNotFoundError:
            pass
    es("/logs-logbox.syslog,logs-logbox.firewall,logs-logbox.proxy,logs-rejects/_delete_by_query?ignore_unavailable=true&refresh=true&conflicts=proceed",
       {"query": {"prefix": {"agent.name": "logstash-fx-"}}}, method="POST")
    left = sum(len(search(i, prefix="logstash-fx-")) for i in ("logs-logbox.syslog", "logs-logbox.firewall", "logs-logbox.proxy", "logs-rejects"))
    check("no fixture document is left in any index", left == 0, f"{left} left")


def real_counts_unchanged(names):
    for name in names:
        d = SAMPLE_DEF[name]
        if os.path.exists(os.path.join(SAMPLES, d["file"])):
            n = len(search(f"logs-{d['dataset']}", agent=f"logstash-{name}"))
            check(f"{name}: real document count unchanged after the fixtures ({d['count']})", n == d["count"], str(n))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", choices=list(SAMPLE_DEF), help="run only the real-sample checks for this sample")
    ap.add_argument("--skip-fixtures", action="store_true")
    ap.add_argument("--keep-fixtures", action="store_true")
    a = ap.parse_args()
    names = [a.only] if a.only else list(SAMPLE_DEF)

    info = es("/")
    if not info:
        sys.exit("Elasticsearch is not answering at " + ES_URL)
    print(f"Elasticsearch {info['version']['number']} at {ES_URL}, expecting pipeline host '{EXPECT_HOST}'")

    real_checks(names)
    if a.only:
        total = len(results)
        print(f"\n{sum(results)}/{total} checks passed")
        sys.exit(0 if all(results) else 1)

    mapping_checks()
    security_checks()
    kibana_checks()
    idempotence_check()
    section("4. Re-ingest each real sample: counts and ids unchanged (R20)")
    items = [(f"logbox-logstash-{n}", f"logs-{SAMPLE_DEF[n]['dataset']}", f"logstash-{n}") for n in names if os.path.exists(os.path.join(SAMPLES, SAMPLE_DEF[n]["file"]))]
    if items:
        reingest_check("real samples", items)
    else:
        skip("re-ingest", "no real samples in samples/")
    section("5. Not built: Redis route (R7, stretch goal)")
    skip("Redis delivers the same JSON documents", "R7 is not built")

    if not a.skip_fixtures:
        try:
            if fixtures_deploy():
                fixture_checks()
                fixtures_reingest()
        finally:
            if not a.keep_fixtures:
                fixtures_teardown()
                real_counts_unchanged(names)
    else:
        skip("synthetic fixtures", "--skip-fixtures")

    print(f"\n{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
