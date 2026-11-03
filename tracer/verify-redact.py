#!/usr/bin/env python3
"""Credential redaction checks (R17, 22-redact.conf). Reads tracer/.env for the password.

Run after ingesting the three redaction fixtures (copy tests/fixtures/redact_syslog.log, redact_cef.log and
redact_proxy.csv to samples/, start the three instances with INPUT_PATH=/data/redact_syslog.log,
FW_INPUT_PATH=/data/redact_cef.log, PX_INPUT_PATH=/data/redact_proxy.csv). Then delete the indices and
re-ingest the real samples.

Superseded in practice by tests/functional_test.py (section 6, fixtures fn_*), which does the same on the deployed
stack and passes. Updated 2026-11-01 for the demo mapping scope (no rule.name, no url.query) but NOT re-run: it needs
indexes that hold only the fixtures.
"""
import base64, json, os, sys, urllib.error, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
# The password comes from the ES_PASSWORD environment variable if set (deployed stack), else from tracer/.env.
env = {} if os.environ.get("ES_PASSWORD") else dict(l.strip().split("=", 1) for l in open(os.path.join(HERE, ".env")) if "=" in l)
env["ES_PASSWORD"] = os.environ.get("ES_PASSWORD") or env["ES_PASSWORD"]
AUTH = "Basic " + base64.b64encode(f"elastic:{env['ES_PASSWORD']}".encode()).decode()


def docs(index):
    req = urllib.request.Request(f"http://127.0.0.1:9200/{index}/_search?size=100",
                                 data=json.dumps({"query": {"match_all": {}}}).encode(), headers={"Authorization": AUTH, "Content-Type": "application/json"})
    try:
        return [h["_source"] for h in json.load(urllib.request.urlopen(req))["hits"]["hits"]]
    except urllib.error.HTTPError:
        return []


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


sys_docs = sorted(docs("logs-logbox.syslog"), key=lambda s: get(s, "org.metadata.pipeline.record_seq"))
fw = {get(s, "event.code"): s for s in docs("logs-logbox.firewall")}
px = {get(s, "event.id"): s for s in docs("logs-logbox.proxy")}
check("fixtures were ingested: 4 syslog, 2 firewall, 2 proxy, 0 rejects", len(sys_docs) == 4 and len(fw) == 2 and len(px) == 2 and not docs("logs-rejects"),
      f"{len(sys_docs)} {len(fw)} {len(px)}")

m = [get(s, "message") for s in sys_docs]
check("syslog: password= and token= values masked, key and neighbours kept", m[0] == "login ok password=[REDACTED] token=[REDACTED] user=zed", m[0])
check("syslog: 'Failed password for ...' unchanged", m[1] == "Failed password for invalid user admin from 192.0.2.1 port 22 ssh2", m[1])
check("syslog: Authorization: Bearer, API_KEY= (upper case) and 'secret:' masked; ; and , stop the value",
      m[2] == "Authorization: Bearer [REDACTED] and API_KEY=[REDACTED];secret: [REDACTED],next", m[2])
check("syslog: PWD=, 'invalid token', 'Token refresh failed', 'incorrect password attempts', xtoken= unchanged",
      all(t in m[3] for t in ("PWD=/home/x", "invalid token,", "Token refresh failed,", "3 incorrect password attempts,", "xtoken=keep")), m[3])
check("syslog known limit: a quoted value with a space is masked only up to the space", 'passphrase="[REDACTED] words"' in m[3], m[3])

t1, t2 = fw["TEST-1"], fw["TEST-2"]
check("firewall: event.reason masked (a field that was never in a field list)", get(t1, "event.reason") == "Login ok password=[REDACTED] token=[REDACTED] for user", get(t1, "event.reason"))
check("firewall: the CEF escaped form password\\=... is masked and then unescaped", "hunter2" not in json.dumps(get(t1, "event.reason")) and "abc123" not in json.dumps(get(t1, "event.reason")))
check("firewall: url token masked, next parameter and the other fields intact", get(t1, "url.original") == "https://www.example.edu/x?token=[REDACTED]&lang=fr"
      and get(t1, "org.metadata.firewall.cs1") == "R-9" and get(t1, "user.name") == "redact.test" and get(t1, "source.ip") == "192.0.2.9")
check("firewall: control line 'Failed password for admin and invalid token' unchanged", get(t2, "event.reason") == "Failed password for admin and invalid token")

p1, p2 = px["0000990"], px["0000991"]
check("proxy: url.original, referrer and notes masked", get(p1, "url.original") == "https://example.com/x?token=[REDACTED]&lang=fr&password=[REDACTED]"
      and get(p1, "http.request.referrer") == "https://ref.example.com/?api_key=[REDACTED]&x=1"
      and get(p1, "org.metadata.proxy.notes") == "login password=[REDACTED], then token=[REDACTED]")
check("proxy: cells after the masked values did not shift", get(p1, "http.response.status_code") == 200 and get(p1, "org.metadata.proxy.bytes_sent") == 10
      and get(p1, "org.metadata.proxy.category") == "News" and get(p1, "user_agent.original") == "Agent/1.0" and get(p1, "user.name") == "redact.test")
check("proxy: control row 'Failed password for asmith; invalid token' unchanged", get(p2, "org.metadata.proxy.notes") == "Failed password for asmith; invalid token")

raw = [get(s, "event.original") for s in sys_docs] + [get(t1, "event.original"), get(p1, "event.original")]
check("event.original stays unredacted (decided limitation)", "hunter2" in raw[0] and "s3cr3t" in raw[2] and "hunter2" in raw[4] and "pw1" in raw[5])
def without_original(d):
    d = dict(d)
    d["event"] = {k: v for k, v in d.get("event", {}).items() if k != "original"}
    return d


every = json.dumps([without_original(d) for d in list(sys_docs) + list(fw.values()) + list(px.values())], ensure_ascii=False)
check("no credential value appears anywhere except event.original", not any(v in every for v in ("hunter2", "abc123", "tok999", "pw1", "K9", "K-123", "s3cr3t", "eyJhbGciOi")))

print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
