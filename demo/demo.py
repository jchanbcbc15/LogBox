#!/usr/bin/env python3
"""Demo script for the log ingestion stack (R10, R15). Python standard library only.

Run from anywhere (it finds the repository from its own location):

    demo/demo.py check                     are the tools, secrets and sample files in place?
    demo/demo.py up                        deploy Elasticsearch and Kibana only (no log source yet)
    demo/demo.py ingest syslog             deploy and run ONE sample end to end, then show counts and
                                           the functional test result (also: firewall, proxy)
    demo/demo.py find syslog               show one ingested event and the Kibana query that finds it
                                           (proxy: --record N uses event.id 000000N)
    demo/demo.py all                       up, then ingest syslog, firewall and proxy in turn
    demo/demo.py reset --yes               remove the containers, volumes, network and working folder

Where the sample files are (they are private and not in Git): the folder given with --samples, else the
environment variable LOGBOX_SAMPLES_DIR, else the "samples" folder of this repository. The folder must hold
01_syslog_unstructured.log, 03_firewall_cef.log and 04_proxy_export.csv under those names.

The password of the Kibana user "elastic" is never printed. Read it with:
    cd ansible && ansible-vault view group_vars/all/vault.yml
"""
import argparse, base64, json, os, re, shutil, ssl, subprocess, sys, time, urllib.error, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ANSIBLE = os.path.join(ROOT, "ansible")
KIBANA_URL = os.environ.get("KIBANA_URL", "http://127.0.0.1:5601")
BASE_DIR = os.environ.get("LOGBOX_BASE_DIR", os.path.expanduser("~/logbox"))

def tls_context():
    """A TLS context that trusts the playbook's private CA once <base>/certs/ca.crt exists. It is built for every request
    on purpose: the file does not exist before the first deployment, and a context built earlier would never trust it."""
    ca = os.path.join(BASE_DIR, "certs", "ca.crt")
    return ssl.create_default_context(cafile=ca) if os.path.exists(ca) else ssl.create_default_context()


def detect_es_url():
    """ES_URL if set; otherwise https://127.0.0.1:9200 when the stack was deployed with TLS (the playbook leaves its
    CA certificate in <base>/certs/ca.crt), else plain http. The one that answers wins."""
    if os.environ.get("ES_URL"):
        return os.environ["ES_URL"]
    schemes = ["https", "http"] if os.path.exists(os.path.join(BASE_DIR, "certs", "ca.crt")) else ["http"]
    for scheme in schemes:
        try:
            urllib.request.urlopen(f"{scheme}://127.0.0.1:9200/", timeout=5, context=tls_context())
        except urllib.error.HTTPError:
            return f"{scheme}://127.0.0.1:9200"      # answered (401 without a password is the normal answer)
        except Exception:
            continue
    return f"{schemes[0]}://127.0.0.1:9200"


ES_URL = detect_es_url()


def detect_namespace():
    """The metadata namespace: METADATA_NS if set, else what the running Logstash containers were given, else 'org'."""
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
LOG = os.path.join(HERE, "ansible-last-run.log")

SOURCES = {
    "syslog":   {"file": "01_syslog_unstructured.log", "dataset": "logbox.syslog"},
    "firewall": {"file": "03_firewall_cef.log",        "dataset": "logbox.firewall"},
    "proxy":    {"file": "04_proxy_export.csv",        "dataset": "logbox.proxy"},
}
# Fields that identify one event of a source, in the order the "find" command tries them.
# (field, is_number)
KEY_FIELDS = {
    "syslog":   [("host.name", False), ("process.pid", True), ("user.name", False), ("source.ip", False)],
    "firewall": [("source.ip", False), ("source.port", True), ("destination.ip", False)],
    "proxy":    [("event.id", False)],
}


def say(text=""):
    print(text, flush=True)


def step(text):
    print(f"\n=== {text}", flush=True)


# ---------------------------------------------------------------------------------------------- plumbing
def samples_dir(args):
    return os.path.abspath(os.path.expanduser(args.samples or os.environ.get("LOGBOX_SAMPLES_DIR") or os.path.join(ROOT, "samples")))


def vault_password():
    if os.environ.get("ES_PASSWORD"):
        return os.environ["ES_PASSWORD"]
    out = subprocess.run(["ansible-vault", "view", "group_vars/all/vault.yml"], cwd=ANSIBLE, capture_output=True, text=True)
    m = re.search(r"^vault_es_elastic_password:\s*(\S+)", out.stdout, re.M)
    if not m:
        sys.exit("Cannot read the elastic password. Run ansible/setup-secrets.sh first (or set ES_PASSWORD).")
    return m.group(1).strip("\"'")


_auth = None


def es(path, body=None, method=None):
    global _auth
    if _auth is None:
        _auth = "Basic " + base64.b64encode(f"elastic:{vault_password()}".encode()).decode()
    req = urllib.request.Request(ES_URL + path, data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers={"Authorization": _auth, "Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req, timeout=30, context=tls_context()))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    except urllib.error.URLError:
        return None


def get(d, path):
    for k in path.split("."):
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def run_playbook(args, enabled, label):
    """Run site.yml with only the given sources enabled. Shows task names, keeps the full output in a log file."""
    extra = ["-e", json.dumps({"enabled_sources": enabled}), "-e", f"samples_src_dir={samples_dir(args)}"]
    if getattr(args, "namespace", None):
        extra += ["-e", f"metadata_namespace={args.namespace}"]   # the namespace for non-ECS fields (default org)
    if getattr(args, "no_tls", False):
        extra += ["-e", "es_tls=false"]        # TLS is on by default; this runs the demo over plain http
    say(f"Running: ansible-playbook site.yml  ({label}; full output in demo/ansible-last-run.log)")
    t0 = time.time()
    with open(LOG, "w") as log:
        p = subprocess.Popen(["ansible-playbook", "site.yml", *extra], cwd=ANSIBLE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        tail = []
        for line in p.stdout:
            log.write(line)
            tail = (tail + [line])[-40:]
            if re.match(r"^(PLAY \[|TASK \[(elasticsearch|kibana|stack_base|logstash_instance) : )", line):
                print("   " + line.strip(), flush=True)
            elif line.startswith("PLAY RECAP") or re.match(r"^\S+\s+: ok=", line):
                print("   " + line.rstrip(), flush=True)
        p.wait()
    if p.returncode != 0:
        say("".join(tail))
        sys.exit(f"The playbook failed (exit {p.returncode}); see {LOG}")
    say(f"   done in {time.time() - t0:.0f} s")
    global ES_URL, NS
    ES_URL = detect_es_url()          # the playbook may have switched between https and http
    NS = detect_namespace()


def counts(name):
    agent = f"logstash-{name}"
    q = {"size": 0, "query": {"term": {"agent.name": agent}}}
    d = es(f"/logs-{SOURCES[name]['dataset']}/_search", q)
    r = es("/logs-rejects/_search", q)
    return (d["hits"]["total"]["value"] if d else 0), (r["hits"]["total"]["value"] if r else 0)


def wait_until_ingested(name, timeout=300):
    """Wait until the number of documents stops changing (the file is read once, then Logstash idles)."""
    say(f"Waiting for Logstash to read {SOURCES[name]['file']} ...")
    end, last, stable = time.time() + timeout, None, 0
    while time.time() < end:
        now = counts(name)
        if sum(now) > 0 and now == last:
            stable += 1
            if stable >= 2:
                return now
        else:
            stable = 0
        last = now
        time.sleep(5)
    sys.exit(f"Timed out waiting for {name}; check: docker logs logbox-logstash-{name}")


# ---------------------------------------------------------------------------------------------- commands
def cmd_check(args):
    step("Prerequisites")
    ok = True

    def line(good, what, hint=""):
        nonlocal ok
        ok &= bool(good)
        say(("  OK    " if good else "  FAIL  ") + what + ("" if good else f"   -> {hint}"))

    d = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True)
    line(d.returncode == 0, f"Docker is running (engine {d.stdout.strip()})" if d.returncode == 0 else "Docker is running",
         "start Docker; the user must be allowed to run `docker`")
    a = subprocess.run(["ansible-playbook", "--version"], capture_output=True, text=True)
    line(a.returncode == 0, a.stdout.splitlines()[0] if a.returncode == 0 else "ansible-playbook is installed",
         "install ansible-core 2.20 or newer (pipx install ansible-core)")
    c = subprocess.run(["ansible-galaxy", "collection", "list", "community.docker"], capture_output=True, text=True)
    line("community.docker" in c.stdout, "Ansible collection community.docker",
         "cd ansible && ansible-galaxy collection install -r requirements.yml")
    line(os.path.exists(os.path.join(ANSIBLE, "vault-password.txt")) and os.path.exists(os.path.join(ANSIBLE, "group_vars/all/vault.yml")),
         "Secrets exist (ansible/vault-password.txt and group_vars/all/vault.yml)", "ansible/setup-secrets.sh")
    sd = samples_dir(args)
    say(f"  Sample folder: {sd}")
    for name, s in SOURCES.items():
        line(os.path.exists(os.path.join(sd, s["file"])), f"{s['file']}", f"copy the file into {sd} or use --samples DIR")
    info = es("/")
    say("  Elasticsearch: " + (f"running, version {info['version']['number']}" if info else "not running yet (that is fine before `up`)"))
    sys.exit(0 if ok else 1)


def cmd_up(args):
    step("Deploy Elasticsearch and Kibana (no log source yet)")
    run_playbook(args, [], "stack only")
    kibana_banner()


def kibana_banner():
    say(f"\nKibana:  {KIBANA_URL}   (user: elastic; password: cd ansible && ansible-vault view group_vars/all/vault.yml)")


def cmd_ingest(args):
    name = args.source
    step(f"Sample '{name}': deploy a Logstash for {SOURCES[name]['file']}")
    run_playbook(args, [name], f"enabled source: {name}")
    indexed, rejected = wait_until_ingested(name)
    say(f"\nIndexed documents: {indexed}   Rejected records (logs-rejects): {rejected}")
    r = es(f"/logs-{SOURCES[name]['dataset']}/_search", {"size": 0, "query": {"term": {"agent.name": f"logstash-{name}"}},
                                                         "aggs": {"a": {"min": {"field": "@timestamp"}}, "b": {"max": {"field": "@timestamp"}}}})
    if r and r["hits"]["total"]["value"]:
        say(f"@timestamp range (UTC): {r['aggregations']['a']['value_as_string']}  to  {r['aggregations']['b']['value_as_string']}")
    step(f"Functional test for '{name}'")
    t = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "functional_test.py"), "--only", name])
    say("\nRESULT: " + ("PASS" if t.returncode == 0 else "FAIL") + f" ({name})")
    step("Now look at it in Kibana")
    find(name, args.record if hasattr(args, "record") else 5)
    return t.returncode


# --------------------------------------------------------------------------------------------- find
def kql_value(v, is_number):
    if is_number:
        return str(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def rison(s):
    return "'" + s.replace("!", "!!").replace("'", "!'") + "'"


def discover_url(view_id, kql):
    a = (f"(columns:!(),dataSource:(dataViewId:{view_id},type:dataView),filters:!(),interval:auto,"
         f"query:(language:kuery,query:{rison(kql)}),sort:!(!('@timestamp',desc)))")
    g = "(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:now-5y,to:now))"
    return f"{KIBANA_URL}/app/discover#/?_g={urllib.parse.quote(g, safe='()!:,')}&_a={urllib.parse.quote(a, safe='()!:,')}"


def find(name, record):
    ds = SOURCES[name]["dataset"]
    if name == "proxy":
        eid = f"{int(record):07d}"
        body = {"size": 1, "query": {"bool": {"filter": [{"term": {"event.id": eid}}, {"term": {"agent.name": f"logstash-{name}"}}]}}}
    else:
        body = {"size": 1, "query": {"term": {"agent.name": f"logstash-{name}"}}, "sort": [{"@timestamp": "asc"}]}
    r = es(f"/logs-{ds}/_search", body)
    hits = r["hits"]["hits"] if r else []
    if not hits:
        say(f"No indexed event in {ds} (for proxy, --record is event.id, e.g. 5 means 0000005).")
        return
    src = hits[0]["_source"]
    say(f"An event from {SOURCES[name]['file']} as the pipeline stored it:")
    say(f"   @timestamp : {src['@timestamp']}")
    say(f"   raw record : {get(src, 'event.original')}")
    conds, filters = [], []
    for f, num in KEY_FIELDS[name]:
        v = get(src, f)
        if v is not None and len(conds) < 2:
            conds.append(f"{f} : {kql_value(v, num)}")
            filters.append({"term": {f: v}})
    by_value = f'event.dataset : "{ds}"' + "".join(f" and {c}" for c in conds)
    n = es(f"/logs-{ds}/_count", {"query": {"bool": {"filter": [{"term": {"agent.name": f"logstash-{name}"}}] + filters}}})
    say("\nIn Kibana: open Discover, choose the data view  Logbox logs (all sources),  paste a query into the search bar, press Enter.")
    say("(The time window is already the last 5 years; the sample data is dated October 2026.)\n")
    say("  Query by values taken from the record:")
    say(f"       {by_value}")
    say(f"       (matches {n['count'] if n else '?'} event(s) in the {name} index)")
    say("\nOr click this link, which opens Discover with that query filled in:")
    say(f"  {discover_url('logbox-logs-all', by_value)}")
    say("\nClick the arrow beside a result to see every field: ECS names, the original line in event.original,")
    say(f"and anything that is not ECS under {NS}.metadata.*.")


def cmd_find(args):
    find(args.source, args.record)


def cmd_all(args):
    cmd_up(args)
    bad = 0
    for name in SOURCES:
        args.source, args.record = name, 5
        bad += cmd_ingest(args) != 0
    step("Summary")
    say("All three samples passed." if not bad else f"{bad} sample(s) FAILED the functional test.")
    sys.exit(1 if bad else 0)


def cmd_reset(args):
    if not args.yes:
        sys.exit("reset removes ALL ingested data, the containers logbox-*, the volumes logbox-es-data, logbox-ls-*-data and the TLS certificate volumes, "
                 f"the network logbox-net and {BASE_DIR}. Run it again with --yes to do that.")
    step("Reset")
    names = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True).stdout.split()
    boxes = [n for n in names if n.startswith("logbox-") and not n.startswith("logbox-tracer")]
    if boxes:
        subprocess.run(["docker", "rm", "-f", *boxes], check=False)
    vols = subprocess.run(["docker", "volume", "ls", "--format", "{{.Name}}"], capture_output=True, text=True).stdout.split()
    gone = [v for v in vols if v in ("logbox-es-data", "logbox-redis-data", "logbox-certs-ca", "logbox-certs-es", "logbox-certs-ca-public") or re.fullmatch(r"logbox-ls-.+-data", v)]
    if gone:
        subprocess.run(["docker", "volume", "rm", *gone], check=False)
    subprocess.run(["docker", "network", "rm", "logbox-net"], check=False, capture_output=True)
    shutil.rmtree(BASE_DIR, ignore_errors=True)
    say("Removed. Run `demo/demo.py up` for a fresh start.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n, fn, doc in (("check", cmd_check, "check prerequisites"), ("up", cmd_up, "deploy Elasticsearch and Kibana"),
                       ("all", cmd_all, "up, then every sample")):
        p = sub.add_parser(n, help=doc)
        p.add_argument("--samples", help="folder holding the three sample files")
        p.add_argument("--no-tls", action="store_true", help="run over plain http (es_tls=false); TLS is the default")
        p.add_argument("--namespace", help="namespace for non-ECS fields, <namespace>.metadata.* (default org)")
        p.set_defaults(fn=fn)
    p = sub.add_parser("ingest", help="run one sample end to end")
    p.add_argument("source", choices=list(SOURCES))
    p.add_argument("--samples", help="folder holding the three sample files")
    p.add_argument("--record", type=int, default=5, help="for proxy, event.id shown in Kibana (5 means 0000005)")
    p.add_argument("--no-tls", action="store_true", help="run over plain http (es_tls=false); TLS is the default")
    p.add_argument("--namespace", help="namespace for non-ECS fields, <namespace>.metadata.* (default org)")
    p.set_defaults(fn=cmd_ingest)
    p = sub.add_parser("find", help="show an event and the Kibana queries that find it")
    p.add_argument("source", choices=list(SOURCES))
    p.add_argument("--record", type=int, default=5)
    p.set_defaults(fn=cmd_find)
    p = sub.add_parser("reset", help="remove everything the playbook created")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(fn=cmd_reset)
    a = ap.parse_args()
    rc = a.fn(a)
    sys.exit(rc if isinstance(rc, int) else 0)


if __name__ == "__main__":
    main()
