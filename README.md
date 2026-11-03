# Log Ingestion In A Box

Three sample logs (syslog, CEF firewall, proxy CSV) are read by **Logstash**, mapped to **ECS 8** with
`@timestamp` in UTC (anything that is not ECS goes under `org.metadata.*`), indexed into **Elasticsearch**, and
viewed in **Kibana**. One **Ansible** playbook deploys everything as Docker containers.

```
sample file --> Logstash (one container per source) --> Elasticsearch --> Kibana
                  parse, map to ECS, redact secrets,        logs-logbox.<source>   data views, Discover
                  reject bad records to logs-rejects        logs-rejects
```

The sample files are not provided but most be copied to `samples/`.

All commands below are run in a WSL/Linux terminal, starting from the repository folder:

```bash
cd ~/proj/LogIngestion
```

### Namespace for non-ECS fields

Anything that is not ECS lives under `<namespace>.metadata.*`. The default namespace is `org`; to use another
name, pass it once to Ansible (`ansible-playbook site.yml -e metadata_namespace=acme`, or `demo.py ... --namespace acme`).
It is the only place to set it: Ansible hands it to Logstash (one rename filter, `logstash/shared/88-namespace.conf`)
and renders it into the index templates. Changing it on an existing stack needs the data indices removed and
the sources re-read, because existing documents keep the old field names.

## What is mapped (and what is not)

The demo build maps a **common ECS core**; the rest stays in the raw record or under `org.metadata.*`. Every
event has `@timestamp` (UTC), `event.original` (the raw line), `event.dataset`, origin fields (host, IP, user where the
format has them) and the collector fields. Details a format carries beyond that are either kept as written under
`org.metadata.<source>.*` (for example the CEF `cs1` rule field, `rt`, the proxy `category` and `notes`) or left in
`message` and `event.original`:

- **Syslog:** header fields (time, host, program, pid) are mapped; the text after the header stays in `message`
  (search it with `message : "..."`). Per-program parsing (sshd, sudo, postfix, ufw, ...) is not part of this build.
- **Firewall:** the CEF header and the extension keys are mapped to ECS (addresses, ports, action, user, ...);
  rule, threat, geo, file hash and the category/type classification stay as written under `org.metadata.firewall`.
- **Proxy:** the 13 columns are mapped; the URL is kept whole in `url.original`.


## 1. One-time setup

You need Docker (running, and your user allowed to run `docker`) and `ansible-core` 2.20 or newer.

```bash
cd ~/proj/LogIngestion/ansible
ansible-galaxy collection install -r requirements.yml   # the community.docker collection
bash setup-secrets.sh                                   # creates vault-password.txt and an encrypted vault.yml
```

`setup-secrets.sh` generates four random passwords (Elasticsearch `elastic`, the Logstash writer, the Kibana
system user, and Redis, which is used only if a source routes to it) and keeps them in an Ansible Vault file. Neither file is committed. It never overwrites existing
files. If you delete them, also delete the Elasticsearch volume (`python3 demo/demo.py reset --yes`), because
Elasticsearch keeps the passwords it was first started with.

Read the Kibana login password when you need it:

```bash
cd ~/proj/LogIngestion/ansible
ansible-vault view group_vars/all/vault.yml     # use vault_es_elastic_password; the user is "elastic"
```

## 2. Where the sample logs go

Put the input files in the samples folder (default `samples/` in the repository):
Then change the file names in two places so they match:

1. **`ansible/group_vars/all/log_sources.yml`** — the `file:` field on each source. This is what the
   playbook copies onto the host and what Logstash actually reads. Set `assumed_year` on syslog (those
   lines have no year; there is deliberately no default).
2. **`demo/demo.py`** — the `SOURCES` map (`"file":` next to syslog, firewall, and proxy). The demo
   script's `check` command looks here, not in the YAML. Skip this if you only run `ansible-playbook`.

- Unstructured syslog → the **syslog** source.
- Firewall CEF-type logs → the **firewall** source.
- Proxy CSV → the **proxy** source.

To keep the files somewhere other than `samples/`, pass the folder when you run the playbook
(`-e samples_src_dir=/path/to/folder`) or the demo script (`--samples /path/to/folder`).

## 3. Run it

### Option A: the demo script (recommended, shows each sample end to end)

```bash
cd ~/proj/LogIngestion
python3 demo/demo.py check                          # tools, secrets and sample files in place?
python3 demo/demo.py up                             # Elasticsearch and Kibana only
python3 demo/demo.py ingest syslog                  # deploy Logstash for one sample, wait, count, run the test
python3 demo/demo.py ingest firewall
python3 demo/demo.py ingest proxy
python3 demo/demo.py find syslog --record 5         # show one event and the exact Kibana queries that find it
python3 demo/demo.py all                            # up + all three samples
python3 demo/demo.py reset --yes                    # remove containers, volumes, network and working folder
```

Add `--samples /path/to/folder` to `check`, `up`, `ingest` and `all` if the files are not in `samples/`.
`ingest` prints the document count, the UTC time range, the functional test result (`RESULT: PASS`) and a
Kibana query for a real event of that sample. A full `all` run takes about 3 minutes.

### Option B: the playbook directly

```bash
cd ~/proj/LogIngestion/ansible
ansible-playbook site.yml                                   # everything, samples from ../samples
ansible-playbook site.yml -e samples_src_dir=/path/to/folder # samples from another folder
ansible-playbook site.yml -e '{"enabled_sources": ["syslog"]}' # only one source
ansible-playbook site.yml -e metadata_namespace=acme        # non-ECS fields under acme.metadata.*
```

A second run changes nothing (`changed=0`). Running again after a restart re-reads the files and overwrites the
same documents (the document id is a fingerprint of the record), so there are never duplicates.

## 4. Open Kibana

Kibana is published on `127.0.0.1:5601` only. From a browser on Windows (with WSL running Docker), open
**http://localhost:5601**. WSL forwards its loopback ports to Windows. Log in as `elastic` with the password from
section 1. Elasticsearch (`https://localhost:9200`, or `http://` without TLS) is an API, not a dashboard; it asks for the same login and
shows JSON.

If `localhost:5601` does not load from Windows: check `localhostForwarding` is not `false` in
`C:\Users\<you>\.wslconfig`, run `wsl --shutdown`, and start again. As a last resort set `kibana_bind: "0.0.0.0"`
in `ansible/group_vars/all/main.yml`, which makes Kibana reachable from the network.

## 5. Find a log entry in Kibana

1. Menu (top left) > **Analytics** > **Discover** (or `http://localhost:5601/app/discover`).
2. Top left, the data view should be **Logbox logs (all sources)**. The time window defaults to the last 5 years;
   the samples are dated October 2026. If you see "Last 15 minutes", open the calendar icon at the top right
   and choose a longer range.
3. Click the search bar, type a query (KQL), press **Enter**.
4. Click the arrow at the left of a row to see all fields. The original line is in `event.original`.

Queries (replace the angle-bracket parts with values from the log line you are looking for):

| Goal | Query |
|---|---|
| All events of one sample | `event.dataset : "logbox.syslog"` (or `logbox.firewall`, `logbox.proxy`) |
| One syslog or firewall line | `message : "Failed password"` (a unique snippet of the parsed message) |
| A user | `user.name : "<user>"` |
| A source IP (firewall) / client IP (proxy) | `source.ip : "<ip>"` / `client.ip : "<ip>"` |
| Words in a syslog or firewall message (the way to find syslog events by content) | `message : "Failed password"` |
| A firewall action | `event.dataset : "logbox.firewall" and event.action : "deny"` |
| Proxy errors | `event.dataset : "logbox.proxy" and http.response.status_code >= 500` |
| One proxy event by its id | `event.id : "<id>"` |
| Proxy rows whose notes spanned several lines | `event.dataset : "logbox.proxy" and tags : "multiline"` |
| Records that failed to parse | switch the data view to **Logbox rejects** |

Notes:

- `event.original` is stored but not indexed, so you cannot search the raw line itself. Search a parsed field
  or `message`. For a proxy row use `event.id`.
- Typing a field name in the search bar offers autocomplete for fields and values.
- `python3 demo/demo.py find <source>` prints the query for a real record of your files, plus a link that
  opens Discover with the query filled in.

Command-line check without Kibana:

```bash
cd ~/proj/LogIngestion/ansible
curl --cacert ~/logbox/certs/ca.crt \
  -u "elastic:$(ansible-vault view group_vars/all/vault.yml | awk -F': *' '/es_elastic/{print $2}' | tr -d '"')" \
  'https://localhost:9200/logs-logbox.*/_count?pretty'
```

With TLS switched off (below) use `http://` and drop `--cacert`.

### TLS: on by default, one switch to turn it off

Elasticsearch speaks **HTTPS** by default, with a certificate from a private CA the playbook creates (a one-off container
using `openssl` from the Elasticsearch image; nothing to install). Logstash, Kibana and the playbook trust that CA.
The CA certificate you need for `curl` is `~/logbox/certs/ca.crt`. The demo script and the test find it themselves.
If TLS gets in the way during a demo, run everything over plain http (authentication stays on):

```bash
ansible-playbook site.yml -e es_tls=false      # or:  python3 demo/demo.py ingest proxy --no-tls
ansible-playbook site.yml                      # back to TLS (the default)
```

Switching recreates the Elasticsearch, Kibana and Logstash containers; the data stays. Kibana's own page stays on
`http://localhost:5601` in both modes (loopback only). A browser opening `https://localhost:9200` shows a certificate
warning because the CA is private; that is expected. No TLS to Redis yet.

### Send a source to Redis instead of Elasticsearch (optional)

Every source goes to Elasticsearch unless you say otherwise. The same parsed events can go to Redis instead
(one destination per source, not both). Nothing else in the configuration changes.

```bash
cd ~/proj/LogIngestion/ansible
# all enabled sources to Redis for this run (here only the proxy)
ansible-playbook site.yml -e default_destination=redis -e '{"enabled_sources":["proxy"]}'
# or permanently for one source: add  destination: redis  to its entry in group_vars/all/log_sources.yml
```

The playbook then also starts a Redis container (`logbox-redis`, password from the vault, not published on a host port).
Look at the result:

```bash
RP=$(ansible-vault view group_vars/all/vault.yml | awk -F': *' '/vault_redis_password/{gsub(/"/,"",$2);print $2}')
docker exec -e REDISCLI_AUTH=$RP logbox-redis redis-cli llen logs-logbox.proxy     # 225 for the proxy sample
docker exec -e REDISCLI_AUTH=$RP logbox-redis redis-cli lindex logs-logbox.proxy 0 # first record as JSON
```

The defaults need nothing else: Logstash sends to the Redis container the playbook starts, on port 6379. To change
the port of that container add `-e redis_port=6390`. To send to a Redis that already exists (another host or
container) and not start one, give its address; the password is still `vault_redis_password` (TLS to Redis is out of scope: the Redis route only shows that Logstash can route elsewhere):

```bash
ansible-playbook site.yml -e default_destination=redis -e redis_external=true -e redis_host=my-redis.example.edu -e redis_port=6379
```

Keys are `logs-<dataset>` (for example `logs-logbox.proxy`) and `logs-rejects`. Redis has no field types and no document
id, so re-reading a file (a restart) appends the records again; Elasticsearch overwrites them. An old vault file made
before this feature needs `vault_redis_password` added (`ansible-vault edit group_vars/all/vault.yml`).
To go back, run the playbook again without `default_destination`.

## 6. Tests

The suite needs Elasticsearch up. If a Logstash instance (or the rest of the stack) is already running, reset
first so this clone's vault and containers match, then start Elasticsearch and Kibana, then run the test:

```bash
cd ~/proj/LogIngestion
python3 demo/demo.py reset --yes
python3 demo/demo.py up
python3 tests/functional_test.py
```

With no flags, the script runs the whole suite (about 3 minutes). It checks record counts against an independent
count of the files, UTC timestamps, ECS names only, multi-line proxy notes, redaction, deliberately broken records
landing in `logs-rejects`, the dead letter queue, security basics, Kibana data views, a second playbook run reporting
no changes, and re-ingest. The private samples in `samples/` are required for the real-source counts.

`--only proxy` (or `syslog` or `firewall`) stops after the real-sample checks for that one source: document count,
rejects, timestamps, origin fields, empty DLQ. It does not run mapping, security, Kibana, idempotence, re-ingest, or
the synthetic fixtures. That is the same slice `python3 demo/demo.py ingest proxy` prints after ingest.

`--skip-fixtures` runs everything except the synthetic files in `tests/fixtures/` (`fn_syslog.log`, `fn_cef.log`,
`fn_dlq.log`, `fn_proxy.csv`). Those committed files (no real data) are deployed as extra Logstash sources to prove
redaction, a bad record per source, occurrence numbers, multi-line proxy notes, and a record Elasticsearch refuses
(DLQ). Skipping them avoids extra containers and is enough when you only care that the three real sources look right.

```bash
python3 tests/functional_test.py --only proxy
python3 tests/functional_test.py --skip-fixtures
```

### If a record is refused by Elasticsearch (dead letter queue)

Logstash sends a record that does not parse to the `Logbox rejects` view. A record that parses but that Elasticsearch
refuses (for example `src=999.999.1.1` in a field typed `ip`) goes to the **dead letter queue (DLQ)** instead. It is
not in Kibana: it is a set of files in the Docker volume `logbox-ls-<source>-data` on the host. For real input it is expected to be empty.

```bash
cd ~/proj/LogIngestion
demo/dlq-inspect.sh firewall --size   # bytes of refused events; 0 = empty
demo/dlq-inspect.sh firewall          # print every refused event with Elasticsearch's reason (read only, about 15 s)
```

For each entry: read the `reason`, decide whether the source value is bad (nothing to fix; keep the raw line as the
finding) or our mapping is wrong (fix it, redeploy), re-run the source (`python3 demo/demo.py ingest <source>`; ids make this
safe), then clear the DLQ: `docker rm -f logbox-logstash-<source> && docker volume rm logbox-ls-<source>-data` and run the playbook
again. Details in `_bmad-output/initiative-log-ingestion-in-a-box/error-handling.md`.

## 7. Tool choices (short version)

| Choice | Why |
|---|---|
| Logstash | built-in filters (csv, grok, date, dissect, fingerprint) cover all three formats; the pipeline is declarative text that is easy to review; one container per source scales out |
| Elasticsearch + ECS 8.x | one documented field vocabulary across sources; index templates keep field types fixed |
| Kibana | the viewer for the result; data views are created by the playbook |
| Ansible (one playbook) | one command deploys a stack on any host with Docker; idempotent, secrets from Ansible Vault |
| Docker | same containers on a laptop or a server; versions pinned to one exact tag (8.19.22) |
| Python standard library for tests and demo | nothing extra to install |



## 8. Repository layout

```
ansible/       site.yml, roles (stack_base, elasticsearch, kibana, logstash_instance), group_vars, setup-secrets.sh
logstash/      shared/ (steps every source uses) and sources/<name>/ (input and mapping per source)
elasticsearch/ index templates
demo/          demo.py
tests/         functional_test.py, fixtures, ECS 8.17 field list
tracer/        development harness used while building each source (not needed to run the demo)
samples/       your private log files (not in Git)
```

## Known limits

- Redis is an either/or alternative to Elasticsearch per source; it is not part of the functional test and re-reads append duplicates.
- The dead letter queue is per Logstash instance (not in Kibana); at its 64 MB cap new refused events are dropped.
- TLS covers Elasticsearch's HTTP port (default on); the Kibana page and Redis are not encrypted, there is no mutual TLS,
  and the private CA key sits in a Docker volume on the target host (no rotation automation).
- The Kibana login uses the `elastic` superuser; a read-only viewer role is a hardening item.
- Elasticsearch needs about 3 GB of memory in total for the stack (Elasticsearch, Kibana, three Logstash containers).
