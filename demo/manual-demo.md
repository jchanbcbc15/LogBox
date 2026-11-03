# Manual demo: ingest the proxy CSV with Ansible, then find a record in Kibana

This runs the demo by hand, without `demo/demo.py`. The example is the proxy CSV (`04_proxy_export.csv`).
The same steps work for the other two samples: use `syslog` or `firewall` where it says `proxy`, and the
file names `01_syslog_unstructured.log` and `03_firewall_cef.log`.

All commands are typed in a WSL terminal. Kibana is opened in a browser on Windows.

## 0. One-time setup (skip if already done)

```bash
cd ~/proj/LogIngestion/ansible
ansible-galaxy collection install -r requirements.yml
./setup-secrets.sh
```

Docker must be running. `setup-secrets.sh` creates the passwords (it never overwrites existing ones).

## 1. Put the sample file where the playbook looks for it

The playbook looks for the file in `~/proj/LogIngestion/samples/` and copies it to the target host. The file
name must be exactly `04_proxy_export.csv`.

```bash
ls -l ~/proj/LogIngestion/samples/04_proxy_export.csv
```

To use a file in another folder, keep the name and add `-e samples_src_dir=/path/to/folder` to the command in
step 2.

## 2. Run the playbook for the CSV only

```bash
cd ~/proj/LogIngestion/ansible
ansible-playbook site.yml -e '{"enabled_sources": ["proxy"]}'
```

With a different sample folder:

```bash
ansible-playbook site.yml -e '{"enabled_sources": ["proxy"]}' -e samples_src_dir=/path/to/folder
```

What this one command does: creates the Docker network and folders, starts Elasticsearch, installs the index
templates and users, starts Kibana and creates its data views, then starts one Logstash container
(`logbox-logstash-proxy`) that reads the CSV once. The first run takes about a minute (it also downloads the
images the first time). At the end the summary line must show `failed=0`:

```
demo-host : ok=33 changed=7 unreachable=0 failed=0 ...
```

Run it a second time and it reports `changed=0`: nothing is duplicated.

## 3. Check that the records arrived

Logstash needs about 30 to 60 seconds after the playbook ends to read the file. Get the Elasticsearch password
into a variable once, then count:

```bash
cd ~/proj/LogIngestion/ansible
ES_PW=$(ansible-vault view group_vars/all/vault.yml | awk -F': *' '/es_elastic/{print $2}' | tr -d '"')
curl -s --cacert ~/logbox/certs/ca.crt -u "elastic:$ES_PW" 'https://localhost:9200/_cat/indices/logs-*?v&h=index,docs.count'
# (If you deployed with -e es_tls=false use:  curl -s -u "elastic:$ES_PW" 'http://localhost:9200/...' )
```

Expected: `logs-logbox.proxy` with 225 documents. Run it again after a few seconds if the number is still growing.
Rejected records (bad rows) are counted in `logs-rejects`; for the sample file there are none.

If the index does not appear after two minutes: `docker logs --tail 30 logbox-logstash-proxy`.

## 4. Pick a record to look for

Look at the first rows of the file and choose one. The second column is the event id, which is unique per row:

```bash
head -6 ~/proj/LogIngestion/samples/04_proxy_export.csv
```

Columns, in order, and where each lands in Kibana:

| CSV column | Field in Kibana |
|---|---|
| 1 time (UTC) | `@timestamp` |
| 2 event_id | `event.id` |
| 3 client_ip | `client.ip` |
| 4 username | `user.name` |
| 5 display_name | `user.full_name` |
| 6 method | `http.request.method` |
| 7 url | `url.original` (the URL as logged; its parts are not split out in this build) |
| 8 status_code | `http.response.status_code` |
| 9 bytes_sent | `org.metadata.proxy.bytes_sent` |
| 10 user_agent | `user_agent.original` |
| 11 referrer | `http.request.referrer` |
| 12 category | `org.metadata.proxy.category` |
| 13 notes | `org.metadata.proxy.notes` (can span several lines) |

Write down the event id (for example the value in column 2 of the first data row) and the username.

## 5. Open Kibana and search

1. In a browser on Windows open **http://localhost:5601**.
2. Log in: user `elastic`, password from
   `cd ~/proj/LogIngestion/ansible && ansible-vault view group_vars/all/vault.yml` (the line
   `vault_es_elastic_password`). Do not show this on screen in a presentation.
3. Open the menu (top left) > **Analytics** > **Discover**.
4. Top left, the data view must be **Logbox logs (all sources)** (or **Logbox proxy**).
5. Time range (top right): the default is the last 5 years, which covers the sample (dated October 2026). If it
   says "Last 15 minutes", change it with the calendar icon.
6. Click the search bar, type a query and press **Enter**. Replace the angle-bracket part with your value,
   keeping the double quotes:

   | To find | Query |
   |---|---|
   | The row with that event id | `event.id : "<event id>"` |
   | All rows of that user | `event.dataset : "logbox.proxy" and user.name : "<username>"` |
   | The row with that event id | `event.dataset : "logbox.proxy" and event.id : "0000005"` |
   | Server errors | `event.dataset : "logbox.proxy" and http.response.status_code >= 500` |
   | Rows whose notes had several lines | `event.dataset : "logbox.proxy" and tags : "multiline"` |
   | Every proxy row | `event.dataset : "logbox.proxy"` |

7. Click the small arrow at the left of the row to expand it. Check:
   - `event.original` is the original CSV row as read from the file;
   - the ECS fields in the table above;
   - `@timestamp` ends with `Z` (UTC);
   - `event.id` is the CSV event_id column;
   - anything that is not ECS is under `org.metadata.*`.

If nothing is found: widen the time range, check the spelling and the quotes in the query, and confirm the
count in step 3. Bad rows are not in the data view above; switch the data view to **Logbox rejects** to see them
with the reason.

## 6. Run it again, or start over

Read the file again (same documents are overwritten, the count stays the same):

```bash
docker restart logbox-logstash-proxy
```

Remove everything (containers, data, network, working folder) for a fresh start:

```bash
cd ~/proj/LogIngestion
demo/demo.py reset --yes
```

After a reset, repeat from step 2. To add the other samples later, run step 2 again with
`'{"enabled_sources": ["syslog"]}'` or `'{"enabled_sources": ["firewall"]}'`. The containers that already
exist are left alone.

## Optional: show the redaction in Kibana

The real samples contain no credentials, so nothing in them is redacted. To have something to show, deploy two
synthetic syslog lines (one password, one session token) as an extra instance:

```bash
cd ansible && ansible-playbook site.yml -e @../demo/redaction-demo.yml
```

In Discover, data view **Logbox logs (all sources)**: `agent.name : "logstash-redaction-demo"`. `message` shows
`password=[REDACTED]` and `token=[REDACTED]`; `event.original` keeps the unredacted line (a known, documented limit).
Search with `message : *REDACTED*`.

Remove it before running the functional test (it counts the real documents): delete the two documents
(`POST logs-logbox.syslog/_delete_by_query` on `agent.name: logstash-redaction-demo`) and run
`docker rm -f logbox-logstash-redaction-demo && docker volume rm logbox-ls-redaction-demo-data`, then the normal playbook.
The functional test's fixtures already prove the redaction; this is only for the demo.
