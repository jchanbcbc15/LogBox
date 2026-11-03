#!/usr/bin/env bash
# One-time setup of the secrets for a fresh clone: a vault password file and an encrypted
# group_vars/all/vault.yml holding four random passwords (the Redis one is used only if a source routes to Redis). Neither file is committed (.gitignore).
# It never overwrites an existing file: Elasticsearch keeps the passwords it was first started with.
set -euo pipefail
cd "$(dirname "$0")"

PW_FILE=vault-password.txt
VAULT=group_vars/all/vault.yml

command -v ansible-vault >/dev/null || { echo "ansible-vault not found: install ansible-core 2.20 or newer first." >&2; exit 1; }
rand() { python3 -c 'import secrets; print(secrets.token_urlsafe(24))'; }

umask 077
if [ -e "$PW_FILE" ]; then
  echo "Keeping the existing $PW_FILE"
else
  rand > "$PW_FILE"
  echo "Created $PW_FILE (the key to the vault; keep it out of Git)"
fi

if [ -e "$VAULT" ]; then
  echo "Keeping the existing $VAULT"
else
  cat > "$VAULT" <<YAML
vault_es_elastic_password: "$(rand)"
vault_logstash_writer_password: "$(rand)"
vault_kibana_system_password: "$(rand)"
vault_redis_password: "$(rand)"
YAML
  ansible-vault encrypt --vault-password-file "$PW_FILE" --encrypt-vault-id default "$VAULT" >/dev/null
  echo "Created $VAULT (encrypted, four random passwords)"
fi
echo "To read the Kibana login (user 'elastic'):  cd ansible && ansible-vault view group_vars/all/vault.yml"
