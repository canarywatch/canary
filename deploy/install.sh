#!/usr/bin/env bash
# Put the canary agent on an Ubuntu or Debian box. Safe to run twice. Lives next to other services:
# it adds its own Caddy site file and never rewrites a Caddyfile that is already there.
#
#   from a copy of the project on the box:   sudo DOMAIN=api.example.com bash /path/to/canary/deploy/install.sh
#   or from GitHub:   REPO=https://github.com/<owner>/canary.git  curl -fsSL .../deploy/install.sh | sudo bash
#
# Nothing here asks for a key or a token. The agent has no credentials at all.
set -euo pipefail
REPO=${REPO:-}
DOMAIN=${DOMAIN:-}
ROOT=/opt/canary
U=canary
PORT=8792
SRC=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." 2>/dev/null && pwd || true)
IP=$(curl -4 -s --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')
HOST=canary.$(echo "$IP" | tr . -).sslip.io      # its own sslip name, so it can share a box (and a Caddy) with another agent
say(){ printf '\n\033[1m%s\033[0m\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run this with sudo"; exit 1; }

say "1/6  packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || echo "apt-get update reported errors (a repository is down); continuing with the package lists we have"
apt-get install -y -qq python3 python3-venv python3-pip git rsync ufw curl debian-keyring debian-archive-keyring apt-transport-https >/dev/null \
  || echo "apt-get install reported errors; continuing, checking the essentials below"
for b in python3 rsync git curl; do command -v $b >/dev/null || { echo "missing: $b. fix apt and run again"; exit 1; }; done
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq && apt-get install -y -qq caddy >/dev/null
fi

say "2/6  user and directories"
id -u $U >/dev/null 2>&1 || useradd --system --home $ROOT --shell /usr/sbin/nologin $U
mkdir -p $ROOT/data
if [ -n "$SRC" ] && [ -f "$SRC/agent/main.py" ]; then
  mkdir -p $ROOT/app
  rsync -a --delete --exclude .git --exclude __pycache__ --exclude .pytest_cache --exclude _to_delete --exclude data "$SRC/" $ROOT/app/
elif [ -d $ROOT/app/.git ]; then git -C $ROOT/app pull --ff-only
elif [ -n "$REPO" ]; then git clone --depth 1 "$REPO" $ROOT/app
else echo "no source: run this from a copy of the project or set REPO="; exit 1; fi
# the static site zipped for a Netlify drop (index.html at the root), served at /site.zip
if [ -d $ROOT/app/site ]; then
  python3 - <<PY
import shutil; shutil.make_archive("$ROOT/data/site", "zip", "$ROOT/app/site")
PY
  chmod 644 $ROOT/data/site.zip
fi
# the source as a bare git repo over dumb http at /canary.git, for GitHub's importer. never the data dir or the config.
SNAP=$(mktemp -d)
rsync -a --exclude .git --exclude __pycache__ --exclude .pytest_cache --exclude _to_delete --exclude data --exclude config.toml "$ROOT/app/" "$SNAP/"
chown -R root:root "$SNAP"
export GIT_CONFIG_PARAMETERS="'safe.directory=*'"
( cd "$SNAP" && git init -q && git add -A && git -c user.name="canary" -c user.email="canary@users.noreply.github.com" \
  commit -q -m "canary: a wall of malicious packages, caught as they land on npm and PyPI" \
  -m "An agent reads every new release without installing it, trips on evidence, and asks the public record. The site shows the wall." \
  && git branch -M main )
rm -rf "$ROOT/data/canary.git"
git clone -q --bare "$SNAP" "$ROOT/data/canary.git"
( cd "$ROOT/data/canary.git" && git update-server-info )
chmod -R a+rX "$ROOT/data/canary.git"
rm -rf "$SNAP"
unset GIT_CONFIG_PARAMETERS

say "3/6  python environment"
[ -d $ROOT/venv ] || python3 -m venv $ROOT/venv
$ROOT/venv/bin/pip install -q --upgrade pip
$ROOT/venv/bin/pip install -q -r $ROOT/app/requirements.txt

say "4/6  config"
[ -f $ROOT/config.toml ] || cp $ROOT/app/config.example.toml $ROOT/config.toml
sed -i "s|^data_dir = .*|data_dir = \"$ROOT/data\"|; s|^port = .*|port = $PORT|" $ROOT/config.toml
[ -f /etc/canary.env ] || { echo "PYTHONUNBUFFERED=1" > /etc/canary.env; chmod 644 /etc/canary.env; }
chown -R $U:$U $ROOT

say "5/6  services"
cp $ROOT/app/deploy/canary-agent.service /etc/systemd/system/
mkdir -p /etc/caddy/sites
sed "s/__HOST__/$HOST/; s/__DOMAIN__/$DOMAIN/" $ROOT/app/deploy/canary.caddy > /etc/caddy/sites/canary.caddy
if [ ! -f /etc/caddy/Caddyfile ]; then
  printf 'import /etc/caddy/sites/*.caddy\n' > /etc/caddy/Caddyfile
elif ! grep -q 'import /etc/caddy/sites/\*.caddy' /etc/caddy/Caddyfile; then
  printf '\nimport /etc/caddy/sites/*.caddy\n' >> /etc/caddy/Caddyfile
fi
caddy validate --config /etc/caddy/Caddyfile >/dev/null
systemctl daemon-reload
systemctl enable canary-agent >/dev/null
systemctl enable --now caddy >/dev/null || true
systemctl reload caddy || systemctl restart caddy || true
systemctl restart canary-agent

say "6/6  firewall"
ufw allow OpenSSH >/dev/null 2>&1 || true
ufw allow 80,443/tcp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true

sleep 3
cat <<TXT

done. what runs now:
  canary-agent   watching npm + pypi, writing $ROOT/data/*.json, http on 127.0.0.1:$PORT
  caddy          https://$HOST ${DOMAIN:+  and  https://$DOMAIN}

doctor:  sudo -u $U $ROOT/venv/bin/python -m agent -c $ROOT/config.toml doctor
watch:   journalctl -u canary-agent -f
wall:    sudo -u $U $ROOT/venv/bin/python -m agent -c $ROOT/config.toml status
scan:    sudo -u $U $ROOT/venv/bin/python -m agent -c $ROOT/config.toml scan npm some-package
TXT
systemctl --no-pager --lines=5 status canary-agent || true
