#!/usr/bin/env bash
# Set the token's contract address on the agent, in one go. Run on the box:
#   sudo bash /opt/canary/app/deploy/mint.sh <MINT>
# The site reads it from state.json within a minute. No redeploy.
set -e
MINT=${1:?usage: mint.sh <MINT>}
[[ "$MINT" =~ ^[1-9A-HJ-NP-Za-km-z]{32,44}$ ]] || { echo "that does not look like a mint address"; exit 1; }
CFG=/opt/canary/config.toml
grep -q '^\[links\]' "$CFG" || printf '\n[links]\ntoken_mint = ""\n' >> "$CFG"
if grep -q '^token_mint' "$CFG"; then sed -i "s|^token_mint = .*|token_mint = \"$MINT\"|" "$CFG"; else sed -i "s|^\[links\]|[links]\ntoken_mint = \"$MINT\"|" "$CFG"; fi
systemctl restart canary-agent
sleep 2
grep '^token_mint' "$CFG"
echo "set. the site picks it up on its next refresh."
