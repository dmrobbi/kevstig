#!/usr/bin/env bash
# kevstig daily refresh: fetch fresh KEV -> rebuild -> redeploy API -> verify.
# Gated: only ever exits 0 after KEVSTIG-REFRESH-OK (a real, verified refresh).
set -euo pipefail

rm -rf /tmp/kevstig-deploy
mkdir -p /tmp/kevstig-deploy
python3 /home/wez/repos/kevstig/kevstig.py \
  --baselines /home/wez/repos/stig-baselines/baselines \
  --out /tmp/kevstig-deploy 2>&1 | tee /tmp/kevstig-build.log
grep -q 'KEVSTIG-OK' /tmp/kevstig-build.log

scp -q /tmp/kevstig-deploy/api/coverage.json /tmp/kevstig-deploy/api/headline.json mail:/tmp/

ssh mail 'sudo cp /tmp/coverage.json /var/www/bedimsecurity.com/capabilities/kevstig/api/coverage.json && sudo cp /tmp/headline.json /var/www/bedimsecurity.com/capabilities/kevstig/api/headline.json && sudo chown www-data:www-data /var/www/bedimsecurity.com/capabilities/kevstig/api/coverage.json /var/www/bedimsecurity.com/capabilities/kevstig/api/headline.json && sudo chmod 640 /var/www/bedimsecurity.com/capabilities/kevstig/api/coverage.json /var/www/bedimsecurity.com/capabilities/kevstig/api/headline.json && sudo rm -f /tmp/coverage.json /tmp/headline.json'

CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://bedimsecurity.com/capabilities/kevstig/api/headline.json)
[ "$CODE" = "200" ] || { echo "headline 404/err: $CODE"; exit 3; }

echo KEVSTIG-REFRESH-OK