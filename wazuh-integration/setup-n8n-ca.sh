#!/bin/bash
# =====================================================================
# Wazuh -> n8n: Selbstsigniertes n8n-Zertifikat im Integrationsskript
# hinterlegen, Skript aktualisieren und Verbindung testen.
#
# Ausfuehren auf dem Docker-Host:   sudo N8N_HOST=n8n.example.com bash setup-n8n-ca.sh
# =====================================================================
set -euo pipefail

# ----- Einstellungen -----
C="${WAZUH_CONTAINER:-single-node-wazuh.manager-1}"   # Name des Wazuh-Manager-Containers
HOST="${N8N_HOST:?Bitte N8N_HOST setzen, z.B. N8N_HOST=n8n.example.com}"   # n8n-Hostname
HOOK="https://${HOST}/webhook/wazuh-alerts"      # Production-Webhook
INT="/var/ossec/integrations"                    # Pfad im Container
WORKDIR="$(cd "$(dirname "$0")" && pwd)"         # Arbeitsordner auf dem Host

ok()   { echo -e "\e[32m[OK]\e[0m   $*"; }
warn() { echo -e "\e[33m[WARN]\e[0m $*"; }
err()  { echo -e "\e[31m[FEHLER]\e[0m $*"; exit 1; }

cd "$WORKDIR"
docker ps --format '{{.Names}}' | grep -qx "$C" || err "Container $C laeuft nicht."

# ----- 1. Zertifikat holen -----
echo "== 1. Zertifikat von ${HOST} abrufen"
openssl s_client -connect "${HOST}:443" -servername "$HOST" </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > n8n-ca.pem || true
[ -s n8n-ca.pem ] || err "Kein Zertifikat erhalten. Ist ${HOST}:443 vom Host erreichbar?"
ok "Zertifikat gespeichert: ${WORKDIR}/n8n-ca.pem"

SUBJECT=$(openssl x509 -in n8n-ca.pem -noout -subject | sed 's/^subject= *//')
ISSUER=$(openssl x509 -in n8n-ca.pem -noout -issuer  | sed 's/^issuer= *//')
ENDDATE=$(openssl x509 -in n8n-ca.pem -noout -enddate | sed 's/^notAfter=//')
echo "   Subject : $SUBJECT"
echo "   Issuer  : $ISSUER"
echo "   Gueltig bis: $ENDDATE"

# Selbstsigniert? (Subject == Issuer)
if [ "$SUBJECT" != "$ISSUER" ]; then
  warn "Zertifikat ist NICHT selbstsigniert, sondern von einer CA ausgestellt."
  warn "Bitte das CA-Zertifikat als ${WORKDIR}/n8n-ca.pem ablegen und Skript erneut starten."
  err  "Abbruch."
fi
ok "Zertifikat ist selbstsigniert."

# Passt der Hostname zum Zertifikat?
if openssl x509 -in n8n-ca.pem -noout -checkhost "$HOST" 2>/dev/null | grep -q "does match"; then
  ok "Hostname ${HOST} passt zum Zertifikat."
else
  err "Hostname ${HOST} steht nicht im Zertifikat (SAN). Zertifikat muss neu ausgestellt werden."
fi

# ----- 2. Token ermitteln -----
echo "== 2. X-Wazuh-Token ermitteln"
TOKEN=$(docker exec "$C" sed -n 's/.*"X-Wazuh-Token": *"\([^"]*\)".*/\1/p' "$INT/custom-n8n.py" 2>/dev/null | head -1 || true)
TOKEN=$(docker exec "$C" sed -n 's/^TOKEN *= *"\([^"]*\)".*/\1/p' "$INT/custom-n8n.py" 2>/dev/null | head -1 || echo "$TOKEN")
if [ -z "$TOKEN" ] || [ "$TOKEN" = "DEIN-X-WAZUH-TOKEN" ]; then
  read -rsp "   Token eingeben (Eingabe unsichtbar): " TOKEN; echo
fi
TOKEN=$(printf '%s' "$TOKEN" | LC_ALL=C tr -cd '[:alnum:]_-')
[ -n "$TOKEN" ] || err "Kein gueltiger Token."
ok "Token: ${TOKEN:0:6}...${TOKEN: -4}"

# ----- 3. Neues Integrationsskript erzeugen -----
echo "== 3. custom-n8n.py erzeugen"
cat > custom-n8n.py << 'PYEOF'
#!/usr/bin/env python3
import sys, json, requests

# Zertifikat des n8n-Servers (selbstsigniert)
CA_FILE = "/var/ossec/integrations/n8n-ca.pem"
TOKEN = "__TOKEN__"

alert_file = sys.argv[1]
hook_url   = sys.argv[3]

with open(alert_file) as f:
    alert = json.load(f)

r = requests.post(
    hook_url,
    json=alert,
    headers={"X-Wazuh-Token": TOKEN},
    timeout=10,
    verify=CA_FILE,
)
r.raise_for_status()   # HTTP-Fehler (z.B. 401/404) im Log anzeigen
PYEOF
sed -i "s|__TOKEN__|${TOKEN}|" custom-n8n.py
ok "Skript erzeugt."

# ----- 4. In den Container kopieren -----
echo "== 4. Dateien in den Container kopieren"
docker cp custom-n8n.py "$C:$INT/custom-n8n.py"
docker cp n8n-ca.pem    "$C:$INT/n8n-ca.pem"
docker exec "$C" bash -c "cd $INT && [ -f custom-n8n ] || cp slack custom-n8n; \
  chown root:wazuh custom-n8n custom-n8n.py n8n-ca.pem && \
  chmod 750 custom-n8n custom-n8n.py && chmod 640 n8n-ca.pem"
docker exec "$C" ls -l "$INT" | grep -E 'custom-n8n|n8n-ca'
ok "Dateien und Rechte gesetzt."

# ----- 5. Syntax pruefen -----
echo "== 5. Python-Syntax pruefen"
docker exec "$C" /var/ossec/framework/python/bin/python3 -m py_compile "$INT/custom-n8n.py" \
  && ok "Python-Syntax OK." || err "Syntaxfehler in custom-n8n.py"

# ----- 6. Verbindung testen (wie Wazuh selbst, mit Token und Zertifikat) -----
echo "== 6. Verbindung zu n8n testen"
CODE=$(docker exec "$C" /var/ossec/framework/python/bin/python3 -c "
import requests
try:
    r = requests.post('$HOOK', json={}, headers={'X-Wazuh-Token': '$TOKEN'},
                      verify='$INT/n8n-ca.pem', timeout=10)
    print(r.status_code)
except requests.exceptions.SSLError as e:
    print('SSL')
except Exception as e:
    print('NET')
")
case "$CODE" in
  200)      ok  "HTTP 200: Verbindung, Zertifikat und Token funktionieren. Fertig!" ;;
  401|403)  warn "HTTP $CODE: SSL ok, aber Token stimmt nicht mit dem n8n-Credential ueberein." ;;
  404)      warn "HTTP 404: SSL ok, aber Workflow in n8n ist nicht aktiv (oder falscher Pfad)." ;;
  SSL)      err  "SSL-Fehler trotz Zertifikat. Bitte Zertifikat und Hostname pruefen." ;;
  NET)      err  "Netzwerkfehler: n8n vom Container aus nicht erreichbar (DNS/Firewall)." ;;
  *)        warn "Unerwartete Antwort: $CODE" ;;
esac

echo
echo "Letzte Eintraege von wazuh-integratord:"
docker exec "$C" grep -i integratord /var/ossec/logs/ossec.log | tail -3
