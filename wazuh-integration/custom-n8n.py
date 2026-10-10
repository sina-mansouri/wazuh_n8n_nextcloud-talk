#!/usr/bin/env python3
"""
Wazuh custom integration: forwards alerts as JSON to an n8n webhook.

Install to /var/ossec/integrations/custom-n8n.py (owner root:wazuh, mode 750)
and create the wrapper:  cp /var/ossec/integrations/slack /var/ossec/integrations/custom-n8n
"""
import sys, json, requests

# CA / self-signed certificate of the n8n server.
# Set to True to use the system CA store (e.g. with a public certificate).
CA_FILE = "/var/ossec/integrations/n8n-ca.pem"

# Shared secret, must match the "Header Auth" credential of the n8n webhook.
# Generate with: openssl rand -hex 32
TOKEN = "CHANGE-ME"

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
r.raise_for_status()   # surface HTTP errors (401/404 ...) in ossec.log
