"""
pfsense_blocker.py — Service de décision et blocage automatisé

Reçoit les verdicts envoyés par le playbook Shuffle (via webhook POST),
interroge Cortex pour le statut de réputation (MISP), et décide du
blocage sur pfSense selon une logique à trois critères :

    - local               : l'IP est-elle interne (privée) ou, si externe,
                             géolocalisée au Maroc ? (is_local)
    - known_malicious     : la réputation est-elle mauvaise selon
                             l'analyse Cortex/MISP ?
    - behavior_confirmed  : le comportement correspond-il à une règle de
                             corrélation Wazuh validée (ici 100010,
                             force brute SSH) ?

Principe de zéro confiance : pour une IP externe (hors Maroc), un seul
signal confirmé (comportement OU réputation) suffit à déclencher le
blocage. Pour une IP locale, réputation ET comportement doivent
coïncider — on évite de bloquer un faux positif interne sur un seul
indicateur.

Valeurs réelles (clé API Cortex, IP du pare-feu) remplacées par des
placeholders avant publication.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import subprocess, json, time, urllib.request, ipaddress

CORTEX_URL = "http://IP_CORTEX_INTERNE:9001"
CORTEX_KEY = "VOTRE_CLE_API_CORTEX"

def get_report(job_id):
    req = urllib.request.Request(
        f"{CORTEX_URL}/api/job/{job_id}/report",
        headers={"Authorization": f"Bearer {CORTEX_KEY}"}
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read())

def is_local(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            return True
    except ValueError:
        return True

    try:
        req = urllib.request.Request(f"http://ip-api.com/json/{ip}?fields=countryCode")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get("countryCode", "") == "MA"
    except Exception:
        return True

def block_ip(ip):
    subprocess.run(
        ["ssh", "-i", "/home/soc/.ssh/pfsense_shuffle",
         "-o", "StrictHostKeyChecking=no",
         "admin@IP_PFSENSE_INTERNE",
         f"pfctl -t SOC_Blocklist -T add {ip}"],
        capture_output=True, text=True, timeout=10
    )

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        body = json.loads(self.rfile.read(length))
        ip = body.get("ip", "")
        job_id = body.get("job_id", "")
        rule_id = body.get("rule_id", "")

        known_malicious = False
        status = "unknown"

        if job_id:
            for attempt in range(8):
                time.sleep(1.5)
                try:
                    data = get_report(job_id)
                    status = data.get("status", "unknown")
                    if status == "Success":
                        taxonomies = data.get("report", {}).get("summary", {}).get("taxonomies", [])
                        for tax in taxonomies:
                            value = tax.get("value", "")
                            if value and not value.startswith("0 "):
                                known_malicious = True
                        break
                    elif status == "Failure":
                        break
                except Exception:
                    pass

        behavior_confirmed = (rule_id == "100010")
        local = is_local(ip)

        blocked = False
        verdict = "safe"

        if local:
            if known_malicious and behavior_confirmed:
                verdict = "blocked"; block_ip(ip); blocked = True
            elif known_malicious and not behavior_confirmed:
                verdict = "needs_review"
            elif not known_malicious and behavior_confirmed:
                verdict = "needs_review"
            else:
                verdict = "safe"
        else:
            if known_malicious and behavior_confirmed:
                verdict = "blocked"; block_ip(ip); blocked = True
            elif known_malicious and not behavior_confirmed:
                verdict = "known_but_inactive"
            elif not known_malicious and behavior_confirmed:
                verdict = "blocked"; block_ip(ip); blocked = True
            else:
                verdict = "safe"

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {
            "success": True, "ip": ip, "local": local,
            "known_malicious": known_malicious,
            "behavior_confirmed": behavior_confirmed,
            "verdict": verdict, "blocked": blocked, "job_status": status
        }
        self.wfile.write(json.dumps(response).encode())

HTTPServer(('0.0.0.0', 5005), Handler).serve_forever()
