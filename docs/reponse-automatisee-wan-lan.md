# Réponse automatisée aux incidents — WAN et LAN micro-segmenté

Ce document détaille la validation de bout en bout de la chaîne de réponse automatisée (Scénario 1, force brute SSH) selon la position de l'attaquant par rapport au pare-feu pfSense.

```
Alerte Wazuh  →  Corrélation MISP  →  Analyse Cortex  →  Blocage IP pfSense  →  Cas TheHive  →  Notification e-mail
 (règle 100010)    (règle 100015)      (verdict réel)     (SOC_Blocklist)                         à l'analyste
```

**MTTR mesuré : 49 secondes**, de l'alerte à la décision de blocage, sans aucune intervention humaine.

## Topologie du laboratoire

| Segment | Réseau | Interface pfSense | Rôle |
|---|---|---|---|
| WAN | 192.168.100.0/24 | WAN | Attaquant externe (Kali en mode pont) |
| LAN | 192.168.56.0/24 | LAN | Victime (Ubuntu) et outils SOC |
| OPT1 | 192.168.20.0/24 | OPT1 (em2) | Attaquant interne isolé (Kali sur `intnet-kali`) |

Le blocage n'a d'effet réel que si le trafic de l'attaquant **traverse** pfSense. Les trois cas de test ci-dessous le démontrent.

## Cas A — Attaquant sur le même segment que la victime

L'IP est bien ajoutée à `SOC_Blocklist`, mais la connexion continue d'aboutir : attaquant et victime communiquent directement, sans passer par le pare-feu. C'est la limite naturelle d'un pare-feu périmétrique face à une menace déjà à l'intérieur — et la motivation des deux cas suivants.

## Cas B — Attaquant en zone WAN

Une Kali est placée sur le réseau WAN avec une route statique forçant le passage par pfSense :

```bash
sudo ip route add 192.168.56.0/24 via <IP WAN pfSense>
```

La même attaque déclenche toute la chaîne ; après le blocage, la connexion échoue :

```
$ ssh -o ConnectTimeout=5 ubuntu@192.168.56.30
ssh: connect to host 192.168.56.30 port 22: Connection timed out
```

## Cas C — Attaquant interne isolé par micro-segmentation

Scénario réaliste en milieu bancaire : poste compromis ou mouvement latéral après une intrusion initiale.

1. **Segmentation** — une troisième interface pfSense (OPT1, `192.168.20.1/24`) isole la Kali (`192.168.20.10`) sur son propre segment. Toute communication vers la victime doit désormais traverser le pare-feu.
2. **Validation du socle réseau** — une règle manuelle de blocage Kali → victime sur OPT1 fait passer le ping de 0 % à 100 % de perte ; elle est ensuite désactivée pour laisser la main à l'automatisation.
3. **Correction d'architecture : règle Floating** — la table `SOC_Blocklist` n'était référencée que par une règle sur l'interface WAN, donc sans effet sur OPT1. Elle a été remplacée par une **règle Floating** appliquée simultanément à WAN, LAN et OPT1 :

   | Champ | Valeur |
   |---|---|
   | Type | Floating, action *Block*, *Quick* activé |
   | Interfaces | WAN, LAN, OPT1 |
   | Source | alias / table `SOC_Blocklist` |
   | Destination | any |

4. **IOC interne dans MISP** — `192.168.20.10` est ajoutée comme attribut `ip-src` d'un événement dédié, puis publiée.
5. **Attaque** — force brute SSH depuis le segment interne :

   ```bash
   for i in 1 2 3 4 5 6; do
     sshpass -p "wrongpass$i" ssh -o StrictHostKeyChecking=no \
       -o ConnectTimeout=3 ubuntu@192.168.56.30 exit
     sleep 1
   done
   ```

6. **Réponse automatique** — règle 100010 déclenchée, enrichissement MISP (100015), workflow Shuffle, analyse Cortex confirmant la correspondance, puis verdict du service de décision :

   ```
   verdict: blocked    mttr_seconds: 49.0
   ```

   L'adresse apparaît dans `pfctl -t SOC_Blocklist -T show` et la Kali ne peut plus joindre la victime (`Connection timed out`).
7. **Traçabilité et notification** — une alerte est créée automatiquement dans TheHive et une notification est envoyée par e-mail à l'analyste.

**Point clé :** la logique de détection et de décision (`scripts/pfsense_blocker.py`, Cortex/MISP) n'a subi **aucune modification**. Seul le point d'application du blocage sur le pare-feu a été adapté : segmentation réseau et automatisation doivent être conçues ensemble.

## Contrôles complémentaires

| Observable | Source | Ajouté à `SOC_Blocklist` | Effet réseau réel |
|---|---|---|---|
| 192.168.56.101 | Même segment que la victime | Oui | Aucun (limite topologique) |
| 192.168.100.93 | Zone WAN, via pfSense | Oui | Effectif (timeout) |
| 192.168.20.10 | Segment interne OPT1, via pfSense | Oui | Effectif (timeout) |
| 203.0.113.99 | Observable inconnu de MISP (RFC 5737) | Non | Sans objet |
| 8.8.8.8 | Flux externe CIRCL (3 événements) | Oui | Effectif si le trafic traverse pfSense |

Le cas 8.8.8.8 met en évidence une limite connue : un blocage piloté uniquement par la Threat Intelligence externe peut produire des faux positifs sur des services d'infrastructure légitimes. Une **liste blanche** (résolveurs DNS publics, plages cloud reconnues) est une amélioration identifiée pour la production.
