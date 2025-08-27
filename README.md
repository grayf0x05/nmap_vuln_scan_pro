.::Nmap Vulnerability Scanner Pro::.
------------------------------------
  - Copyright ©️ 2025  
  - Written by: grayf0x        

***  

## 🎥 Video Tutorial
[![Guarda il tutorial su YouTube](https://img.youtube.com/vi/aAVvBN4LmPU/0.jpg)](https://www.youtube.com/watch?v=aAVvBN4LmPU)

# Nmap Vuln Scan Pro

Uno strumento avanzato in **Python 3** che integra **Nmap** con i database di vulnerabilità più diffusi (*vulscan* e *vulners*), automatizzando la scansione e la generazione di report interattivi.  
Pensato per sistemisti, pentester e ricercatori di sicurezza che vogliono identificare vulnerabilità in modo rapido e strutturato.

⚠️ **Disclaimer**: questo tool è destinato esclusivamente ad attività lecite di auditing e penetration test su sistemi di cui si possiede l’autorizzazione.  
L’autore non si assume alcuna responsabilità per usi impropri.

---

## ✨ Funzionalità principali
- Esecuzione automatizzata di **Nmap con script NSE** per vulnerabilità.
- Integrazione con i database:
  - `vulscan`
  - `vulners`
- Parsing dei risultati con output in **HTML interattivo**, **JSON**, **CSV** e **XML Nmap**.
- Report con timestamp e UUID univoci.
- Report HTML con grafici interattivi (Chart.js) e funzioni di filtro/ordinamento CVE.
- Log dettagliati delle scansioni ed eventuali aggiornamenti (`logs/`).
- Aggiornamento automatico dei database NSE (`vulscan`, `vulners`, `--script-updatedb`).
- Gestione **profili di scansione** (Rapida, Standard, Approfondita, Completa).
- Supporto parametri da linea di comando con opzioni avanzate.
- **Richiede esecuzione come root**: non è più previsto fallback automatico.

---

## 📦 Requisiti
- **Python 3.8+**
- **Nmap** installato e raggiungibile da `$PATH`
- Strumenti base (`git`, `curl`, `wget`)
- **Accesso root obbligatorio** (alcune funzionalità non si avviano senza privilegi)
- Nessuna dipendenza Python esterna: usa solo librerie standard
- Database `vulscan` e `vulners` vengono scaricati/aggiornati automaticamente nella cartella scripts di Nmap:
  ```
  /usr/share/nmap/scripts/vulscan/
  /usr/share/nmap/scripts/vulners/
  ```

---

## ⚙️ Installazione
Clona la repository:
```bash
git clone https://github.com/tuo-utente/nmap-vuln-scan-pro.git
cd nmap-vuln-scan-pro
```

Rendi eseguibile lo script:
```bash
chmod +x nmap_vuln_scan_pro-1.5.py
```

---

## 🚀 Utilizzo

### Esempio base
```bash
sudo ./nmap_vuln_scan_pro-1.5.py 192.168.1.100
```

### Scansione di un’intera subnet
```bash
sudo ./nmap_vuln_scan_pro-1.5.py 192.168.1.0/24
```

### Report HTML e apertura automatica
```bash
sudo ./nmap_vuln_scan_pro-1.5.py scanme.nmap.org --open-html
```

### Dry-run (mostra solo il comando Nmap che verrebbe eseguito)
```bash
sudo ./nmap_vuln_scan_pro-1.5.py scanme.nmap.org --dry-run
```

---

## 📊 Profili di scansione

Lo script offre **4 profili preconfigurati** che bilanciano velocità e profondità di analisi:  

| Profilo | Nome           | Descrizione |
|---------|----------------|-------------|
| **1**   | Rapida         | Scansione veloce con `--top-ports 100`, utile per un check immediato. |
| **2**   | Standard       | Scansiona le prime 1000 porte, include script comuni (es. `ssl-cert`, `smb-vuln*`, `ftp-anon`). |
| **3**   | Approfondita   | Scansione SYN (`-sS`) delle prime 1024 porte, con script `default`, `safe`, `ssl-cert`, `ssl-enum-ciphers`. Timeout e retry limitati. |
| **4**   | Completa       | Scansione SYN (`-sS`) fino alla porta 2048, con script `default`, `safe`, `auth`, `discovery`, `ssl`. Timeout e retry limitati. |

🔹 Tutti i profili richiedono privilegi **root** per l’esecuzione corretta.  

---

## 🔧 Parametri disponibili (v1.5)
```
usage: nmap_vuln_scan_pro-1.5.py [-h] [target] [-p {1,2,3,4}]
                                 [-a ALIAS] [-o OUTDIR] [--no-update]
                                 [--no-vm-safe] [--ports PORTS]
                                 [--scripts-extra SCRIPTS_EXTRA]
                                 [--rate RATE] [--open-html]
                                 [--verbose-updates] [--updates-log UPDATES_LOG]
                                 [--dry-run] [--no-json] [--no-csv] [--no-html]

Positional:
  target                  IP/IPv6 o hostname da scansionare

Opzioni:
  -h, --help              mostra questo messaggio ed esce
  -p, --profile           profilo di scansione:
                          1=Rapida, 2=Standard, 3=Approfondita, 4=Completa
  -a, --alias             alias del target (es. server01)
  -o, --outdir            directory di output report
  --no-update             non aggiorna/installa script NSE
  --no-vm-safe            disabilita limitazioni (--max-rate)
  --ports                 override porte (es. 1-1024,80,443)
  --scripts-extra         script NSE extra (virgola-separati)
  --rate                  override --max-rate (pkt/s)
  --open-html             apre il report HTML a fine scansione
  --verbose-updates       mostra output completo aggiornamenti
  --updates-log           file log aggiornamenti
  --dry-run               stampa il comando Nmap senza eseguirlo
  --no-json               non genera output JSON
  --no-csv                non genera output CSV
  --no-html               non genera output HTML
```

---

## 📑 Esempio di output
Esecuzione:
```bash
sudo ./nmap_vuln_scan_pro-1.5.py scanme.nmap.org --open-html
```

Estratto dal report JSON:
```json
{
    "scanme.nmap.org": {
        "hostname": "scanme.nmap.org",
        "ports": ["22/tcp","80/tcp"],
        "services": {
            "22/tcp": {"name":"ssh","product":"OpenSSH","version":"7.9p1"},
            "80/tcp": {"name":"http","product":"Apache httpd","version":"2.4.38"}
        },
        "cves": [
            {
                "id": "CVE-2023-12345",
                "description": "CVSS 7.5",
                "severity": "High",
                "port": "80/tcp"
            }
        ]
    }
}
```

---

## 🤝 Contributi
Le **pull request** sono benvenute.  
Per grandi cambiamenti, apri prima una issue per discutere cosa vorresti modificare.  
