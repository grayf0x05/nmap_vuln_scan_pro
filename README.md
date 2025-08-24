.::Nmap Vulnerability Scanner Pro::.
------------------------------------
  - Copyright ©️ 2025
  - Written by: grayf0x        

***  

## 🎥 Video Tutorial
[![Guarda il tutorial su YouTube](https://img.youtube.com/vi/qbUjt6nPReo/0.jpg)](https://www.youtube.com/watch?v=qbUjt6nPReo)

# Nmap Vuln Scan Pro

Uno strumento avanzato in **Python 3** che integra **Nmap** con i database di vulnerabilità più diffusi (come *vulscan* e *vulners*), automatizzando la scansione e la generazione di report.  
Pensato per sistemisti, pentester e ricercatori di sicurezza che vogliono identificare vulnerabilità in modo rapido e strutturato.

⚠️ **Disclaimer**: questo tool è destinato esclusivamente ad attività lecite di auditing e penetration test su sistemi di cui si possiede l’autorizzazione. L’autore non si assume alcuna responsabilità per usi impropri.

---

## ✨ Funzionalità principali
- Esecuzione automatizzata di **Nmap con script NSE** per vulnerabilità.
- Integrazione con i database:
  - `vulscan`
  - `vulners`
- Parsing dei risultati in **XML, HTML, JSON, CSV**.
- Report con timestamp e UUID univoci.
- Gestione output su file (log strutturati).
- Supporto a **parametri da linea di comando** (da v1.3).
- Controllo privilegi e dipendenze richieste.

---

## 📦 Requisiti
- **Python 3.8+**
- **Nmap** installato e raggiungibile da `$PATH`
- Moduli Python standard (nessuna dipendenza esterna non inclusa)
- Accesso root (necessario per alcune tipologie di scansione)
- Database `vulscan` e `vulners` installati nella cartella di Nmap:
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
chmod +x nmap_vuln_scan_pro-1.3.py
```

---

## 🚀 Utilizzo

### Esempio base
```bash
sudo ./nmap_vuln_scan_pro-1.3.py -t 192.168.1.100
```

### Scansione di un’intera subnet
```bash
sudo ./nmap_vuln_scan_pro-1.3.py -t 192.168.1.0/24
```

### Salvataggio output in JSON
```bash
sudo ./nmap_vuln_scan_pro-1.3.py -t scanme.nmap.org -o json
```

---

## 🔧 Parametri disponibili (v1.3)
```
usage: nmap_vuln_scan_pro-1.3.py [-h] -t TARGET [-o {xml,json,csv,html}] [-p PORTS]

Opzioni:
  -h, --help            mostra questo messaggio ed esce
  -t, --target          target da scansionare (IP, host o subnet)
  -p, --ports           specifica porte da scansionare (es: 80,443,8080)
  -o, --output          formato di output (xml, json, csv, html)
```

---

## 📑 Esempio di output
Esecuzione:
```bash
sudo ./nmap_vuln_scan_pro-1.3.py -t scanme.nmap.org -o json
```

Estratto del risultato:
```json
{
  "target": "scanme.nmap.org",
  "timestamp": "2025-08-24T12:30:15",
  "uuid": "f5c2a3d0-91a3-45b6-a2f5-3a7f9a12cdef",
  "open_ports": [22, 80],
  "vulnerabilities": [
    {
      "cve": "CVE-2023-12345",
      "description": "Example vulnerability",
      "source": "vulners"
    }
  ]
}
```

---

## 📝 Cronologia versioni
- **v1.3**
  - Aggiunto `argparse` per parsing parametri da CLI
  - Supporto export in formato CSV
  - Maggiore modularità del codice
- **v1.2**
  - Supporto JSON e UUID
  - Logging avanzato con timestamp
- **v1.1**
  - Controllo privilegi `root`
  - Parsing HTML
- **v1.0**
  - Versione base con dipendenze e path database

---

## 🤝 Contributi
Le **pull request** sono benvenute. Per grandi cambiamenti, apri prima una issue per discutere cosa vorresti modificare.
