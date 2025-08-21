#!/usr/bin/env python3
import subprocess
import xml.etree.ElementTree as ET
import os
import sys
import time
import platform
from datetime import datetime

# ---------------------- PERCORSI ----------------------
VULSCAN_PATH = "/usr/share/nmap/scripts/vulscan/"
VULNERS_PATH = "/usr/share/nmap/scripts/vulners/"
VULSCAN_DB_FILES = [
    "exploitdb.csv",
    "cve.csv",
    "osvdb.csv",
    "cert.org.csv"
]

# ---------------------- CHECK DIPENDENZE ----------------------
def check_dependencies():
    print("[*] Verifica delle dipendenze...")
    required_tools = ["nmap", "git", "python3", "curl", "wget"]
    missing_tools = []

    for tool in required_tools:
        if subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            missing_tools.append(tool)

    if missing_tools:
        print(f"[!] Le seguenti dipendenze non sono installate: {', '.join(missing_tools)}")
        install_dependencies(missing_tools)
    else:
        print("[*] Tutte le dipendenze sono presenti.")

def install_dependencies(tools):
    system_platform = platform.system()
    print("[*] Provo a installare le dipendenze mancanti...")
    if system_platform == "Linux":
        pkg_manager = detect_pkg_manager()
        if not pkg_manager:
            print("[!] Gestore pacchetti non supportato. Installa manualmente:", ', '.join(tools))
            sys.exit(1)
        subprocess.call(["sudo", pkg_manager, "update"])
        subprocess.call(["sudo", pkg_manager, "install", "-y"] + tools)
    elif system_platform == "Darwin":
        for tool in tools:
            subprocess.call(["brew", "install", tool])
    else:
        print(f"[!] Sistema operativo non supportato: {system_platform}. Installa manualmente: {', '.join(tools)}")
        sys.exit(1)

def detect_pkg_manager():
    for pm in ["apt", "yum", "pacman"]:
        if subprocess.call(["which", pm], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            return pm
    return None

# ---------------------- VULSCAN ----------------------
def update_vulscan_db():
    if not os.path.isdir(VULSCAN_PATH):
        print("[*] Vulscan non trovato. Installazione automatica...")
        try:
            subprocess.run(
                ["sudo", "git", "clone", "https://github.com/scipag/vulscan.git", VULSCAN_PATH],
                check=True
            )
            print("[*] Vulscan installato correttamente.")
        except subprocess.CalledProcessError:
            print("[!] Errore durante l'installazione automatica di Vulscan.")
            return

    print("[*] Vulscan già presente, controllo aggiornamenti...")

    update_sh = os.path.join(VULSCAN_PATH, "update.sh")
    update_files_sh = os.path.join(VULSCAN_PATH, "utilities", "updater", "updateFiles.sh")

    if os.path.exists(update_sh):
        print("[*] Aggiornamento database Vulscan con update.sh...")
        try:
            subprocess.run(["bash", update_sh], check=True)
            print("[*] Database Vulscan aggiornati.")
        except subprocess.CalledProcessError:
            print("[!] Errore durante esecuzione update.sh.")
    elif os.path.exists(update_files_sh):
        print("[*] Aggiornamento database Vulscan con updateFiles.sh...")
        try:
            subprocess.run(["bash", update_files_sh], check=True)
            print("[*] Database Vulscan aggiornati.")
        except subprocess.CalledProcessError:
            print("[!] Errore durante esecuzione updateFiles.sh.")
    else:
        print("[!] Nessuno script di aggiornamento trovato in Vulscan.")
        print("    → Assicurati di avere la versione ufficiale: https://github.com/scipag/vulscan")
        print("    → In alternativa aggiorna manualmente i CSV nella cartella db/")

# ---------------------- VULNERS ----------------------
def update_vulners():
    if not os.path.isdir(VULNERS_PATH):
        print("[*] nmap-vulners non trovato. Installazione automatica...")
        try:
            subprocess.run(
                ["sudo", "git", "clone", "https://github.com/vulnersCom/nmap-vulners.git", VULNERS_PATH],
                check=True
            )
            print("[*] nmap-vulners installato correttamente.")
        except subprocess.CalledProcessError:
            print("[!] Errore durante l'installazione automatica di nmap-vulners.")
            return
    else:
        print("[*] Aggiornamento nmap-vulners...")
        try:
            subprocess.run(["git", "-C", VULNERS_PATH, "pull"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("[*] nmap-vulners aggiornato.")
        except subprocess.CalledProcessError:
            print("[!] Errore durante aggiornamento nmap-vulners.")

# ---------------------- NMAP ----------------------
def update_nmap_scripts():
    print("[*] Aggiornamento degli script Nmap...")
    try:
        subprocess.run(["sudo", "nmap", "--script-updatedb"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[*] Script Nmap aggiornati.")
    except subprocess.CalledProcessError:
        print("[!] Errore aggiornamento script Nmap.")

def build_nmap_command(target, profile, output_xml):
    scripts = ["vuln", "vulners", "vulscan/vulscan"]
    extra_flags = []

    if profile == "1":  # Base
        extra_flags = ["-T3", "--top-ports", "100"]
    elif profile == "2":  # Intermedio
        scripts += ["ssl-cert", "ssl-enum-ciphers", "smb-vuln*", "ftp-anon"]
        extra_flags = ["-T3", "-p1-500", "--version-all"]
    elif profile == "3":  # Avanzato
        scripts += ["default", "safe", "ssl-cert", "ssl-enum-ciphers", "smb-vuln*", "ftp-anon"]
        extra_flags = ["-sS", "-sU", "-A", "-p-", "-T3", "--version-all", "--script-timeout", "5m", "--max-retries", "2"]
    elif profile == "4":  # Full Audit
        scripts += ["default", "safe", "auth", "discovery", "ssl-cert", "ssl-enum-ciphers", "smb-vuln*", "ftp-anon"]
        extra_flags = ["-sS", "-sU", "-A", "-p-", "-T3", "--version-all", "--script-timeout", "5m", "--max-retries", "2", "--host-timeout", "2h"]

    cmd = [
        "nmap", "-sV", "--stats-every", "5s",
        "--script", ",".join(scripts),
        "-oX", output_xml, target
    ] + extra_flags

    return cmd

# ---------------------- REPORT ----------------------
def generate_html_report(xml_file, profile, duration_seconds):
    import xml.etree.ElementTree as ET
    import os
    from datetime import timedelta

    reports_dir = os.path.dirname(xml_file)
    html_file = os.path.join(reports_dir, os.path.basename(xml_file).replace(".xml", ".html"))

    try:
        tree = ET.parse(xml_file)
    except Exception:
        print("[!] File XML non valido o non trovato. Nessun report generato.")
        return

    root = tree.getroot()
    host_data = {}
    severity_count = {"Critical":0, "High":0, "Medium":0, "Low":0, "Info":0}

    for host in root.findall('host'):
        addr = host.find('address').get('addr')
        host_data[addr] = {
            'ports': [],
            'cves': {},
            'max_severity': 'Info',
            'sev_counts': {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
        }
        for port in host.findall('ports/port'):
            portid = port.get('portid')
            service = port.find('service').get('name') if port.find('service') is not None else "Unknown"
            scripts_out = []
            for script in port.findall('script'):
                output = script.get('output')
                if output:
                    scripts_out.append({'id': script.get('id'), 'output': output})
                    for word in output.split():
                        if word.startswith("CVE-"):
                            sev = "Info"
                            if "Critical" in output or "HIGH" in output:
                                sev = "Critical"
                            elif "MEDIUM" in output:
                                sev = "Medium"
                            elif "LOW" in output:
                                sev = "Low"
                            host_data[addr]['cves'][word] = sev
                            severity_count[sev] += 1
                            host_data[addr]['sev_counts'][sev] += 1
                            if sev == "Critical":
                                host_data[addr]['max_severity'] = "Critical"
                            elif sev == "High" and host_data[addr]['max_severity'] not in ["Critical"]:
                                host_data[addr]['max_severity'] = "High"
                            elif sev == "Medium" and host_data[addr]['max_severity'] not in ["Critical","High"]:
                                host_data[addr]['max_severity'] = "Medium"
            host_data[addr]['ports'].append({'port': portid, 'service': service, 'scripts': scripts_out})

    duration_str = str(timedelta(seconds=int(duration_seconds)))

    html_content = f"""
    <html>
    <head>
    <title>Report Nmap Vulnerability Scanner</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f4f4f4; }}
        h1, h2 {{ color: #333; }}
        .dashboard {{ background: #fff; padding: 10px; margin-bottom: 20px; border-radius: 5px; }}
        table {{ border-collapse: collapse; width: 100%; background: #fff; margin-bottom: 20px; border-radius:5px; overflow:hidden; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
        th {{ background: #333; color: #fff; }}
        .Critical {{ color: red; font-weight: bold; }}
        .High {{ color: darkorange; font-weight: bold; }}
        .Medium {{ color: goldenrod; font-weight: bold; }}
        .Low {{ color: green; font-weight: bold; }}
        .Info {{ color: gray; }}
        input, select {{ padding: 5px; margin: 5px 0; }}
        canvas {{ max-width: 500px; margin: 10px 0; }}
    </style>
    </head>
    <body>
    <h1>Report Nmap Vulnerability Scanner</h1>
    <div class="dashboard">
        <div><b>Target XML:</b> {os.path.basename(xml_file)}</div>
        <div><b>Profilo Scansione:</b> {profile}</div>
        <div><b>Durata scansione:</b> {duration_str}</div>
        <div><b>Numero host scansionati:</b> {len(host_data)}</div>
    </div>

    <h2>Filtri interattivi</h2>
    <input type="text" id="hostFilter" placeholder="Filtra per host">
    <select id="sevFilter">
        <option value="">Tutte le severità</option>
        <option value="Critical">Critical</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
        <option value="Info">Info</option>
    </select>

    <h2>Distribuzione globale vulnerabilità</h2>
    <canvas id="severityChart"></canvas>

    <h2>Riepilogo host</h2>
    <table id="hostTable">
        <thead>
        <tr><th>Host</th><th>Porta aperte</th><th>Vulnerabilità trovate</th><th>Severità massima</th></tr>
        </thead>
        <tbody>
    """

    for host, info in host_data.items():
        num_ports = len(info['ports'])
        num_cves = len(info['cves'])
        max_sev = info['max_severity']
        html_content += f"<tr data-host='{host}' data-sev='{max_sev}'><td>{host}</td><td>{num_ports}</td><td>{num_cves}</td><td class='{max_sev}'>{max_sev}</td></tr>"

    html_content += "</tbody></table>"

    html_content += "<h2>Grafici vulnerabilità per host</h2>"
    for host, info in host_data.items():
        counts = [info['sev_counts'][sev] for sev in ["Critical","High","Medium","Low","Info"]]
        html_content += f"<h3>{host}</h3><canvas id='chart_{host.replace('.', '_')}'></canvas>"
        html_content += f"""
        <script>
        new Chart(document.getElementById('chart_{host.replace('.', '_')}').getContext('2d'), {{
            type: 'bar',
             {{
                labels: ['Critical','High','Medium','Low','Info'],
                datasets: [{{
                     {counts},
                    backgroundColor: ['#e74c3c','#e67e22','#f1c40f','#27ae60','#95a5a6']
                }}]
            }},
            options: {{
                plugins: {{
                    legend: {{ display: false }},
                    tooltip: {{
                        callbacks: {{
                            label: function(context) {{
                                return context.label + ": " + context.raw;
                            }}
                        }}
                    }}
                }},
                scales: {{
                    y: {{ beginAtZero: true }}
                }}
            }}
        }});
        </script>
        """

    html_content += "<h2>Dettaglio scansione</h2>"
    for host, info in host_data.items():
        html_content += f"<h3>{host}</h3>"
        html_content += "<table><tr><th>Porta</th><th>Servizio</th><th>Script Output</th></tr>"
        for port in info['ports']:
            script_out_html = ""
            for s in port['scripts']:
                out = s['output'].replace("\n","<br>")
                for word, sev in info['cves'].items():
                    out = out.replace(word, f"<a href='https://nvd.nist.gov/vuln/detail/{word}' target='_blank' class='{sev}'>{word}</a>")
                script_out_html += f"<b>{s['id']}</b>: {out}<br>"
            html_content += f"<tr><td>{port['port']}</td><td>{port['service']}</td><td>{script_out_html}</td></tr>"
        html_content += "</table>"

    html_content += f"""
    <script>
        var severityCounts = {list(severity_count.values())};
        var labels = ['Critical','High','Medium','Low','Info'];
        var colors = ['#e74c3c','#e67e22','#f1c40f','#27ae60','#95a5a6'];

        new Chart(document.getElementById('severityChart').getContext('2d'), {{
            type: 'doughnut',
             {{
                labels: labels,
                datasets: [{{
                     severityCounts,
                    backgroundColor: colors
                }}]
            }},
            options: {{
                plugins: {{
                    legend: {{
                        position: 'right',
                        labels: {{ font: {{ size: 14 }} }}
                    }},
                    tooltip: {{
                        callbacks: {{
                            label: function(context) {{
                                let total = context.dataset.data.reduce((a,b)=>a+b,0);
                                let value = context.raw;
                                let percentage = ((value / total) * 100).toFixed(1) + "%";
                                return context.label + ": " + value + " (" + percentage + ")";
                            }}
                        }}
                    }}
                }}
            }}
        }});

        document.getElementById("hostFilter").addEventListener("input", function(){{
            var val = this.value.toLowerCase();
            var rows = document.querySelectorAll("#hostTable tbody tr");
            rows.forEach(r => {{
                r.style.display = r.dataset.host.toLowerCase().includes(val) ? "" : "none";
            }});
        }});
        document.getElementById("sevFilter").addEventListener("change", function(){{
            var val = this.value;
            var rows = document.querySelectorAll("#hostTable tbody tr");
            rows.forEach(r => {{
                r.style.display = (val==="" || r.dataset.sev===val) ? "" : "none";
            }});
        }});
    </script>
    </body></html>
    """

    with open(html_file, "w") as f:
        f.write(html_content)

    print(f"[*] Report HTML interattivo salvato in: {html_file}")

# ---------------------- MAIN ----------------------
def print_banner():
    banner = r"""
=========================================
        Nmap Vulnerability Scanner Pro
            Created by: grayf0x05
               Version: 1.0
=========================================
"""
    print(banner)

def main():
    print_banner()
    check_dependencies()
    
    update_vulscan_db()
    update_vulners()
    update_nmap_scripts()

    profile_names = {"1": "base", "2": "intermedio", "3": "avanzato", "4": "full_audit"}

    while True:
        target = input("Inserisci target (IP o dominio) (oppure 'exit' per uscire): ").strip()
        if target.lower() == 'exit':
            print("[*] Uscita dal programma.")
            break

        print("Seleziona profilo scansione:")
        print("1) Base")
        print("2) Intermedio")
        print("3) Avanzato")
        print("4) Full Audit")
        profile = input("Profilo (1-4): ").strip()
        if profile not in profile_names:
            print("[!] Profilo non valido. Riprova.")
            continue

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reports_dir = os.path.join("reports", f"scan_{timestamp}")
        os.makedirs(reports_dir, exist_ok=True)
        output_xml = os.path.join(reports_dir, f"scan_{target.replace('.', '_')}_{profile_names[profile]}.xml")

        cmd = build_nmap_command(target, profile, output_xml)

        print("[*] Avvio scansione...")

        start_time = time.time()
        process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        tick_symbols = ["-", "\\", "|", "/"]  
        tick_index = 0
        bar_length = 30  
        fill_index = 0

        while process.poll() is None:
            elapsed = int(time.time() - start_time)
            hours, remainder = divmod(elapsed, 3600)
            mins, secs = divmod(remainder, 60)
            elapsed_str = f"{hours:02}:{mins:02}:{secs:02}"

            bar = "[" + "=" * fill_index + " " * (bar_length - fill_index) + "]"
            sys.stdout.write(f"\r{tick_symbols[tick_index]} {bar} Tempo: {elapsed_str}")
            sys.stdout.flush()

            tick_index = (tick_index + 1) % len(tick_symbols)
            fill_index = (fill_index + 1) % (bar_length + 1)
            time.sleep(1)

        duration_seconds = int(time.time() - start_time)
        print("\n[*] Scansione completata.")
        generate_html_report(output_xml, profile_names[profile], duration_seconds)

if __name__ == "__main__":
    main()
