#!/usr/bin/env python3
import subprocess
import xml.etree.ElementTree as ET
import os
import sys
import platform
import re
from datetime import datetime
import shutil
import html
import json
import uuid
import time

# ---------------------- PRIVILEGI ----------------------
if os.geteuid() != 0:
    print("[!] Lo script richiede privilegi di root. Usa 'sudo'.")
    sys.exit(1)

# ---------------------- PERCORSI ----------------------
VULSCAN_PATH = "/usr/share/nmap/scripts/vulscan/"
VULNERS_PATH = "/usr/share/nmap/scripts/vulners/"

# ---------------------- VALIDAZIONE TARGET ----------------------
IP_REGEX = re.compile(r"^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$")
HOSTNAME_REGEX = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")

def validate_target(target):
    return bool(IP_REGEX.match(target) or HOSTNAME_REGEX.match(target))

# ---------------------- CHECK DIPENDENZE ----------------------
def check_dependencies():
    print("[*] Verifica delle dipendenze...")
    required_tools = ["nmap", "git", "python3", "curl", "wget"]
    missing_tools = [tool for tool in required_tools if not shutil.which(tool)]
    if missing_tools:
        print(f"[!] Dipendenze mancanti: {', '.join(missing_tools)}")
        install_dependencies(missing_tools)
    else:
        print("[*] Tutte le dipendenze sono presenti.")

def install_dependencies(tools):
    system_platform = platform.system()
    print("[*] Installazione delle dipendenze mancanti...")
    if system_platform == "Linux":
        pkg_manager = detect_pkg_manager()
        if not pkg_manager:
            print(f"[!] Pacchetto manager non supportato. Installa manualmente: {', '.join(tools)}")
            sys.exit(1)
        subprocess.run(["sudo", pkg_manager, "update"], check=True)
        subprocess.run(["sudo", pkg_manager, "install", "-y"] + tools, check=True)
    elif system_platform == "Darwin":
        if not shutil.which("brew"):
            print("[!] Homebrew non installato. Installalo prima di procedere.")
            sys.exit(1)
        for tool in tools:
            subprocess.run(["brew", "install", tool], check=True)
    else:
        print(f"[!] Sistema operativo non supportato: {system_platform}. Installa manualmente: {', '.join(tools)}")
        sys.exit(1)

def detect_pkg_manager():
    for pm in ["apt", "yum", "pacman"]:
        if shutil.which(pm):
            return pm
    return None

# ---------------------- VULSCAN ----------------------
def update_vulscan_db():
    if not os.path.isdir(VULSCAN_PATH):
        print("[*] Vulscan non trovato. Installazione automatica...")
        try:
            subprocess.run(["sudo", "git", "clone", "https://github.com/scipag/vulscan.git", VULSCAN_PATH], check=True)
            print("[*] Vulscan installato correttamente.")
        except subprocess.CalledProcessError:
            print("[!] Errore durante l'installazione di Vulscan.")
            return
    print("[*] Aggiornamento Vulscan...")
    update_sh = os.path.join(VULSCAN_PATH, "update.sh")
    update_files_sh = os.path.join(VULSCAN_PATH, "utilities", "updater", "updateFiles.sh")
    try:
        if os.path.exists(update_sh):
            subprocess.run(["bash", update_sh], check=True)
        elif os.path.exists(update_files_sh):
            subprocess.run(["bash", update_files_sh], check=True)
    except subprocess.CalledProcessError:
        print("[!] Errore durante l'aggiornamento di Vulscan.")

# ---------------------- VULNERS ----------------------
def update_vulners():
    if not os.path.isdir(VULNERS_PATH):
        try:
            subprocess.run(["sudo", "git", "clone", "https://github.com/vulnersCom/nmap-vulners.git", VULNERS_PATH], check=True)
        except subprocess.CalledProcessError:
            print("[!] Errore clonando Vulners.")
    else:
        subprocess.run(["git", "-C", VULNERS_PATH, "pull"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# ---------------------- NMAP ----------------------
import subprocess

def update_nmap_scripts():
    subprocess.run(["sudo", "nmap", "--script-updatedb"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def build_nmap_command(target, profile, output_xml):
    scripts = ["vuln", "vulners", "vulscan/vulscan"]
    extra_flags = []

    if profile == "1":
        extra_flags = ["-T3", "--top-ports", "100"]

    elif profile == "2":
        scripts += ["ssl-cert", "ssl-enum-ciphers", "smb-vuln*", "ftp-anon"]
        extra_flags = ["-T3", "-p1-500", "--version-all"]

    # Profilo 3 - versione VM-safe
    elif profile == "3":
        scripts += ["default", "safe", "ssl-cert", "ssl-enum-ciphers"]
        extra_flags = [
            "-sS",               # TCP SYN scan
            "-p1-1024",          # solo porte comuni
            "-T2",               # più lento, meno stress
            "--version-all",
            "--script-timeout", "2m",
            "--max-retries", "1"
        ]
        # Script vulnerabilità separati (eseguibili uno per volta)
        # smb-vuln* su porta 445
        # ftp-anon su porta 21

    # Profilo 4 - versione VM-safe
    elif profile == "4":
        scripts += ["default", "safe", "auth", "discovery", "ssl-cert", "ssl-enum-ciphers"]
        extra_flags = [
            "-sS",
            "-p1-1024",
            "-T2",
            "--version-all",
            "--script-timeout", "2m",
            "--max-retries", "1"
        ]
        # Script vulnerabilità separati
        # smb-vuln* -> porta 445
        # ftp-anon -> porta 21
        # UDP limitato se necessario su porte note

    cmd = ["nmap", "-sV", "--stats-every", "5s", "--script", ",".join(scripts), "-oX", output_xml, target] + extra_flags
    return cmd

# ---------------------- PARSING XML ----------------------
CVE_REGEX = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)
SEVERITY_REGEX = re.compile(r"Severity:\s*(Critical|High|Medium|Low|Info)", re.IGNORECASE)

def parse_nmap_xml(xml_file):
    host_data = {}
    try:
        tree = ET.parse(xml_file)
    except ET.ParseError as e:
        print(f"[!] Errore parsing XML {xml_file}: {e}")
        return host_data
    except FileNotFoundError:
        print(f"[!] File XML non trovato: {xml_file}")
        return host_data

    root = tree.getroot()
    for host in root.findall('host'):
        ip = next((addr.get('addr') for addr in host.findall('address') if addr.get('addrtype') == 'ipv4'), None)
        if not ip:
            continue

        ports = [
            f"{p.get('portid')}/{p.get('protocol')}" 
            for p in host.findall(".//port") 
            if p.find('state') is not None and p.find('state').get('state') == 'open'
        ]

        cves = []
        scripts = host.findall('hostscript/script') + host.findall(".//script")
        for script in scripts:
            output = script.get('output', '')
            script_severity = script.get('severity', None)
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                cve_matches = CVE_REGEX.findall(line)
                severity_match = SEVERITY_REGEX.search(line)
                if script_severity:
                    severity = script_severity.capitalize()
                elif severity_match:
                    severity = severity_match.group(1).capitalize()
                else:
                    severity = 'Info'

                for cve in cve_matches:
                    cves.append({
                        'id': cve.upper(),
                        'description': html.escape(line),
                        'severity': severity
                    })

        host_data[ip] = {'ports': ports, 'cves': cves}
    return host_data

# ---------------------- REPORT HTML ----------------------
def generate_html_report_from_xml(xml_file, output_file="report.html"):
    host_data = parse_nmap_xml(xml_file)
    
    severity_count = {'Critical':0,'High':0,'Medium':0,'Low':0,'Info':0}
    for info in host_data.values():
        for cve in info['cves']:
            sev = cve.get('severity','Info')
            severity_count[sev] = severity_count.get(sev, 0) + 1

    severity_colors = {
        'Critical': '#FF0000',
        'High': '#FF8C00',
        'Medium': '#FFD700',
        'Low': '#32CD32',
        'Info': '#808080'
    }

    total_hosts = len(host_data)
    total_ports = sum(len(info['ports']) for info in host_data.values())
    total_cves = sum(len(info['cves']) for info in host_data.values())

    severity_rows = "".join(
        f"<tr><td>{sev}</td><td><span class='severity-Cell' style='background:{severity_colors[sev]}'>{count}</span></td></tr>"
        for sev, count in severity_count.items()
    )

    summary_table = f"""
    <h2>Riassunto scansione</h2>
    <table>
        <tr><th>Totale host</th><th>Porte aperte</th><th>Vulnerabilità trovate</th></tr>
        <tr>
            <td>{total_hosts}</td>
            <td>{total_ports}</td>
            <td>{total_cves}</td>
        </tr>
    </table>
    <h3>Distribuzione vulnerabilità per severità</h3>
    <table>
        <tr><th>Severità</th><th>Numero</th></tr>
        {severity_rows}
    </table>
    """

    host_summary = """
    <h2>Dettagli host</h2>
    <table>
        <tr><th>Host</th><th>Porte aperte</th><th>Numero vulnerabilità</th></tr>
    """
    for ip, info in host_data.items():
        host_summary += (
            f"<tr>"
            f"<td>{ip}</td>"
            f"<td>{', '.join(info['ports']) if info['ports'] else '-'}</td>"
            f"<td>{len(info['cves'])}</td>"
            f"</tr>"
        )
    host_summary += "</table>"

    html_content = f"""
<html>
<head>
    <title>Report Vulnerabilità</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
    body{{font-family:Arial;}}
    table{{border-collapse:collapse;width:100%;margin-bottom:20px;}}
    th,td{{border:1px solid #ccc;padding:5px;text-align:left;}}
    th{{background-color:#f2f2f2;}}
    .severity-filter {{margin-bottom: 15px;font-size: 16px;}}
    .severity-Cell {{padding: 2px 6px;border-radius: 4px;color: white;font-weight: bold;display: inline-block;}}
    a {{ color: #1E90FF; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    #severityChart, #hostChart {{width: 400px !important;height: 300px !important;}}
</style>
</head>
<body>
<h1>Report Vulnerabilità</h1>
{summary_table}
{host_summary}
<h2>Distribuzione severità globale</h2>
<canvas id="severityChart"></canvas>
<h2>Vulnerabilità per host</h2>
<canvas id="hostChart"></canvas>
<h2>Dettagli CVE</h2>
<div class="severity-filter">
Filtra per severità:
{''.join([f'<label><input type="checkbox" class="sev-filter" value="{sev}" checked> {sev}</label> ' for sev in severity_count])}
</div>
<table>
<tr><th>Host</th><th>Porta</th><th>CVE</th><th>Severità</th><th>Descrizione</th></tr>
"""

    for ip, info in host_data.items():
        ports_str = ', '.join(info['ports'])
        for cve in info['cves']:
            sev_class = f"sev-{cve['severity']}"
            color = severity_colors.get(cve['severity'], '#808080')
            cve_link = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve['id']}"
            html_content += (
                f"<tr class='cve-row {sev_class}'>"
                f"<td>{ip}</td>"
                f"<td>{ports_str}</td>"
                f"<td><a href='{cve_link}' target='_blank'>{cve['id']}</a></td>"
                f"<td><span class='severity-Cell' style='background:{color}'>{cve['severity']}</span></td>"
                f"<td>{cve['description']}</td>"
                "</tr>"
            )

    html_content += "</table>"

    html_content += f"""
<script>
const severityCtx = document.getElementById('severityChart').getContext('2d');
new Chart(severityCtx, {{
    type: 'pie',
    data: {{
        labels: {list(severity_count.keys())},
        datasets: [{{data: {list(severity_count.values())}, backgroundColor: {list(severity_colors.values())}}}]
    }},
    options: {{responsive: true, plugins: {{ legend: {{ position: 'bottom' }} }}}}
}});
const hostCtx = document.getElementById('hostChart').getContext('2d');
new Chart(hostCtx, {{
    type: 'bar',
    data: {{
        labels: {list(host_data.keys())},
        datasets: [{{label: 'Numero vulnerabilità', data: {[len(info['cves']) for info in host_data.values()]}, backgroundColor: '#4169E1'}}]
    }},
    options: {{responsive: true, scales: {{ y: {{ beginAtZero: true, precision:0 }} }}, plugins: {{ legend: {{ display: false }} }}}}
}});
const checkboxes = document.querySelectorAll('.sev-filter');
checkboxes.forEach(cb => {{
    cb.addEventListener('change', () => {{
        const checkedSev = Array.from(checkboxes).filter(c=>c.checked).map(c=>c.value);
        document.querySelectorAll('.cve-row').forEach(row => {{
            const classes = row.className.split(' ');
            let show = false;
            for(let c of classes) {{
                if(c.startsWith('sev-') && checkedSev.includes(c.replace('sev-',''))){{show=true;}}
            }}
            row.style.display = show ? '' : 'none';
        }});
    }});
}});
</script>
</body></html>
"""

    with open(output_file, "w") as f:
        f.write(html_content)
    print(f"[*] Report HTML generato: {output_file}")

# ---------------------- REPORT JSON ----------------------
def save_json_report(xml_file, output_file="report.json"):
    data = parse_nmap_xml(xml_file)
    with open(output_file, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[*] Report JSON generato: {output_file}")

# ---------------------- BANNER ----------------------
def print_banner():
    print("""
=========================================
        Nmap Vulnerability Scanner Pro
            Created by: grayf0x
               Version: 1.2
=========================================
""")

# ---------------------- MAIN ----------------------
def main():
    print_banner()
    check_dependencies()
    update_vulscan_db()
    update_vulners()
    update_nmap_scripts()

    target = input("Inserisci IP o hostname da scansionare: ").strip()
    if not validate_target(target):
        print("[!] Target non valido.")
        sys.exit(1)

    alias = input("Vuoi assegnare un nome descrittivo al target (es. server01)? [Invio per saltare]: ").strip()
    alias = re.sub(r'[^a-zA-Z0-9_-]', '_', alias) if alias else target.replace(".", "_")

    print("Profilo di scansione:\n1) Rapida\n2) Standard\n3) Approfondita\n4) Completa")
    profile = input("Scegli profilo (1-4): ").strip()
    if profile not in ["1","2","3","4"]:
        print("[!] Profilo non valido. Uso 2 (Standard).")
        profile = "2"

    profile_names = {"1": "Rapida", "2": "Standard", "3": "Approfondita", "4": "Completa"}
    profile_name = profile_names.get(profile, "Standard")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:6]

    reports_dir = os.path.join("reports", profile_name)
    os.makedirs(reports_dir, exist_ok=True)

    output_xml = os.path.join(reports_dir, f"scan_{alias}_{timestamp}_{unique_id}.xml")
    output_html = os.path.join(reports_dir, f"report_{alias}_{timestamp}_{unique_id}.html")
    output_json = os.path.join(reports_dir, f"report_{alias}_{timestamp}_{unique_id}.json")

    cmd = build_nmap_command(target, profile, output_xml)
    print(f"[*] Avvio scansione Nmap sul target {target} ({alias}) con profilo {profile_name})...")
    start_time = time.time()
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Errore durante la scansione: {e}")
        sys.exit(1)

    generate_html_report_from_xml(output_xml, output_html)
    save_json_report(output_xml, output_json)

    elapsed = time.time() - start_time
    minutes, seconds = divmod(int(elapsed), 60)
    print(f"[*] Tempo impiegato per la scansione: {minutes}m {seconds}s")
    print(f"[*] Report salvato in: {output_html}")

if __name__ == "__main__":
    main()
    
