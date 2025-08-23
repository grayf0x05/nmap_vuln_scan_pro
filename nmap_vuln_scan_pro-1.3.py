#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
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
import csv

# ---------------------- PERCORSI ----------------------
VULSCAN_PATH = "/usr/share/nmap/scripts/vulscan/"
VULNERS_PATH = "/usr/share/nmap/scripts/vulners/"

# ---------------------- VALIDAZIONE TARGET ----------------------
IPV4_REGEX = re.compile(r"^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$")
HOSTNAME_REGEX = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")

def validate_target(target: str) -> bool:
    return bool(IPV4_REGEX.match(target) or HOSTNAME_REGEX.match(target))

# ---------------------- DIPENDENZE ----------------------
def detect_pkg_manager():
    for pm in ["apt", "dnf", "yum", "pacman"]:
        if shutil.which(pm):
            return pm
    return None

def install_dependencies(tools):
    system_platform = platform.system()
    print("[*] Installazione delle dipendenze mancanti...")
    if system_platform == "Linux":
        pm = detect_pkg_manager()
        if not pm:
            print(f"[!] Package manager non trovato. Installa manualmente: {', '.join(tools)}")
            sys.exit(1)
        if pm == "apt":
            subprocess.run([pm, "update"], check=True)
            subprocess.run([pm, "install", "-y"] + tools, check=True)
        elif pm in ("dnf", "yum"):
            subprocess.run([pm, "-y", "install"] + tools, check=True)
        elif pm == "pacman":
            subprocess.run([pm, "-Sy", "--needed"] + tools, check=True)
    elif system_platform == "Darwin":
        if not shutil.which("brew"):
            print("[!] Homebrew non installato. Installalo prima di procedere.")
            sys.exit(1)
        for tool in tools:
            subprocess.run(["brew", "install", tool], check=True)
    else:
        print(f"[!] Sistema operativo non supportato: {system_platform}. Installa manualmente: {', '.join(tools)}")
        sys.exit(1)

def check_dependencies():
    print("[*] Verifica delle dipendenze...")
    required_tools = ["nmap", "git", "python3", "curl", "wget"]
    missing = [t for t in required_tools if not shutil.which(t)]
    if missing:
        print(f"[!] Dipendenze mancanti: {', '.join(missing)}")
        install_dependencies(missing)
    else:
        print("[*] Tutte le dipendenze sono presenti.")

# ---------------------- GIT UTILS ----------------------
def _is_git_repo(path: str) -> bool:
    try:
        subprocess.run(["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def git_clone_or_pull(repo_url: str, dest_path: str):
    parent = os.path.dirname(dest_path.rstrip("/"))
    os.makedirs(parent, exist_ok=True)
    if os.path.isdir(dest_path):
        if _is_git_repo(dest_path):
            try:
                subprocess.run(["git", "-C", dest_path, "pull", "--ff-only"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            except subprocess.CalledProcessError:
                print(f"[!] Errore durante 'git pull' in {dest_path}.")
        else:
            # cartella presente ma non repo: reclona in tmp e sostituisci contenuti
            tmp = dest_path.rstrip("/") + ".tmpclone"
            if os.path.exists(tmp):
                shutil.rmtree(tmp, ignore_errors=True)
            try:
                subprocess.run(["git", "clone", repo_url, tmp], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # pulisci dest e muovi contenuti
                for name in os.listdir(dest_path):
                    p = os.path.join(dest_path, name)
                    shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.remove(p)
                for name in os.listdir(tmp):
                    shutil.move(os.path.join(tmp, name), os.path.join(dest_path, name))
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
    else:
        try:
            subprocess.run(["git", "clone", repo_url, dest_path], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            print(f"[!] Errore clonando {repo_url} in {dest_path}.")

# ---------------------- AGGIORNAMENTO SCRIPT NSE ----------------------
def update_vulscan_db():
    print("[*] Aggiornamento Vulscan...")
    git_clone_or_pull("https://github.com/scipag/vulscan.git", VULSCAN_PATH)
    # Esegui gli script di update se presenti
    update_sh = os.path.join(VULSCAN_PATH, "update.sh")
    update_files_sh = os.path.join(VULSCAN_PATH, "utilities", "updater", "updateFiles.sh")
    try:
        if os.path.exists(update_sh):
            subprocess.run(["bash", update_sh], check=True)
        elif os.path.exists(update_files_sh):
            subprocess.run(["bash", update_files_sh], check=True)
    except subprocess.CalledProcessError:
        print("[!] Errore durante l'aggiornamento dei database Vulscan.")

def update_vulners():
    print("[*] Aggiornamento Vulners...")
    git_clone_or_pull("https://github.com/vulnersCom/nmap-vulners.git", VULNERS_PATH)

def update_nmap_scripts():
    try:
        subprocess.run(["nmap", "--script-updatedb"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError:
        print("[!] nmap --script-updatedb ha restituito un errore (continuo).")

# ---------------------- COSTRUZIONE COMANDO NMAP ----------------------
def build_nmap_command(target, profile, output_xml, vm_safe=True):
    scripts = ["vuln", "vulners", "vulscan/vulscan"]
    extra_flags = ["--stats-every", "5s"]

    if profile == "1":
        extra_flags += ["-T3", "--top-ports", "100"]
    elif profile == "2":
        scripts += ["ssl-cert", "ssl-enum-ciphers", "smb-vuln*", "ftp-anon"]
        extra_flags += ["-T3", "-p1-1000", "--version-all"]
    elif profile == "3":
        scripts += ["default", "safe", "ssl-cert", "ssl-enum-ciphers"]
        extra_flags += ["-sS", "-p1-1024", "-T2", "--version-all", "--script-timeout", "2m", "--max-retries", "1"]
    elif profile == "4":
        scripts += ["default", "safe", "auth", "discovery", "ssl-cert", "ssl-enum-ciphers"]
        extra_flags += ["-sS", "-p1-2048", "-T2", "--version-all", "--script-timeout", "2m", "--max-retries", "1"]

    if vm_safe:
        extra_flags += ["--max-rate", "300"]  # limita aggressività su reti sensibili/VM

    cmd = ["nmap", "-sV", "--script", ",".join(scripts), "-oX", output_xml, target] + extra_flags
    return cmd

# ---------------------- PARSING XML MIGLIORATO ----------------------
CVE_REGEX = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)
SEVERITY_REGEX = re.compile(r"Severity:\s*(Critical|High|Medium|Low|Info)", re.IGNORECASE)
CVSS_REGEX = re.compile(r"CVSS[:\s]*(?:v3[\.\d]*)?[:\s]*([0-9]+\.[0-9]+)", re.IGNORECASE)
# CVSS stampato subito dopo il CVE (es. "CVE-2019-1234 7.5 …")
CVSS_AFTER_CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}\s+([0-9]{1,2}\.[0-9])")
# Parole di severità senza prefisso "Severity:"
SEVERITY_WORDS_REGEX = re.compile(r"\b(Critical|High|Medium|Low)\b", re.IGNORECASE)

SEV_BUCKETS = {
    'critical': (9.0, 10.0),
    'high':     (7.0, 8.9),
    'medium':   (4.0, 6.9),
    'low':      (0.1, 3.9)
}

def _cvss_to_severity(cvss: float) -> str:
    if cvss is None:
        return 'Info'
    for sev, (lo, hi) in SEV_BUCKETS.items():
        if lo <= cvss <= hi:
            return sev.capitalize()
    return 'Info'

# Estrazione CVE/CSVSS da strutture XML (script <table>/<elem>)
def _extract_structured_cves(script_elem):
    pairs = []  # (cve_id, cvss or None)
    for tbl in script_elem.findall('.//table'):
        row = {}
        for e in tbl.findall('elem'):
            k = (e.get('key') or '').lower()
            row[k] = (e.text or '').strip()
        # trova CVE in un qualsiasi valore
        cve_id = None
        for v in list(row.values()):
            m = CVE_REGEX.search(v or '')
            if m:
                cve_id = m.group(1).upper()
                break
        if not cve_id:
            continue
        # prova a ricavare il cvss
        cvss = None
        for k, v in row.items():
            if 'cvss' in k or 'score' in k:
                m = re.search(r'([0-9]{1,2}\.[0-9])', v or '')
                if m:
                    try:
                        cvss = float(m.group(1))
                    except Exception:
                        pass
                else:
                    try:
                        cvss = float(v)
                    except Exception:
                        pass
        pairs.append((cve_id, cvss))
    return pairs

def parse_nmap_xml(xml_file):
    """
    Ritorna struttura per host:
    {
      ip: {
        'hostname': 'example.local',
        'ports': ['22/tcp', ...],
        'services': { '22/tcp': {'name': 'ssh', 'product': 'OpenSSH', 'version': '8.x', 'extrainfo': ''} },
        'cves': [ {'id': 'CVE-XXXX-YYYY', 'severity': 'High', 'port': '22/tcp', 'description': '...'} ]
      }
    }
    """
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
        ip = next((a.get('addr') for a in host.findall('address') if a.get('addrtype') in ('ipv4', 'ipv6')), None)
        if not ip:
            continue

        info = {'ports': [], 'services': {}, 'cves': [], 'hostname': ''}

        # hostname (se presente nel report nmap)
        names = [hn.get('name') for hn in host.findall('hostnames/hostname') if hn.get('name')]
        if names:
            info['hostname'] = names[0]

        seen = set()  # (CVE, port)

        # Per porta
        for p in host.findall(".//ports/port"):
            state = p.find('state')
            if state is None or state.get('state') != 'open':
                continue
            portid = p.get('portid')
            proto = p.get('protocol')
            port_key = f"{portid}/{proto}"
            info['ports'].append(port_key)

            svc = p.find('service')
            if svc is not None:
                info['services'][port_key] = {
                    'name': svc.get('name', ''),
                    'product': svc.get('product', ''),
                    'version': svc.get('version', ''),
                    'extrainfo': svc.get('extrainfo', '')
                }

            for s in p.findall('script'):
                # Estrazione strutturata (tabellare)
                for cve_id, cvss_score in _extract_structured_cves(s):
                    key = (cve_id, port_key)
                    if key in seen:
                        continue
                    seen.add(key)
                    sev = _cvss_to_severity(cvss_score) if isinstance(cvss_score, float) else 'Info'
                    info['cves'].append({
                        'id': cve_id,
                        'description': html.escape(f'CVSS {cvss_score}' if cvss_score is not None else '—'),
                        'severity': sev,
                        'port': port_key
                    })
                # Estrazione da output testuale
                output = s.get('output', '') or ''
                for line in output.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    cves = CVE_REGEX.findall(line)

                    # prova: "CVSS: 9.8" / "CVSSv3 Base Score: 9.8"
                    cvss_match = CVSS_REGEX.search(line)
                    # fallback: numero subito dopo il CVE, es. "CVE-2019-1234 7.5"
                    if not cvss_match:
                        cvss_match = CVSS_AFTER_CVE_REGEX.search(line)

                    # severità come parola (con o senza "Severity:")
                    sev_match = SEVERITY_REGEX.search(line)
                    if not sev_match:
                        sev_match = SEVERITY_WORDS_REGEX.search(line)

                    if cvss_match:
                        try:
                            sev = _cvss_to_severity(float(cvss_match.group(1)))
                        except ValueError:
                            sev = 'Info'
                    elif sev_match:
                        sev = sev_match.group(1).capitalize()
                    else:
                        sev = 'Info'

                    for cve in cves:
                        key = (cve.upper(), port_key)
                        if key in seen:
                            continue
                        seen.add(key)
                        info['cves'].append({
                            'id': cve.upper(),
                            'description': html.escape(line),
                            'severity': sev,
                            'port': port_key
                        })

        # Hostscript (non legato a porta)
        for s in host.findall('hostscript/script'):
            # Estrazione strutturata (tabellare)
            for cve_id, cvss_score in _extract_structured_cves(s):
                key = (cve_id, None)
                if key in seen:
                    continue
                seen.add(key)
                sev = _cvss_to_severity(cvss_score) if isinstance(cvss_score, float) else 'Info'
                info['cves'].append({
                    'id': cve_id,
                    'description': html.escape('Structured'),
                    'severity': sev,
                    'port': '-'
                })
            # Estrazione da output testuale
            output = s.get('output', '') or ''
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                cves = CVE_REGEX.findall(line)

                # prova: "CVSS: 9.8" / "CVSSv3 Base Score: 9.8"
                cvss_match = CVSS_REGEX.search(line)
                # fallback: numero subito dopo il CVE, es. "CVE-2019-1234 7.5"
                if not cvss_match:
                    cvss_match = CVSS_AFTER_CVE_REGEX.search(line)

                # severità come parola (con o senza "Severity:")
                sev_match = SEVERITY_REGEX.search(line)
                if not sev_match:
                    sev_match = SEVERITY_WORDS_REGEX.search(line)

                if cvss_match:
                    try:
                        sev = _cvss_to_severity(float(cvss_match.group(1)))
                    except ValueError:
                        sev = 'Info'
                elif sev_match:
                    sev = sev_match.group(1).capitalize()
                else:
                    sev = 'Info'

                for cve in cves:
                    key = (cve.upper(), None)
                    if key in seen:
                        continue
                    seen.add(key)
                    info['cves'].append({
                        'id': cve.upper(),
                        'description': html.escape(line),
                        'severity': sev,
                        'port': '-'
                    })

        host_data[ip] = info

    return host_data

# ---------------------- REPORT HTML/JSON/CSV ----------------------
def generate_html_report_from_xml(xml_file, output_file="report.html"):
    host_data = parse_nmap_xml(xml_file)

    severity_colors = {
        'Critical': '#FF0000',
        'High': '#FF8C00',
        'Medium': '#FFD700',
        'Low': '#32CD32',
        'Info': '#808080'
    }

    def host_label(ip, info):
        hn = info.get('hostname') or ''
        if hn and hn != ip:
            return f"{html.escape(hn)} <code class='ip-badge'>{ip}</code>"
        return f"<code class='ip-badge'>{ip}</code>"

    # Conteggi e ordinamento
    severity_count = {k: 0 for k in severity_colors.keys()}
    for info in host_data.values():
        for cve in info['cves']:
            severity_count[cve.get('severity', 'Info')] = severity_count.get(cve.get('severity', 'Info'), 0) + 1

    SEV_ORDER = {'Critical':0,'High':1,'Medium':2,'Low':3,'Info':4}
    for info in host_data.values():
        info['cves'].sort(key=lambda c: (SEV_ORDER.get(c.get('severity','Info'),4), c.get('id','')))

    total_hosts = len(host_data)
    total_ports = sum(len(info['ports']) for info in host_data.values())
    total_cves = sum(len(info['cves']) for info in host_data.values())

    severity_rows = "".join(
        f"<tr><td>{sev}</td><td><span class='severity-Cell' style='background:{severity_colors.get(sev,'#808080')}'>{count}</span></td></tr>"
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
        <tr><th>Host (hostname/IP)</th><th>Porte aperte</th><th>Numero vulnerabilità</th></tr>
    """
    for ip, info in host_data.items():
        host_summary += (
            f"<tr>"
            f"<td>{host_label(ip, info)}</td>"
            f"<td>{', '.join(info['ports']) if info['ports'] else '-'}</td>"
            f"<td>{len(info['cves'])}</td>"
            f"</tr>"
        )
    host_summary += "</table>"

    # Dati per i grafici (passati come JSON)
    severity_labels_js = json.dumps(list(severity_count.keys()))
    severity_values_js = json.dumps([severity_count[k] for k in severity_count.keys()])
    severity_colors_js = json.dumps([severity_colors[k] for k in severity_count.keys()])

    host_order = sorted(host_data.keys(), key=lambda k: len(host_data[k]['cves']), reverse=True)
    host_labels_display = []
    for h in host_order:
        hn = host_data[h].get('hostname') or ''
        host_labels_display.append(f"{hn} ({h})" if hn and hn != h else h)
    host_labels_js = json.dumps(host_labels_display)
    host_values_js = json.dumps([len(host_data[h]['cves']) for h in host_order])

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
    #severityChart, #hostChart {{width: 550px !important;height: 350px !important;}}
    .ip-badge {{background:#f6f6f6; border:1px solid #ddd; padding:1px 4px; border-radius:4px; font-family: monospace;}}
    .legend-box {{background:#fafafa; border:1px solid #eee; padding:8px 12px; border-radius:6px; margin:12px 0;}}
    .sort-controls {{margin: 8px 0;}}
</style>
</head>
<body>
<h1>Report Vulnerabilità</h1>
{summary_table}
<div class='legend-box'>
  <h2>Legenda</h2>
  <p><strong>Severità:</strong>
     <span class='severity-Cell' style='background:#FF0000'>Critical</span> (CVSS ≥ 9.0) •
     <span class='severity-Cell' style='background:#FF8C00'>High</span> (7.0–8.9) •
     <span class='severity-Cell' style='background:#FFD700'>Medium</span> (4.0–6.9) •
     <span class='severity-Cell' style='background:#32CD32'>Low</span> (0.1–3.9) •
     <span class='severity-Cell' style='background:#808080'>Info</span> (senza punteggio)
  </p>
  <p><strong>Host:</strong> mostrato come <em>hostname</em> <code class='ip-badge'>IP</code>. Se l'hostname non è disponibile, viene mostrato solo l'<code class='ip-badge'>IP</code>.</p>
</div>
{host_summary}
<h2>Distribuzione severità globale</h2>
<canvas id="severityChart"></canvas>
<h2>Vulnerabilità per host (ordinate)</h2>
<canvas id="hostChart"></canvas>
<h2>Dettagli CVE</h2>
<div class="severity-filter">
Filtra per severità:
{''.join([f'<label><input type="checkbox" class="sev-filter" value="{sev}" checked> {sev}</label> ' for sev in severity_count])}
</div>
<div class="sort-controls">
  Ordina per:
  <select id="sortMode">
    <option value="severity">Severità</option>
    <option value="port">Porta</option>
    <option value="cve">CVE</option>
    <option value="host">Host</option>
  </select>
  <label><input type="checkbox" id="sortDesc"> Discendente</label>
</div>
<table>
<thead>
<tr><th>Host (hostname/IP)</th><th>Porta</th><th>Servizio</th><th>CVE</th><th>Severità</th><th>Descrizione</th></tr>
</thead>
<tbody id="cveBody">
"""

    # Tabella CVE dettagliata
    for ip, info in host_data.items():
        for cve in info['cves']:
            sev_class = f"sev-{cve['severity']}"
            color = severity_colors.get(cve['severity'], '#808080')
            port = cve.get('port', '-')
            svc_meta = info['services'].get(port, {})
            svc_str = " ".join(filter(None, [svc_meta.get('name',''), svc_meta.get('product',''), svc_meta.get('version','')])).strip() or '-'
            cve_id = cve['id']
            mitre = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            nvd   = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            SEV_ORDER = {'Critical':0,'High':1,'Medium':2,'Low':3,'Info':4}
            sev_rank = SEV_ORDER.get(cve['severity'], 4)
            host_sort = info.get('hostname') or ip
            try:
                port_num = int(str(port).split('/')[0])
            except Exception:
                port_num = 65535
            html_content += (
                f"<tr class='cve-row {sev_class}' data-sev='{sev_rank}' data-port='{port_num}' data-cve='{cve_id}' data-host='{html.escape(host_sort)}'>"
                f"<td>{host_label(ip, info)}</td>"
                f"<td>{port}</td>"
                f"<td>{html.escape(svc_str)}</td>"
                f"<td><a href='{mitre}' target='_blank'>{cve_id}</a> | <a href='{nvd}' target='_blank'>NVD</a></td>"
                f"<td><span class='severity-Cell' style='background:{color}'>{cve['severity']}</span></td>"
                f"<td>{cve['description']}</td>"
                "</tr>"
            )

    html_content += "</tbody></table>"

    # Script: usa JSON per evitare graffe problematiche
    html_content += f"""
<script>
const severityCtx = document.getElementById('severityChart').getContext('2d');
new Chart(severityCtx, {{
    type: 'pie',
    data: {{
        labels: {severity_labels_js},
        datasets: [{{data: {severity_values_js}, backgroundColor: {severity_colors_js}}}]
    }},
    options: {{responsive: true, plugins: {{ legend: {{ position: 'bottom' }}, title: {{ display: true, text: 'Distribuzione per severità' }}, tooltip: {{ callbacks: {{ label: function(ctx) {{ return ctx.label + ': ' + ctx.parsed + ' vulnerabilità'; }} }} }} }}}}
}});
const hostCtx = document.getElementById('hostChart').getContext('2d');
new Chart(hostCtx, {{
    type: 'bar',
    data: {{
        labels: {host_labels_js},
        datasets: [{{label: 'Numero vulnerabilità', data: {host_values_js}}}]
    }},
    options: {{responsive: true, scales: {{ x: {{ title: {{ display: true, text: 'Host' }} }}, y: {{ beginAtZero: true, ticks: {{ precision: 0, stepSize: 1 }}, title: {{ display: true, text: 'Numero vulnerabilità' }} }} }}, plugins: {{ legend: {{ display: false }}, title: {{ display: true, text: 'Vulnerabilità per host' }}, tooltip: {{ callbacks: {{ label: function(ctx) {{ return ctx.parsed.y + ' vulnerabilità'; }} }} }} }}}}
}});
const checkboxes = document.querySelectorAll('.sev-filter');
function applyFilter() {{
    const checkedSev = Array.from(checkboxes).filter(c=>c.checked).map(c=>c.value);
    document.querySelectorAll('.cve-row').forEach(row => {{
        const match = checkedSev.some(sev => row.classList.contains('sev-' + sev));
        row.style.display = match ? '' : 'none';
    }});
}}
checkboxes.forEach(cb => cb.addEventListener('change', applyFilter));

// Ordinamento CVE
const sortMode = document.getElementById('sortMode');
const sortDesc = document.getElementById('sortDesc');
function applySort() {{
    const tbody = document.getElementById('cveBody');
    if (!tbody) return;
    const rows = Array.from(tbody.querySelectorAll('tr.cve-row'));
    const mode = (sortMode && sortMode.value) || 'severity';
    const desc = !!(sortDesc && sortDesc.checked);
    const keyFns = {{
        severity: r => parseInt(r.dataset.sev || '4', 10),
        port: r => parseInt(r.dataset.port || '65535', 10),
        cve: r => (r.dataset.cve || ''),
        host: r => (r.dataset.host || '')
    }};
    const keyFn = keyFns[mode] || keyFns.severity;
    rows.sort((a,b)=>{{
        const ka = keyFn(a), kb = keyFn(b);
        if (ka < kb) return desc ? 1 : -1;
        if (ka > kb) return desc ? -1 : 1;
        const ca = (a.dataset.cve||'');
        const cb = (b.dataset.cve||'');
        if (ca < cb) return desc ? 1 : -1;
        if (ca > cb) return desc ? -1 : 1;
        return 0;
    }});
    rows.forEach(r => tbody.appendChild(r));
}}
if (sortMode) sortMode.addEventListener('change', applySort);
if (sortDesc) sortDesc.addEventListener('change', applySort);
applyFilter();
applySort();
</script>
</body></html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[*] Report HTML generato: {output_file}")

def save_json_report(xml_file, output_file="report.json"):
    data = parse_nmap_xml(xml_file)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"[*] Report JSON generato: {output_file}")

def save_csv_report(xml_file, output_file="report.csv"):
    data = parse_nmap_xml(xml_file)
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "port", "service", "cve", "severity", "description"])
        for ip, info in data.items():
            for c in info["cves"]:
                svc = info["services"].get(c.get("port", "-"), {})
                svc_str = " ".join(filter(None, [svc.get('name',''), svc.get('product',''), svc.get('version','')])) or "-"
                w.writerow([ip, c.get("port", "-"), svc_str, c["id"], c["severity"], html.unescape(c["description"])])
    print(f"[*] Report CSV generato: {output_file}")

# ---------------------- BANNER ----------------------
def print_banner():
    print("""
=========================================
        Nmap Vulnerability Scanner Pro
            Created by: grayf0x
               Version: 1.3
=========================================
""")

# ---------------------- ARGPARSE ----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Nmap Vulnerability Scanner Pro")
    p.add_argument("target", nargs="?", help="IP o hostname da scansionare")
    p.add_argument("-p", "--profile", choices=["1", "2", "3", "4"],
                   help="Profilo di scansione (1=Rapida,2=Standard,3=Approfondita,4=Completa)")
    p.add_argument("-a", "--alias", default=None, help="Alias del target (default: derivato dal target)")
    p.add_argument("-o", "--outdir", default=None, help="Directory base report (default: reports/<Profilo>)")
    p.add_argument("--no-update", action="store_true", help="Non aggiornare/installa script NSE")
    p.add_argument("--vm-safe", action="store_true", help="Forza impostazioni gentili per VM")
    return p.parse_args()

def choose_profile_interactive(default="2"):
    print("""Profilo di scansione:
1) Rapida
2) Standard
3) Approfondita
4) Completa""")
    while True:
        sel = input(f"Scegli profilo (1-4) [{default}]: ").strip() or default
        if sel in ("1", "2", "3", "4"):
            return sel
        print("[!] Valore non valido. Riprova.")

# ---------------------- MAIN ----------------------
def main():
    # Root check
    if os.geteuid() != 0:
        print("[!] Lo script richiede privilegi di root. Usa 'sudo'.")
        sys.exit(1)

    print_banner()
    args = parse_args()

    target = args.target or input("Inserisci IP o hostname da scansionare: ").strip()
    if not validate_target(target):
        print("[!] Target non valido.")
        sys.exit(1)

    alias_input = args.alias
    if alias_input is None:
        alias_input = input("Vuoi assegnare un nome descrittivo al target (es. server01)? [Invio per saltare]: ").strip()
    alias = re.sub(r'[^a-zA-Z0-9_-]', '_', alias_input) if alias_input else target.replace(".", "_")

    profile = args.profile
    if not profile:
        if sys.stdin.isatty():
            profile = choose_profile_interactive()
        else:
            profile = "2"  # default in non-interattivo/CI
    profile_names = {"1": "Rapida", "2": "Standard", "3": "Approfondita", "4": "Completa"}
    profile_name = profile_names.get(profile, "Standard")

    if not args.no_update:
        check_dependencies()
        update_vulscan_db()
        update_vulners()
        update_nmap_scripts()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:6]

    reports_dir = args.outdir or os.path.join("reports", profile_name)
    os.makedirs(reports_dir, exist_ok=True)

    output_xml = os.path.join(reports_dir, f"scan_{alias}_{timestamp}_{unique_id}.xml")
    output_html = os.path.join(reports_dir, f"report_{alias}_{timestamp}_{unique_id}.html")
    output_json = os.path.join(reports_dir, f"report_{alias}_{timestamp}_{unique_id}.json")
    output_csv = os.path.join(reports_dir, f"report_{alias}_{timestamp}_{unique_id}.csv")
    output_log = os.path.join(reports_dir, f"scan_{alias}_{timestamp}_{unique_id}.log")

    cmd = build_nmap_command(target, profile, output_xml, vm_safe=args.vm_safe)
    print(f"[*] Avvio scansione Nmap sul target {target} ({alias}) con profilo {profile_name}...")

    start_time = time.time()
    try:
        with open(output_log, 'w', encoding='utf-8') as logf:
            logf.write(f"Comando: {' '.join(cmd)}\n")
            logf.write(f"Inizio: {datetime.now().isoformat()}\n")
            subprocess.run(cmd, check=True)
            logf.write(f"Fine: {datetime.now().isoformat()}\n")
    except KeyboardInterrupt:
        print("\n[!] Interrotto dall'utente.")
        sys.exit(130)
    except subprocess.CalledProcessError as e:
        print(f"[!] Errore durante la scansione: {e}")
        sys.exit(1)

    # Generazione report
    generate_html_report_from_xml(output_xml, output_html)
    save_json_report(output_xml, output_json)
    save_csv_report(output_xml, output_csv)

    elapsed = time.time() - start_time
    minutes, seconds = divmod(int(elapsed), 60)
    print(f"[*] Tempo impiegato per la scansione: {minutes}m {seconds}s")

    print("[*] Report salvati in:")
    print("   HTML:", os.path.abspath(output_html))
    print("   JSON:", os.path.abspath(output_json))
    print("   CSV :", os.path.abspath(output_csv))
    print("   LOG :", os.path.abspath(output_log))

if __name__ == "__main__":
    main()
