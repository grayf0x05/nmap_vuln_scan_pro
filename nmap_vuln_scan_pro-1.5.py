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
import ipaddress
import tempfile

# ---------------------- PERCORSI / PATH DETECTION ----------------------
def _default_script_dir():
    candidates = [
        "/usr/share/nmap/scripts",
        "/usr/local/share/nmap/scripts",
        "/opt/homebrew/share/nmap/scripts",  # macOS (brew)
    ]
    # Fallback: cerca dentro il Cellar nmap di Homebrew
    cellar = "/opt/homebrew/Cellar/nmap"
    if os.path.isdir(cellar):
        for root, dirs, files in os.walk(cellar):
            if root.endswith("/share/nmap/scripts"):
                candidates.insert(0, root)
                break
    for base in candidates:
        if os.path.isdir(base):
            return base
    return "/usr/share/nmap/scripts"

SCRIPTS_BASE = _default_script_dir()
VULSCAN_PATH = os.path.join(SCRIPTS_BASE, "vulscan")
VULNERS_PATH = os.path.join(SCRIPTS_BASE, "vulners")

# Fallback per utente non root / dir non scrivibile
USER_SCRIPTS_BASE = os.path.expanduser("~/.local/share/nmap/scripts")

def _ensure_scripts_base_writable():
    """
    Ritorna una directory scrivibile per gli script NSE.
    Se SCRIPTS_BASE non è scrivibile, usa ~/.local/share/nmap/scripts.
    """
    base = SCRIPTS_BASE
    if not os.access(base, os.W_OK):
        os.makedirs(USER_SCRIPTS_BASE, exist_ok=True)
        print(f"[*] Directory script non scrivibile ({base}), uso fallback: {USER_SCRIPTS_BASE}")
        return USER_SCRIPTS_BASE
    return base

# ---------------------- VALIDAZIONE TARGET ----------------------
HOSTNAME_REGEX = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")

def validate_target(target: str) -> bool:
    if not target or len(target) > 253:
        return False
    t = target.strip("[]")  # consenti input tipo [2001:db8::1]
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return bool(HOSTNAME_REGEX.match(target))

def _normalize_target_for_nmap(t: str) -> str:
    """
    Nmap non accetta target IPv6 racchiusi tra [] come nelle URL.
    Rimuovi eventuali parentesi.
    """
    t = t.strip()
    if t.startswith("[") and t.endswith("]"):
        return t[1:-1]
    return t

# ---------------------- DIPENDENZE ----------------------
def detect_pkg_manager():
    for pm in ["apt", "dnf", "yum", "pacman", "apk"]:
        if shutil.which(pm):
            return pm
    return None

def install_dependencies(tools):
    system_platform = platform.system()
    print("[*] Installazione delle dipendenze mancanti...")
    use_sudo = False
    if os.name == "posix":
        try:
            use_sudo = (os.geteuid() != 0) and bool(shutil.which("sudo"))
        except AttributeError:
            use_sudo = bool(shutil.which("sudo"))
    # Hardening: se non root e senza sudo, fermati con messaggio chiaro
    if os.name == "posix" and not use_sudo:
        try:
            if os.geteuid() != 0:
                print("[!] Permessi insufficienti e 'sudo' assente: esegui come root oppure installa manualmente:", ", ".join(tools))
                sys.exit(1)
        except AttributeError:
            pass

    def cmd_with_sudo(*args):
        return (["sudo"] if use_sudo else []) + list(args)

    if system_platform == "Linux":
        pm = detect_pkg_manager()
        if not pm:
            print(f"[!] Package manager non trovato. Installa manualmente: {', '.join(tools)}")
            sys.exit(1)
        if pm == "apt":
            subprocess.run(cmd_with_sudo(pm, "update"), check=True)
            subprocess.run(cmd_with_sudo(pm, "install", "-y", *tools), check=True)
        elif pm in ("dnf", "yum"):
            subprocess.run(cmd_with_sudo(pm, "-y", "install", *tools), check=True)
        elif pm == "pacman":
            subprocess.run(cmd_with_sudo(pm, "-Sy", "--needed", *tools), check=True)
        elif pm == "apk":
            subprocess.run(cmd_with_sudo(pm, "add", *tools), check=True)
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
    required_tools = ["nmap", "git", "curl", "wget"]
    missing = [t for t in required_tools if not shutil.which(t)]
    if missing:
        print(f"[!] Dipendenze mancanti: {', '.join(missing)}")
        install_dependencies(missing)
    else:
        print("[*] Tutte le dipendenze sono presenti.")

# ---------------------- ESECUZIONE: STREAMING / QUIET ----------------------
def run_streamed_and_tee(cmd, log_path, cwd=None):
    """
    Mostra l'output in tempo reale e lo scrive nel log.
    """
    start_iso = datetime.now().isoformat()
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, 'w', encoding='utf-8') as logf:
        logf.write(f"Comando: {' '.join(cmd)}\n")
        logf.write(f"Inizio: {start_iso}\n\n")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=cwd
    )
    try:
        with open(log_path, 'a', encoding='utf-8') as logf:
            assert proc.stdout is not None
            for line in proc.stdout:
                print(line, end='')
                logf.write(line)
        rc = proc.wait()
    except KeyboardInterrupt:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        raise
    finally:
        with open(log_path, 'a', encoding='utf-8') as logf:
            logf.write(f"\nFine: {datetime.now().isoformat()}\n")
    if rc != 0:
        raise subprocess.CalledProcessError(rc, cmd)

def run_quiet_with_dots(cmd, log_path, label="", cwd=None):
    """
    Esegue un comando in QUIET: redireziona stdout/stderr su log e mostra solo dei puntini.
    """
    start_iso = datetime.now().isoformat()
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, 'a', encoding='utf-8') as logf:
        logf.write(f"[{start_iso}] {' '.join(cmd)}\n")
    print(f"[*] {label} (log: {log_path}) ", end='', flush=True)
    with open(log_path, 'a', encoding='utf-8') as logf:
        proc = subprocess.Popen(cmd, stdout=logf, stderr=logf, text=True, cwd=cwd)
        try:
            while proc.poll() is None:
                print(".", end='', flush=True)
                time.sleep(0.5)
        except KeyboardInterrupt:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
            print(" interrotto")
            raise
    if proc.returncode != 0:
        print(" errore")
        raise subprocess.CalledProcessError(proc.returncode, cmd)
    print(" fatto")

# ---------------------- GIT UTILS ----------------------
def _is_git_repo(path: str) -> bool:
    try:
        subprocess.run(["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def git_clone_or_pull(repo_url: str, dest_path: str, verbose_updates: bool, updates_log: str):
    parent = os.path.dirname(dest_path.rstrip("/"))
    os.makedirs(parent, exist_ok=True)

    if os.path.isdir(dest_path):
        if _is_git_repo(dest_path):
            cmd = ["git", "-C", dest_path, "pull", "--ff-only", "-q"]
            if verbose_updates:
                run_streamed_and_tee(cmd, updates_log)
            else:
                run_quiet_with_dots(cmd, updates_log, label=f"git pull {os.path.basename(dest_path)}")
        else:
            tmp = tempfile.mkdtemp(prefix=os.path.basename(dest_path.rstrip("/")) + "_tmp_")
            try:
                cmd = ["git", "clone", "--depth", "1", "-q", repo_url, tmp]
                if verbose_updates:
                    run_streamed_and_tee(cmd, updates_log)
                else:
                    run_quiet_with_dots(cmd, updates_log, label=f"git clone {os.path.basename(dest_path)}")
                # pulizia e sostituzione
                for name in os.listdir(dest_path):
                    p = os.path.join(dest_path, name)
                    shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.remove(p)
                for name in os.listdir(tmp):
                    shutil.move(os.path.join(tmp, name), os.path.join(dest_path, name))
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
    else:
        cmd = ["git", "clone", "--depth", "1", "-q", repo_url, dest_path]
        if verbose_updates:
            run_streamed_and_tee(cmd, updates_log)
        else:
            run_quiet_with_dots(cmd, updates_log, label=f"git clone {os.path.basename(dest_path)}")

# ---------------------- AGGIORNAMENTO SCRIPT NSE ----------------------
def update_vulscan_db(verbose_updates: bool, updates_log: str):
    print("[*] Aggiornamento Vulscan...")
    writable_base = _ensure_scripts_base_writable()
    vulscan_dest = os.path.join(writable_base, "vulscan")
    git_clone_or_pull("https://github.com/scipag/vulscan.git", vulscan_dest, verbose_updates, updates_log)
    update_sh = os.path.join(vulscan_dest, "update.sh")
    update_files_sh = os.path.join(vulscan_dest, "utilities", "updater", "updateFiles.sh")
    try:
        if os.path.exists(update_sh):
            cmd = ["bash", update_sh]
            if verbose_updates:
                run_streamed_and_tee(cmd, updates_log, cwd=vulscan_dest)
            else:
                run_quiet_with_dots(cmd, updates_log, label="vulscan update.sh", cwd=vulscan_dest)
        elif os.path.exists(update_files_sh):
            cmd = ["bash", update_files_sh]
            if verbose_updates:
                run_streamed_and_tee(cmd, updates_log, cwd=os.path.dirname(update_files_sh))
            else:
                run_quiet_with_dots(cmd, updates_log, label="vulscan updateFiles.sh", cwd=os.path.dirname(update_files_sh))
        else:
            print("[*] Nessuno script di update vulscan trovato (ok).")
    except subprocess.CalledProcessError:
        print("[!] Errore durante l'aggiornamento dei database Vulscan (vedi log).")

def update_vulners(verbose_updates: bool, updates_log: str):
    print("[*] Aggiornamento Vulners...")
    writable_base = _ensure_scripts_base_writable()
    vulners_dest = os.path.join(writable_base, "vulners")
    git_clone_or_pull("https://github.com/vulnersCom/nmap-vulners.git", vulners_dest, verbose_updates, updates_log)

def update_nmap_scripts(verbose_updates: bool, updates_log: str):
    # Controlla che la directory sia scrivibile (soprattutto su macOS con brew)
    if not os.access(SCRIPTS_BASE, os.W_OK):
        print(f"[!] Directory non scrivibile: {SCRIPTS_BASE}. Salto --script-updatedb.")
        return
    cmd = ["nmap", "--script-updatedb"]
    if verbose_updates:
        run_streamed_and_tee(cmd, updates_log)
    else:
        run_quiet_with_dots(cmd, updates_log, label="nmap --script-updatedb")

# ---------------------- COSTRUZIONE COMANDO NMAP ----------------------
SAFE_NSE = re.compile(r"^[A-Za-z0-9_\-\*/\.]+$")

def build_nmap_command(
    target,
    profile,
    output_xml,
    vm_safe=True,
    ports=None,
    extra_scripts=None,
    rate=None,
    oabase=None,
    force_connect_scan=False,  # mantenuto per compatibilità, ma non usato perché richiediamo root
    scripts_base=None
):
    # Se abbiamo una base esplicita (fallback utente), referenzia gli script con path completo
    if scripts_base:
        scripts = []
        # 'vuln' è built-in: lo aggiungiamo comunque come nome semplice
        scripts.append("vuln")
        scripts.append(os.path.join(scripts_base, "vulners"))
        scripts.append(os.path.join(scripts_base, "vulscan", "vulscan"))
    else:
        scripts = ["vuln", "vulners", "vulscan/vulscan"]
    extra_flags = ["--stats-every", "5s"]

    # Profili
    if profile == "1":
        # Rapida
        extra_flags += ["-T3", "--top-ports", "100"]
    elif profile == "2":
        # Standard
        scripts += ["ssl-cert", "ssl-enum-ciphers", "smb-vuln*", "ftp-anon"]
        extra_flags += ["-T3", "-p1-1000", "--version-all"]
    elif profile == "3":
        # Approfondita (usiamo -sS: richiede root e lo imponiamo in main)
        scripts += ["default", "safe", "ssl-cert", "ssl-enum-ciphers"]
        extra_flags += [
            "-sS", "-p1-1024",
            "-T3", "--version-all",
            "--script-timeout", "5m"
        ]
    elif profile == "4":
        # Completa (usiamo -sS)
        scripts += ["default", "safe", "auth", "discovery", "ssl-cert", "ssl-enum-ciphers"]
        extra_flags += [
            "-sS", "-p1-2048",
            "-T3", "--version-all",
            "--script-timeout", "5m"
        ]

    # Extra NSE, sanificati
    if extra_scripts:
        for s in extra_scripts.split(","):
            s = s.strip()
            if s and SAFE_NSE.match(s):
                scripts.append(s)
            elif s:
                print(f"[!] Script NSE non valido e ignorato: {s}")

    # Throttle
    if vm_safe:
        extra_flags += ["--max-rate", str(rate if rate else 300)]
    elif rate:
        extra_flags += ["--max-rate", str(rate)]

    base = ["nmap", "-sV", "--script", ",".join(scripts)]
    if ports:
        base += ["-p", ports]

    cmd = base + ["-oX", output_xml]
    if oabase:
        cmd += ["-oA", oabase]

    # ⚠️ importante: opzioni PRIMA del target
    cmd += extra_flags + [target]
    return cmd

# ---------------------- PARSING XML / REPORT ----------------------
CVE_REGEX = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)
SEVERITY_REGEX = re.compile(r"Severity:\s*(Critical|High|Medium|Low|Info)", re.IGNORECASE)
CVSS_REGEX = re.compile(r"CVSS[:\s]*(?:v3[\.\d]*)?[:\s]*([0-9]{1,2}\.[0-9]{1,2})", re.IGNORECASE)
CVSS_V31_REGEX = re.compile(r"CVSS\s*v?3(?:\.\d)?[:\s]*([0-9]{1,2}\.[0-9]{1,2})", re.IGNORECASE)
CVSS_AFTER_CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}\s+([0-9]{1,2}\.[0-9]{1,2})")
SEVERITY_WORDS_REGEX = re.compile(r"\b(Critical|High|Medium|Low)\b", re.IGNORECASE)

SEV_BUCKETS = {
    'critical': (9.0, 10.0),
    'high':     (7.0, 8.9),
    'medium':   (4.0, 6.9),
    'low':      (0.0, 3.9)  # include 0.0
}
SEV_ORDER = {'Critical':0,'High':1,'Medium':2,'Low':3,'Info':4}

def _cvss_to_severity(cvss: float) -> str:
    if cvss is None:
        return 'Info'
    for sev, (lo, hi) in SEV_BUCKETS.items():
        if lo <= cvss <= hi:
            return sev.capitalize()
    return 'Info'

def _extract_structured_cves(script_elem):
    pairs = []
    for tbl in script_elem.findall('.//table'):
        row = {}
        for e in tbl.findall('elem'):
            k = (e.get('key') or '').lower()
            row[k] = (e.text or '').strip()
        cve_id = None
        for v in list(row.values()):
            m = CVE_REGEX.search(v or '')
            if m:
                cve_id = m.group(1).upper()
                break
        if not cve_id:
            continue
        cvss = None
        for k, v in row.items():
            if 'cvss' in k or 'score' in k:
                m = re.search(r'([0-9]{1,2}\.[0-9]{1,2})', v or '')
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
    for host in root.iterfind('host'):
        ip = next((a.get('addr') for a in host.findall('address') if a.get('addrtype') in ('ipv4', 'ipv6')), None)
        if not ip:
            continue

        info = {'ports': [], 'services': {}, 'cves': [], 'hostname': ''}

        names = [hn.get('name') for hn in host.findall('hostnames/hostname') if hn.get('name')]
        if names:
            info['hostname'] = names[0]

        seen = set()

        for p in host.iterfind('ports/port'):
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
                # Structured tables
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
                # Unstructured lines
                output = s.get('output', '') or ''
                for line in output.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    cves = CVE_REGEX.findall(line)
                    cvss_match = (CVSS_REGEX.search(line) or
                                  CVSS_V31_REGEX.search(line) or
                                  CVSS_AFTER_CVE_REGEX.search(line))
                    sev_match = SEVERITY_REGEX.search(line) or SEVERITY_WORDS_REGEX.search(line)

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

        # hostscript level
        for s in host.findall('hostscript/script'):
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
            output = s.get('output', '') or ''
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                cves = CVE_REGEX.findall(line)
                cvss_match = (CVSS_REGEX.search(line) or
                              CVSS_V31_REGEX.search(line) or
                              CVSS_AFTER_CVE_REGEX.search(line))
                sev_match = SEVERITY_REGEX.search(line) or SEVERITY_WORDS_REGEX.search(line)

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

        info['cves'].sort(key=lambda c: (SEV_ORDER.get(c.get('severity','Info'),4), c.get('id','')))
        host_data[ip] = info

    return host_data

# ---------------------- REPORT: HTML/JSON/CSV (da dati già parsati) ----------------------
def generate_html_report_from_data(host_data, output_file="report.html"):
    severity_colors = {
        'Critical': '#FF0000',
        'High': '#FF8C00',
        'Medium': '#FFD700',
        'Low': '#32CD32',
        'Info': '#808080'
    }

    ordered_sev = ["Critical","High","Medium","Low","Info"]

    def host_label(ip, info):
        hn = info.get('hostname') or ''
        if hn and hn != ip:
            safe_hn = html.escape(hn)
            return f"<span title='{safe_hn}'>{safe_hn}</span> <code class='ip-badge'>{ip}</code>"
        return f"<code class='ip-badge'>{ip}</code>"

    severity_count = {k: 0 for k in ordered_sev}
    for info in host_data.values():
        for cve in info['cves']:
            severity_count[cve.get('severity', 'Info')] = severity_count.get(cve.get('severity', 'Info'), 0) + 1

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

    severity_labels_js = json.dumps(ordered_sev)
    severity_values_js = json.dumps([severity_count[k] for k in ordered_sev])
    severity_colors_js = json.dumps([severity_colors[k] for k in ordered_sev])

    html_content = f"""
<html>
<head>
    <meta charset="utf-8">
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
    /* canvas più grande per migliorare la leggibilità */
    #severityChart {{width: 760px !important;height: 460px !important; max-width: 100%;}}
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
<h2>Distribuzione severità globale</h2>
<canvas id="severityChart" role="img" aria-label="Distribuzione vulnerabilità per severità"></canvas>
<noscript><p>Abilita JavaScript per visualizzare il grafico delle severità.</p></noscript>
{host_summary}
<h2>Dettagli CVE</h2>
<div class="severity-filter">
Filtra per severità:
{''.join([f'<label><input type="checkbox" class="sev-filter" value="{sev}" checked> {sev}</label> ' for sev in ordered_sev])}
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

    for ip, info in host_data.items():
        for cve in info['cves']:
            color = severity_colors.get(cve['severity'], '#808080')
            port = cve.get('port', '-')
            svc_meta = info['services'].get(port, {})
            svc_str = " ".join(filter(None, [svc_meta.get('name',''), svc_meta.get('product',''), svc_meta.get('version','')])).strip() or '-'
            cve_id = cve['id']
            mitre = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            nvd   = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            sev_rank = SEV_ORDER.get(cve['severity'], 4)
            host_sort = info.get('hostname') or ip
            try:
                port_num = int(str(port).split('/')[0])
            except Exception:
                port_num = 65535
            html_content += (
                f"<tr class='cve-row sev-{cve['severity']}' data-sev='{sev_rank}' data-port='{port_num}' data-cve='{cve_id}' data-host='{html.escape(host_sort)}'>"
                f"<td>{host_label(ip, info)}</td>"
                f"<td>{port}</td>"
                f"<td title='{html.escape(svc_str)}'>{html.escape(svc_str)}</td>"
                f"<td><a href='{mitre}' target='_blank' rel='noopener noreferrer'>{cve_id}</a> | <a href='{nvd}' target='_blank' rel='noopener noreferrer'>NVD</a></td>"
                f"<td><span class='severity-Cell' style='background:{color}'>{cve['severity']}</span></td>"
                f"<td>{cve['description']}</td>"
                "</tr>"
            )

    html_content += "</tbody></table>"

    html_content += f"""
<script>
const severityCtx = document.getElementById('severityChart').getContext('2d');
new Chart(severityCtx, {{
    type: 'pie',
    data: {{
        labels: {severity_labels_js},
        datasets: [{{data: {severity_values_js}, backgroundColor: {severity_colors_js}}}]
    }},
    options: {{
        responsive: true,
        layout: {{ padding: 12 }},
        plugins: {{
            legend: {{
                position: 'right',
                labels: {{
                    font: {{ size: 14 }},
                    boxWidth: 18,
                    boxHeight: 18,
                    padding: 16
                }}
            }},
            title: {{
                display: true,
                text: 'Distribuzione per severità',
                font: {{ size: 18 }}
            }},
            tooltip: {{
                callbacks: {{
                    label: function(ctx) {{
                        return ctx.label + ': ' + ctx.parsed + ' vulnerabilità';
                    }}
                }}
            }}
        }}
    }}
}});

// Filtri severità tabella
const checkboxes = document.querySelectorAll('.sev-filter');
function applyFilter() {{
    const checkedSev = Array.from(checkboxes).filter(c=>c.checked).map(c=>c.value);
    document.querySelectorAll('.cve-row').forEach(row => {{
        const match = checkedSev.some(sev => row.classList.contains('sev-' + sev));
        row.style.display = match ? '' : 'none';
    }});
}}
checkboxes.forEach(cb => cb.addEventListener('change', applyFilter));

// Ordinamenti tabella
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

def save_json_report_from_data(data, output_file="report.json"):
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"[*] Report JSON generato: {output_file}")

def save_csv_report_from_data(data, output_file="report.csv"):
    def _csv_sanitize(s: str) -> str:
        if s and s[0] in ("=", "+", "-", "@"):
            return "'" + s
        return s

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "port", "service", "cve", "severity", "description"])
        for ip, info in data.items():
            for c in info["cves"]:
                svc = info["services"].get(c.get("port", "-"), {})
                svc_str = " ".join(filter(None, [svc.get('name',''), svc.get('product',''), svc.get('version','')])) or "-"
                desc = html.unescape(c["description"])
                if len(desc) > 2000:
                    desc = desc[:2000] + "…"
                w.writerow([
                    _csv_sanitize(ip),
                    c.get("port", "-"),
                    _csv_sanitize(svc_str),
                    c["id"],
                    c["severity"],
                    _csv_sanitize(desc)
                ])
    print(f"[*] Report CSV generato: {output_file}")

# ---------------------- VULN-ONLY SECOND PASS ----------------------
def run_vuln_only_pass(data, target, alias, reports_dir, vm_safe=True, rate=None, force_connect_scan=False):
    """
    Secondo passaggio focalizzato: esegue solo gli script di vulnerabilità
    sulle porte già trovate aperte nel primo scan.
    """
    # Raccogli le porte aperte dal primo pass
    open_ports = []
    for info in data.values():
        open_ports.extend(info.get("ports", []))

    if not open_ports:
        print("[*] Nessuna porta aperta trovata: salto vuln-only pass.")
        return

    # Converte "22/tcp","80/tcp" -> "22,80"
    port_list = ",".join(sorted(set(p.split("/")[0] for p in open_ports if "/" in p)))

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:6]

    output_xml = os.path.join(reports_dir, f"vulnpass_{alias}_{timestamp}_{unique_id}.xml")
    output_html = os.path.join(reports_dir, f"vulnpass_{alias}_{timestamp}_{unique_id}.html")
    output_json = os.path.join(reports_dir, f"vulnpass_{alias}_{timestamp}_{unique_id}.json")
    output_csv  = os.path.join(reports_dir, f"vulnpass_{alias}_{timestamp}_{unique_id}.csv")
    output_log  = os.path.join(reports_dir, f"vulnpass_{alias}_{timestamp}_{unique_id}.log")
    oabase      = os.path.join(reports_dir, f"vulnpass_{alias}_{timestamp}_{unique_id}")

    scripts = ["vuln", "vulners", "vulscan/vulscan"]
    # Richiediamo root: usiamo -sS
    scan_flag = "-sS"

    # Costruisci il comando "snello"
    cmd = [
        "nmap",
        "-sV",
        "--script", ",".join(scripts),
        "-p", port_list,
        "-oX", output_xml,
        "-oA", oabase,
        "--stats-every", "5s",
        scan_flag,
        "-T3",
        "--version-all",
        "--script-timeout", "5m",
    ]
    if vm_safe:
        cmd += ["--max-rate", str(rate if rate else 500)]
    elif rate:
        cmd += ["--max-rate", str(rate)]

    cmd += [target]

    print(f"[*] Avvio vuln-only pass sulle porte: {port_list}")
    try:
        run_streamed_and_tee(cmd, output_log)
    except KeyboardInterrupt:
        print("\n[!] Vuln-only pass interrotto dall'utente.")
        return
    except subprocess.CalledProcessError as e:
        print(f"[!] Errore vuln-only pass (rc {e.returncode}).")
        return

    # Parsing e report del secondo pass
    vuln_data = parse_nmap_xml(output_xml)
    generate_html_report_from_data(vuln_data, output_html)
    save_json_report_from_data(vuln_data, output_json)
    save_csv_report_from_data(vuln_data, output_csv)

    print("[*] Vuln-only pass completato. Report salvati in:")
    print("   HTML:", os.path.abspath(output_html))
    print("   JSON:", os.path.abspath(output_json))
    print("   CSV :", os.path.abspath(output_csv))
    print("   LOG :", os.path.abspath(output_log))

# ====================== BANNER ======================
def print_banner():
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    print(f"""{CYAN}{BOLD}
=========================================
        \033[91mNmap Vulnerability Scanner Pro\033[0m{CYAN}{BOLD}
            {GREEN}Created by: grayf0x{RESET}{CYAN}{BOLD}
               {YELLOW}Version: 1.5{RESET}{CYAN}{BOLD}
========================================={RESET}
""")

# ---------------------- ARGPARSE ----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Nmap Vulnerability Scanner Pro")
    p.add_argument("target", nargs="?", help="IP/IPv6 o hostname da scansionare")
    p.add_argument("-p", "--profile", choices=["1", "2", "3", "4"],
                   help="Profilo di scansione (1=Rapida,2=Standard,3=Approfondita,4=Completa)")
    p.add_argument("-a", "--alias", default=None, help="Alias del target (default: derivato dal target)")
    p.add_argument("-o", "--outdir", default=None, help="Directory base report (default: reports/<Profilo>)")
    p.add_argument("--no-update", action="store_true", help="Non aggiornare/installa script NSE")
    p.add_argument("--no-vm-safe", action="store_true", help="Disabilita limitazioni gentili (--max-rate)")
    p.add_argument("--ports", default=None, help="Override porte (es. 1-1024,80,443)")
    p.add_argument("--scripts-extra", default=None, help="Script NSE extra separati da virgola")
    p.add_argument("--rate", type=int, default=None, help="Override --max-rate (pkt/s)")
    p.add_argument("--open-html", action="store_true", help="Apri il report HTML al termine")
    p.add_argument("--verbose-updates", action="store_true", help="Mostra output completo degli aggiornamenti iniziali")
    p.add_argument("--updates-log", default=None, help="Percorso file log per gli aggiornamenti (default: logs/updates_<ts>.log)")
    p.add_argument("--dry-run", action="store_true", help="Stampa il comando Nmap e termina")
    p.add_argument("--no-json", action="store_true", help="Non generare l'output JSON")
    p.add_argument("--no-csv", action="store_true", help="Non generare l'output CSV")
    p.add_argument("--no-html", action="store_true", help="Non generare l'output HTML")
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
    print_banner()
    args = parse_args()

    # === Check privilegi: richiede root ===
    if os.name == "posix":
        try:
            if os.geteuid() != 0:
                print("[!] Lo script richiede privilegi di root. Esegui con 'sudo'.")
                sys.exit(1)
        except AttributeError:
            pass

    target = args.target or input("Inserisci IP/IPv6 o hostname da scansionare: ").strip()
    if not validate_target(target):
        print("[!] Target non valido.")
        sys.exit(1)
    target = _normalize_target_for_nmap(target)

    alias_input = args.alias
    if alias_input is None:
        alias_input = input("Vuoi assegnare un nome descrittivo al target (es. server01)? [Invio per saltare]: ").strip()
    alias = re.sub(r'[^a-zA-Z0-9_-]', '_', alias_input) if alias_input else target.replace(".", "_").replace(":", "_")

    profile = args.profile
    if not profile:
        if sys.stdin.isatty():
            profile = choose_profile_interactive()
        else:
            profile = "2"
    profile_names = {"1": "Rapida", "2": "Standard", "3": "Approfondita", "4": "Completa"}
    profile_name = profile_names.get(profile, "Standard")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_id = uuid.uuid4().hex[:6]

    reports_dir = args.outdir or os.path.join("reports", profile_name)
    os.makedirs(reports_dir, exist_ok=True)

    # Log degli aggiornamenti (quiet)
    updates_log = args.updates_log or os.path.join("logs", f"updates_{timestamp}_{unique_id}.log")
    os.makedirs(os.path.dirname(updates_log), exist_ok=True)

    if not args.no_update:
        check_dependencies()
        update_vulscan_db(verbose_updates=args.verbose_updates, updates_log=updates_log)
        update_vulners(verbose_updates=args.verbose_updates, updates_log=updates_log)
        update_nmap_scripts(verbose_updates=args.verbose_updates, updates_log=updates_log)

    output_xml = os.path.join(reports_dir, f"scan_{alias}_{timestamp}_{unique_id}.xml")
    output_html = os.path.join(reports_dir, f"report_{alias}_{timestamp}_{unique_id}.html")
    output_json = os.path.join(reports_dir, f"report_{alias}_{timestamp}_{unique_id}.json")
    output_csv = os.path.join(reports_dir, f"report_{alias}_{timestamp}_{unique_id}.csv")
    output_log = os.path.join(reports_dir, f"scan_{alias}_{timestamp}_{unique_id}.log")
    oabase = os.path.join(reports_dir, f"scan_{alias}_{timestamp}_{unique_id}")

    # Forziamo -sS in profili 3/4: nessun fallback -sT (richiediamo root)
    force_connect = False  # mantenuto per compatibilità con firma funzione

    # Normalizza e valida --ports
    PORT_TOKEN = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")
    def _validate_ports_list(ports: str) -> bool:
        for tok in ports.split(","):
            m = PORT_TOKEN.match(tok)
            if not m: return False
            a, b = m.group(1), m.group(2)
            ai, bi = int(a), int(b) if b else int(a)
            if not (0 < ai <= 65535 and 0 < bi <= 65535 and ai <= bi):
                return False
        return True
    ports = args.ports.replace(" ", "") if args.ports else None
    if ports and not _validate_ports_list(ports):
        print("[!] Formato --ports non valido. Esempi: 1-1024,80,443")
        sys.exit(1)

    # Scegli base script scrivibile (serve anche per i path script nel comando)
    writable_base = _ensure_scripts_base_writable()

    cmd = build_nmap_command(
        target=target,
        profile=profile,
        output_xml=output_xml,
        vm_safe=not args.no_vm_safe,
        ports=ports,
        extra_scripts=args.scripts_extra,
        rate=args.rate,
        oabase=oabase,
        force_connect_scan=force_connect,
        scripts_base=writable_base if writable_base != SCRIPTS_BASE else None
    )

    print(f"[*] Comando Nmap: {' '.join(cmd)}")
    if args.dry_run:
        print("[*] Modalità --dry-run: esco senza eseguire la scansione.")
        print(f"[*] Output previsti in: {reports_dir}")
        print(f"    XML: {output_xml}")
        print(f"    HTML: {output_html}")
        print(f"    JSON: {output_json}")
        print(f"    CSV : {output_csv}")
        print(f"    LOG : {output_log}")
        sys.exit(0)

    print(f"[*] Avvio scansione Nmap sul target {target} ({alias}) con profilo {profile_name}...")
    start_time = time.time()

    try:
        run_streamed_and_tee(cmd, output_log)  # OUTPUT LIVE della scansione
    except KeyboardInterrupt:
        print("\n[!] Interrotto dall'utente.")
        sys.exit(130)
    except subprocess.CalledProcessError as e:
        print(f"[!] Errore durante la scansione (rc {e.returncode}).")
        sys.exit(1)

    # Parsing UNA SOLA VOLTA (primo pass)
    data = parse_nmap_xml(output_xml)

    # Generazione report richiesti (primo pass)
    if not args.no_html:
        generate_html_report_from_data(data, output_html)
    if not args.no_json:
        save_json_report_from_data(data, output_json)
    if not args.no_csv:
        save_csv_report_from_data(data, output_csv)

    # ===== vuln-only pass opzionale per profili 3/4 =====
    if profile in ("3", "4") and sys.stdin.isatty():
        try:
            choice = input("[?] Vuoi eseguire un secondo passaggio vuln-only sulle porte aperte? [y/N]: ").strip().lower()
        except EOFError:
            choice = "n"
        if choice == "y":
            run_vuln_only_pass(
                data, target, alias, reports_dir,
                vm_safe=not args.no_vm_safe,
                rate=args.rate,
                force_connect_scan=False  # sempre -sS
            )

    elapsed = time.time() - start_time
    minutes, seconds = divmod(int(elapsed), 60)
    print(f"[*] Tempo impiegato per la scansione: {minutes}m {seconds}s")

    print("[*] Report salvati in:")
    if not args.no_html:
        print("   HTML:", os.path.abspath(output_html))
    if not args.no_json:
        print("   JSON:", os.path.abspath(output_json))
    if not args.no_csv:
        print("   CSV :", os.path.abspath(output_csv))
    print("   LOG :", os.path.abspath(output_log))
    if not args.no_update:
        print("   UPD  :", os.path.abspath(updates_log))

    if (not args.no_html) and args.open_html:
        try:
            if sys.platform.startswith("darwin"):
                subprocess.run(["open", output_html], check=False)
            elif sys.platform.startswith("linux"):
                if shutil.which("xdg-open"):
                    subprocess.run(["xdg-open", output_html], check=False)
                else:
                    print("[!] 'xdg-open' non trovato. Apri manualmente il file HTML.")
            elif os.name == "nt":
                os.startfile(os.path.abspath(output_html))  # type: ignore
        except Exception:
            print("[!] Impossibile aprire automaticamente il report HTML.")

if __name__ == "__main__":
    main()
