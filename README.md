.::Nmap Vulnerability Scanner Pro::.
------------------------------------
  - Copyright ©️ 2025
  - Written by: grayf0x    

DESCRIZIONE:
------------------------------------

Questo script Python è un avanzato scanner di vulnerabilità di rete basato su Nmap, progettato per facilitare l’individuazione di falle di sicurezza nei sistemi target.
Panoramica:  
lo script automatizza e integra diversi strumenti e database di vulnerabilità per effettuare una scansione completa dei target di rete attraverso Nmap.  
Utilizza script NSE (Nmap Scripting Engine) dedicati alle vulnerabilità, in particolare Vulscan e Vulners, permettendo di recuperare informazioni dettagliate su CVE (Common Vulnerabilities and Exposures) per i servizi esposti.  
Funzionalità principali:  
	•	Controllo e installazione delle dipendenze: verifica che strumenti essenziali come `nmap`, `git`, `python3`, `curl` e `wget` siano presenti, e se mancano li installa automaticamente in base al sistema operativo.  
	•	Aggiornamento database vulnerabilità:  
	•	Clona o aggiorna localmente Vulscan, un insieme di database CSV che contiene informazioni sulle vulnerabilità.  
	•	Clona o aggiorna nmap-vulners, un plugin che interroga la piattaforma Vulners per informazioni sulle vulnerabilità più aggiornate.  
	•	Aggiorna gli script di Nmap per garantirne la completezza e la presenza delle ultime query e check di sicurezza.  
	•	Scansione flessibile con profili:  l’utente può scegliere uno tra quattro profili di scansione (Base, Intermedio, Avanzato, Full Audit) che determinano l’estensione, la profondità e la durata della scansione (ad esempio: numero di porte, tipi di script, velocità).  
	•	Esecuzione della scansione:  
 Lo script costruisce dinamicamente il comando Nmap con gli script di vulnerabilità, fa partire la scansione e mostra una barra di progresso animata in console con tempo trascorso.  
	•	Generazione di report HTML interattivi: dopo la scansione, lo script analizza il file XML prodotto da Nmap, estrae informazioni su porte, servizi e vulnerabilità trovate.   categorizzandole per severità (Critical, High, Medium, Low, Info). Il report HTML contiene:  
	•	Dashboard riassuntiva  
	•	Filtri interattivi per host e severità  
	•	Grafici a torta e a barre per distribuzione e dettaglio vulnerabilità per host  
	•	Tabelle dettagliate con output degli script e link diretti ai database NVD per ogni CVE  
 Vantaggi e utilizzo:  
	•	Automazione completa: aggiornamento automatico di tool e database permette di avere dati sempre aggiornati senza intervento manuale continuo.  
	•	Multi-profilo: consente dall’analisi rapida a scansioni molto approfondite ed esaustive.  
	•	Report ricchi e navigabili: i risultati sono facilmente interpretabili grazie a una buona interfaccia HTML dinamica con grafici e filtri.  
	•	Adatto sia a tester di sicurezza esperti che a chi vuole un primo screening approfondito delle vulnerabilità di rete.  
Tecnologie sottostanti:  
	•	Nmap e Nmap Scripting Engine (NSE) per scansione e scripting di vulnerability checks.  
	•	Vulscan e Vulners per database CVE e exploit.  
	•	Python per orchestrare la scansione, aggiornamenti e generazione report.  
	•	Chart.js per visualizzazioni interattive nel report finale.  
In sintesi, questo script è un tool professionale che sfrutta la potenza e la versatilità di Nmap estendendola con database di vulnerabilità e generazione di report interattivi, ideale per attività di security assessment e penetration testing più o meno automatizzate e personalizzate.  
