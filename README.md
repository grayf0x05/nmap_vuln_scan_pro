.::Nmap Vulnerability Scanner Pro::.
------------------------------------
  - Copyright ©️ 2025
  - Written by: grayf0x    

Questo script Python è un tool automatizzato per effettuare scansioni di vulnerabilità su un host di rete usando `nmap` con l’integrazione dei plugin `vulners` e `vulscan`.    

***  

## 🎥 Video Tutorial
[![Guarda il tutorial su YouTube](https://img.youtube.com/vi/JSDotBUQ9y0/0.jpg)](https://www.youtube.com/watch?v=JSDotBUQ9y0)


### Descrizione    

1. **Controllo privilegi**    
   Lo script verifica di essere eseguito con privilegi di root, necessari per alcune funzionalità di `nmap`.  

2. **Verifica e installazione dipendenze**    
   Controlla la presenza dei tool necessari (`nmap`, `git`, `python3`, `curl`, `wget`) e, se mancanti, tenta di installarli automaticamente tramite i gestori pacchetti più comuni (`apt`, `yum`, `pacman`, Homebrew).  

3. **Aggiornamento database vulnerabilità**    
   - Scarica o aggiorna automaticamente i database di vulnerabilità di `vulscan` e `vulners` (plugin di `nmap` per vulnerability scanning).  
   - Aggiorna la cache degli script nmap (`nmap --script-updatedb`).  

4. **Validazione del target**    
   Permette di inserire un indirizzo IP o hostname da sottoporre a scansione, validandolo con regex.  

5. **Configurazione della scansione**    
   Propone quattro profili di scansione con livelli di approfondimento crescente, che differiscono per tipi di script usati, porte scansionate e flag di esecuzione.  

6. **Esecuzione scansione Nmap**    
   Costruisce il comando nmap con i plugin e gli argomenti scelti, esegue la scansione e genera un file XML con i risultati.  

7. **Parsing e analisi dei risultati**    
   - Analizza il file XML prodotto da nmap, estraendo per ogni host le porte aperte, le vulnerabilità identificate con i rispettivi CVE.    
   - Estrae anche la severità reale associata a ogni vulnerabilità ricavandola dall’output degli script (Critical, High, Medium, Low, Info).  

8. **Generazione report HTML interattivo**    
   Produce un report HTML completo e leggibile che include:    
   - Sommario con numero totale di host, porte aperte e vulnerabilità trovate.    
   - Distribuzione delle vulnerabilità per severità, con badge colorati.    
   - Grafici dinamici (usa Chart.js) per la distribuzione delle severità e il numero di vulnerabilità per host.    
   - Tabella con il dettaglio completo di ogni vulnerabilità (host, porta, CVE con link alla pagina ufficiale, severità e descrizione).    
   - Filtri interattivi per visualizzare solo le vulnerabilità di alcune severità (es. mostrare solo Critical e High).    
   - Organizzazione dei report in cartelle suddivise per profilo e identificatore del target.  

***  

### Utilizzo tipico  

- Lanci lo script (come `sudo python3 script.py`), inserisci l’IP o hostname da scansionare e, opzionalmente, un nome descrittivo (alias).  
- Scegli il profilo di scansione (da rapido a completo).  
- Lo script gestisce dipendenze, aggiorna i database, esegue la scansione e genera report.  
- Alla fine viene generato un report HTML interattivo facilmente consultabile via browser.  

***  

### Punti di forza  

- Automazione completa dalla preparazione all’output finale.  
- Integrazione dei plugin `vulners` e `vulscan` per massimizzare la copertura sulle vulnerabilità note.  
- Parsing intelligente che estrae la severità reale e genera report visivamente chiari e interattivi.  
- Supporto multi-piattaforma (Linux e macOS) con installazione automatica dipendenze.  
- Report organizzati in una struttura di cartelle per una facile gestione storica.
- Nella versione 1.2 sono stati ottimizzati i profili di scansione 3 e 4 per macchine virtuali.  

***  

In sintesi, è una soluzione pratica e completa per penetration tester o amministratori di sistema per automatizzare scansioni di vulnerabilità con `nmap`, producendo risultati immediatamente fruibili e ben organizzati. 
