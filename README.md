# NetSniff: Advanced Network Analysis & MITM Suite

**NetSniff** è un framework professionale per l'intercettazione e l'analisi del traffico di rete in tempo reale. Grazie a un'interfaccia dashboard moderna e intuitiva, il software permette di monitorare, ispezionare e manipolare i dati degli altri dispositivi connessi alla rete locale.

![NetSniff Dashboard](https://via.placeholder.com/800x400.png?text=NetSniff+Dashboard+Preview)

## Caratteristiche Principali

*   **Discovery Intelligente:** Scansione della rete con identificazione automatica di produttori (Apple, Samsung, ecc.) e host.
*   **Traffic Sniffing:** Monitoraggio in tempo reale di query DNS e richieste HTTP con ispettore di pacchetti integrato.
*   **JS Injection Engine:** Iniettore di codice JavaScript personalizzato per modificare l'esperienza web dei dispositivi target (in siti HTTP).
*   **Security Bypass:** Tecniche di SSL Stripping e HTTPS Blocking per forzare il traffico su protocolli leggibili.
*   **DNS Mapping:** Associazione automatica tra indirizzi IP e domini reali per una leggibilità totale dei log, anche su traffico criptato.

*NetSniff trasforma il tuo computer in un potente centro di controllo per il monitoraggio e il testing della sicurezza di rete.*

## Disclaimer ⚠️

**QUESTO SOFTWARE È STATO CREATO A SCOPO PURAMENTE EDUCATIVO.**
L'autore non si assume alcuna responsabilità per l'uso improprio di questo strumento. L'intercettazione del traffico dati su reti altrui senza autorizzazione è un reato perseguibile penalmente. Utilizzare solo su reti di propria proprietà o con esplicito consenso.

## Installazione

1.  Clona la repository:
    ```bash
    git clone https://github.com/tiadiff/WiFi-Sniffer.git
    cd WiFi-Sniffer
    ```

2.  Installa le dipendenze:
    ```bash
    pip install -r requirements.txt
    ```

3.  (Opzionale) Assicurati di avere i permessi di amministrazione, necessari per `scapy` e `pfctl`.

## Utilizzo

1.  Avvia lo sniffer (richiede sudo):
    ```bash
    sudo python sniffer.py
    ```
    *In alternativa, su macOS puoi usare lo script `sniffer.command`.*

2.  Apri il browser e vai alla dashboard:
    [http://localhost:5001](http://localhost:5001)

3.  Seleziona il **Target IP** (Vittima) e il **Gateway IP** (Router).
4.  Attiva le funzioni desiderate (Sniffing, Injection, HTTPS Block).

## Requisiti

*   Python 3.8+
*   macOS (Consigliato per supporto nativo `pfctl`) o Linux
*   Permessi di Root/Sudo

## Licenza

MIT License.
