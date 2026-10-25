# Protezione continua — sviluppo 0.4

Questa versione aggiunge un agente dell'utente, avvisi comportamentali, un filtro browser e verifiche degli aggiornamenti. Non e una protezione antivirus preventiva completa e non sostituisce Bitdefender, Defender o Smart App Control.

## Agente

Da Protezioni > Apri protezione continua seleziona fino a otto cartelle. Dopo conferma puoi avviare il monitor, richiedere l'avvio al tuo accesso e abilitare gli aggiornamenti ufficiali ClamAV ogni sei ore. L'avvio al login riguarda solo l'utente, tramite la sua chiave Run; non viene creato un servizio di sistema, account o driver. Nessuna di queste impostazioni e attivata automaticamente dai test o dall'installazione.

Il monitor scansiona dopo le modifiche, non prima dell'esecuzione. I file gia presenti richiedono una scansione manuale iniziale. Esclude i propri dati e runtime, rifiuta collegamenti, limita la coda a 2000 percorsi e le scansioni automatiche a 128 MiB per file. Errori, eventi persi e file che continuano a cambiare sono segnalati come copertura incompleta. Non cancella o mette in quarantena automaticamente.

Lo stato e aggiornato ogni due secondi. Dopo dodici secondi senza contatto, la UI non conferma l'agente attivo. Il canale di arresto e riservato allo stesso utente. Fermare il monitor non cambia altri antivirus o Smart App Control.

## Avvisi comportamentali

Il campionamento processi ogni venti secondi cerca alcune combinazioni, come interpreti avviati da Office o usi remoti di determinati interpreti. Gli argomenti vengono elaborati in memoria e non salvati. Raffiche di modifiche a molti file generano un avviso senza attribuire automaticamente il responsabile.

Sono segnali euristici, non prove di malware: operazioni legittime possono generarli e processi brevi possono sfuggire. Nessun processo viene terminato. Non e un EDR, anti-exploit o rilevatore universale di ransomware.

## Filtro browser

La cartella browser-extension contiene un'estensione Manifest V3 da installare e autorizzare personalmente. Parte disattivata. Non legge il contenuto delle pagine e non invia cronologia o file. Domini bloccati, eccezioni e sottodomini sono gestiti dal motore declarativeNetRequest prima delle richieste di rete.

La lista pubblica CERT Polska e facoltativa e si aggiorna ogni cinque minuti solo se richiesto. Il download HTTPS contatta hole.cert.pl, che puo vedere l'IP del richiedente. Gli elenchi vengono sostituiti integralmente per rimuovere anche i domini scaduti; se un aggiornamento fallisce, vengono mantenute le vecchie regole e mostrato un errore. La lista non comprende ogni sito pericoloso, non analizza allegati o contenuti e non sostituisce Safe Browsing o SmartScreen.

Sorgente: https://wiedza.cert.pl/systemy-cert-polska/uslugi/lista-ostrzezen/

## Integrita e aggiornamenti

Il confronto con original-components.json rileva incoerenze dei tre componenti originali. Un attaccante dello stesso utente potrebbe cambiare sia i file sia il manifesto: non e antimanomissione equivalente a un servizio antivirus protetto.

Il verificatore dei rilasci richiede RSA-PSS/SHA256 con chiave pubblica fissata, versione crescente, scadenza, repository esatto, dimensione e hash. Rifiuta alterazioni, replay e origini diverse. Nessuna chiave di rilascio e fissata nella build corrente: nessun programma viene scaricato o installato automaticamente. E testato il verificatore, non un sistema completo di distribuzione. Questa firma dei manifesti non e Authenticode e non autorizza il programma in Smart App Control.

## Limiti e collaudo

Restano assenti driver preventivo proprio, servizio antimanomissione protetto, anti-exploit e reputazione globale. Le regole AppLocker sono separate e richiedono audit/UAC. Non vengono disabilitati i provider presenti.

I test usano file innocui, un motore simulato per i casi di errore e un profilo browser temporaneo con server HTTP locale. Non usano malware vivo, non installano criteri AppLocker e non modificano browser personali o impostazioni di sicurezza Windows. Non sono una certificazione di efficacia antivirus.
