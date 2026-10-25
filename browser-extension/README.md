# Sentinella Web — sviluppo

Estensione sperimentale per Chrome, Edge e Brave compatibili con Manifest V3. Non viene installata automaticamente. Il titolare deve autorizzare personalmente installazione e permessi.

Per il collaudo usa un profilo separato. Nella pagina Estensioni scegli le opzioni di sviluppo del browser, poi Carica estensione non pacchettizzata e questa cartella. Non cambiare protezioni Windows o controlli di sicurezza per forzare un'installazione bloccata da criteri. Apri le opzioni di Sentinella Web: inizialmente il filtro e disattivato.

Inserisci un dominio per riga da bloccare o autorizzare. Le eccezioni comprendono i sottodomini e prevalgono solo sui blocchi di questa estensione. Per usare CERT seleziona la sorgente e aggiorna l'elenco. Download e aggiornamenti periodici sono opt-in. Nessuna cronologia o contenuto delle pagine viene inviato. Il fornitore del download vede l'IP della richiesta.

Sorgente: https://hole.cert.pl/domains/v2/domains.txt

Attribuzione e specifica: https://wiedza.cert.pl/systemy-cert-polska/uslugi/lista-ostrzezen/

Il filtro blocca solo i domini configurati: non rileva ogni sito malevolo e non analizza i file scaricati. Le vecchie regole sono mantenute se un aggiornamento fallisce. L'elenco completo viene sostituito dopo gli aggiornamenti riusciti, anche per rimuovere i domini non piu presenti.

Per rimuoverlo, disattiva o disinstalla Sentinella Web dalla pagina Estensioni. I suoi dati sono in storage.local. I test automatici nel repository usano un profilo Chromium temporaneo e un server HTTP innocuo; non modificano il browser personale.
