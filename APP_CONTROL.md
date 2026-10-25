# Controllo applicazioni — sviluppo 0.3

Questa funzione gestisce regole AppLocker di Windows. Non e una replica di Smart App Control e non ne modifica lo stato. Un file consentito da AppLocker puo ancora essere bloccato da Smart App Control, Defender o altri antivirus. L'attuale app non firmata rimane soggetta al blocco di avvio gia osservato.

## Cosa implementa

- Lista locale di versioni approvate; SHA256 completo per la verifica dei file e hash Authenticode calcolato dai cmdlet AppLocker per la regola effettiva. Non sono la stessa cosa.
- Bozza separata dal criterio installato: aggiungere o rimuovere un file non cambia automaticamente Windows.
- Test offline con Test-AppLockerPolicy, che non esegue il file e non installa il criterio.
- Audit prima dell'applicazione in blocco. La stessa lista e lo stesso profilo devono essere stati applicati in audit; la UI richiede che l'utente abbia esaminato gli eventi prima di richiedere il blocco.
- Conferma esplicita e UAC per audit, blocco e ripristino. Il processo amministratore accetta solo tre azioni, verifica l'hash della richiesta, ricontrolla file e hash sotto lock di lettura e genera nuovamente l'XML dai dati strutturati.
- Controllo di coerenza del criterio prima della modifica. Rifiuta regole gia presenti o esterne, criteri cambiati e bozze appartenenti a un altro utente.
- Backup del criterio iniziale e dati di gestione in ProgramData\SentinellaFree.AppControl, con scrittura riservata ad Administrators e SYSTEM. Il ripristino rifiuta di sovrascrivere un criterio non piu corrispondente all'ultimo gestito da Sentinella.
- Avvio automatico di Application Identity su richiesta di applicazione; tipo di avvio iniziale conservato per il ripristino. Un servizio condiviso non viene fermato automaticamente.

## Perimetro e limiti

Il blocco riguarda EXE/COM dell'utente indicato nella bozza. La regola deny e circoscritta al suo SID; le altre utenze non ricevono i suoi divieti. La directory Windows e la base consentita, con ulteriori divieti per alcune note cartelle scrivibili, tra cui Temp, Tasks e tracing. Program Files e consentita come base solo se l'utente seleziona esplicitamente l'opzione meno restrittiva. Le eccezioni hash approvate sono inserite in tutti i divieti; una revoca le rimuove da tutti.

La collezione delle app pacchettizzate mantiene consentite quelle firmate, per non bloccare accidentalmente le app Windows quando si introduce una collezione EXE. Non viene offerto il controllo delle singole app pacchettizzate in questa versione.

Questa configurazione NON copre DLL, script, macro, installer, codice eseguito dentro programmi autorizzati, ne abusi di strumenti Windows. Le cartelle base non sono un controllo dinamico delle ACL di ogni sottocartella. Non e una barriera contro un amministratore locale e non offre la reputazione cloud o le garanzie di Smart App Control. Non viene promesso il blocco di ogni possibile esecuzione non autorizzata.

Non c'e un popup universale prima di ogni avvio: l'eseguibile non consentito viene gestito da Windows; l'utente aggiunge esplicitamente il file alla bozza e aggiorna i criteri dopo averlo esaminato. Le dipendenze EXE e gli aggiornamenti che cambiano contenuto devono essere autorizzati separatamente.

## Uso previsto dopo aver risolto legittimamente l'avvio di Sentinella

1. Apri Protezioni > Gestisci autorizzazioni e leggi lo stato.
2. Aggiungi esplicitamente Sentinella e il motore, quindi le applicazioni necessarie. La firma o l'autorizzazione non attestano che il contenuto sia sicuro.
3. Verifica offline file necessari e un eseguibile innocuo non autorizzato. Esporta il piano per esaminarlo: contiene SID e percorsi personali, quindi non pubblicarlo senza revisione.
4. Applica audit con conferma e UAC. Controlla Visualizzatore eventi > Registri applicazioni e servizi > Microsoft > Windows > AppLocker > EXE and DLL; gli eventi audit sono 8003, i blocchi 8004.
5. Dopo un collaudo rappresentativo, conferma la revisione dell'audit e richiedi Attiva blocco. Non e una procedura da eseguire automaticamente sul PC durante lo sviluppo.
6. Per rimuovere le regole gestite usa Ripristina criterio precedente, con UAC. Se i criteri sono cambiati esternamente, rivolgiti all'amministratore invece di forzare la sostituzione. La copia iniziale e original-policy.xml nella cartella protetta indicata sopra.

Passare da blocco ad audit o ripristinare il criterio precedente elimina i blocchi di questa funzione. La UI lo indica prima della richiesta UAC. Smart App Control non viene mai attivato, disattivato o aggirato da questi comandi.

## Verifica effettuata

La pipeline Windows esegue test della generazione, della revoca, dei dati non validi, dei profili e dei fingerprint; poi usa cmdlet AppLocker nativi su copie di binari Windows innocui, senza eseguirle. Verifica autorizzazione, divieto, revoca, cambio nome e isolamento dell'utente con criteri offline. Nessun test installa criteri, avvia UAC, cambia servizi o modifica Smart App Control.

L'applicazione elevata, il blocco effettivo e il ripristino non sono stati collaudati end-to-end. La nuova finestra non e stata eseguita su questo PC per il blocco Smart App Control gia documentato. Una compilazione o un test offline riuscito non prova questi passaggi.

## Riferimenti Microsoft

- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-applocker-rule-behavior
- https://learn.microsoft.com/en-us/windows/client-management/mdm/applocker-csp
