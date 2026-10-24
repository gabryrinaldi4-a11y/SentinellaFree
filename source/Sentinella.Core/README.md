# Moduli aggiunti nella versione 0.2

ClamEngine integra clamscan/freshclam da percorsi espliciti e mantiene distinti rilevamenti, limiti, errori e copertura delle firme. ClamQuarantine lega l'isolamento a una copia di byte effettivamente rianalizzata. SnapshotVault crea backup locali versionati e verifica SHA-256 prima del ripristino in una nuova cartella. Questi moduli non introducono un driver Windows di prevenzione né un motore anti-exploit o filtro web. I dettagli e i test aggiornati sono nel LEGGIMI principale e in evidence.

Il documento che segue descrive i moduli originari, tuttora presenti.

# Sentinella.Core

Implementazione originale, gratuita, senza dipendenze NuGet. Target: Windows e .NET 10.

## Scanner locale

`LocalScanner` calcola SHA-256 con lettura streaming e confronta esclusivamente le regole JSON esplicitamente caricate (`[{"sha256":"64 caratteri esadecimali","name":"nome"}]`). Non include un database di malware. `NoLocalMatch` significa soltanto nessuna corrispondenza locale; non certifica un file sicuro. Gli archivi sono trattati come file interi, senza analizzarne il contenuto.

Limiti: 256 MiB per file, 8 GiB complessivi di byte hashati, 25.000 file, 10.000 directory, profondità 128. File inaccessibili, collegamenti e reparse point sono esclusi e segnalati. La scansione incompleta non produce una conclusione di assenza di malware. La cancellazione genera `OperationCanceledException`.

## Quarantena manuale

Solo un `Finding` con verdetto `LocalHashMatch` può essere passato a `QuarantineAsync`. Il file deve essere locale, regolare, senza hard link e con dimensione massima di 32 MiB. L'utente deve avviare esplicitamente l'operazione attraverso l'interfaccia.

L'apertura Win32 acquisisce un handle esclusivo con accesso di lettura ed eliminazione. Il percorso finale e gli attributi vengono verificati, il contenuto viene nuovamente hashato e confrontato con la scansione. La copia contiene metadati e byte cifrati con AES-256-GCM, con chiave casuale diversa per ogni elemento e protezione DPAPI legata all'account Windows. Il formato e l'ID partecipano all'autenticazione. Il file `.sqf` viene salvato con flush, rinominato senza sovrascrivere e riletto/autenticato; solo dopo viene impostata l'eliminazione dell'originale attraverso lo stesso handle, evitando una nuova eliminazione per nome. Se un errore avviene tra commit e rimozione possono rimanere entrambe le copie.

Il ripristino richiede una destinazione esplicita e usa `FileMode.CreateNew`: non sovrascrive file e non esegue i byte ripristinati. La copia cifrata viene conservata anche dopo il ripristino. Se la scrittura del ripristino viene interrotta può rimanere un file di destinazione incompleto. Le voci danneggiate causano un errore, non vengono presentate come valide.

DPAPI richiede lo stesso account e il relativo materiale crittografico Windows. Copiare solo la cartella quarantena su un altro PC/account può impedire il recupero. Questa quarantena è uno strumento di conservazione cifrata, non un confine di sicurezza contro programmi eseguiti dallo stesso utente o un amministratore. Nessuna protezione preventiva kernel, auto-difesa, rilevazione comportamentale o aggiornamento firme è implementato in questo nucleo.

## Test

Eseguire dalla cartella `source`:

```powershell
dotnet run --project .\Sentinella.Tests\Sentinella.Tests.csproj -c Release
```

I test creano soltanto fixture innocue e regole hash di test in una cartella temporanea con GUID. Nessun EICAR e nessun malware reale. Verificano hash, assenza di database, validazione regole, duplicati, percorso assente, cancellazione, rifiuto di file cambiati/non corrispondenti, quarantena/ripristino con byte esatti, mancata sovrascrittura, ID con traversal, manomissione, hard link e file bloccati. I test dei link simbolici sono saltati con messaggio esplicito quando il processo non ha il privilegio Windows richiesto.

