Questo progetto implementa un sistema basato su blockchain per la gestione sicura dei documenti medici e il controllo degli accessi. Il sistema si basa su due smart contract principali e include una suite di test completa.


Architettura dei Contratti

Il sistema è composto da due smart contract scritti in Solidity:

1. MedChainGovernance (GSC)

* È un contratto di governance di tipo M-of-N.


* Gestisce le autorità del consorzio (validatori) e il protocollo di emergenza "Break-Glass".


* Permette ai validatori di inviare e firmare proposte per aggiungere (whitelisting) le autorità di identità.


* Gestisce le richieste di accesso di emergenza ai dati, richiedendo il raggiungimento di una soglia di firme specifica (es. 2 su 3) per l'approvazione.



2. MedChainVault (MSC)

* Funge da Master Smart Contract e archivio dei documenti (Document Vault).


* Si occupa della gestione degli Access Control Token (ACT) e dell'implementazione della revoca a cascata.


* Interagisce con il contratto di governance per verificare che l'identità di chi chiama le funzioni sia valida e presente nella whitelist.


* Consente ai proprietari dei documenti di registrare record (con CID, sigillo e firma) e di emettere "Root ACT" per delegare l'accesso.



Caratteristiche Principali di Sicurezza

* Controllo degli Accessi Granulare: Supporta permessi specifici di tipo `READ` e `WRITE` per i token.


* Prevenzione DoS sul Gas: La profondità massima della delega degli accessi è strettamente limitata a 3 per evitare attacchi di tipo Denial of Service legati al consumo di Gas.


* Integrità della Catena: Ogni volta che si delega o si autorizza un accesso, il contratto verifica l'intera catena del token per assicurarsi che nessun nodo genitore sia scaduto o revocato.


* Revoca a Cascata: La revoca di un token invalida automaticamente tutti i token derivati da esso.



Testing

La suite di test è scritta in TypeScript utilizzando il test runner di Node.js (`node:test`), Hardhat e Viem.

I test coprono le seguenti aree critiche:

* Protocollo di Governance: Verifica l'inserimento in whitelist di medici e pazienti al raggiungimento della soglia richiesta.


* Gestione Documenti e ACT: Testa la registrazione sicura dei documenti, la creazione dei token, la delega e la revoca a cascata verificando i consumi di gas.


Casi Limite (Edge Cases):
* Approvazione degli accessi di emergenza (Break-Glass).


* Prevenzione del superamento del limite di profondità per le deleghe.


* Blocco dei tentativi di revoca da parte di utenti non autorizzati.


* Blocco dei tentativi di escalazione dei privilegi (es. usare un token `READ` per autorizzare un'operazione di `WRITE`).


* Rifiuto di token scaduti o revocati.
