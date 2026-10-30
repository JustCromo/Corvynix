# Corvynix

**Black box digitale e rilevamento dello spoofing GNSS per capsule di trasporto medicale via drone.**

Corvynix registra ogni dato di volo in modo che nessuno possa modificarlo o leggerlo, indica dato per dato quanto ci si può fidare di ciò che è stato registrato e si accorge se il segnale GNSS viene ingannato, anche quando l'attacco è lento e progettato per non farsi notare. In caso di spoofing il drone entra in safe mode e la centrale viene avvisata.

Progetto nato durante un hackathon sulla Smart Capsule. È un prototipo dimostrativo: interamente software, non richiede modifiche all'hardware della capsula.

---

## Cosa fa

### 1. Black box digitale
- **Integrità**: ogni record contiene l'impronta SHA-256 del precedente. Togliere, modificare o riordinare un record spezza la catena.
- **Autenticità**: ogni record è firmato con Ed25519. Le chiavi di firma cambiano a ogni tratto di volo (epoca) e vengono distrutte subito dopo: chi compromette la capsula non può riscrivere il passato.
- **Riservatezza**: ogni record è cifrato con la chiave pubblica della centrale (X25519 + AES-256-GCM). La capsula scrive ma non può rileggere i propri dati.
- **Verifica in tempo reale**: la centrale decifra e verifica ogni record appena arriva e controlla periodicamente che la copia locale nella capsula sia identica a quella ricevuta.
- **Affidabilità dato per dato**: ogni record è classificato come *sigillato*, *verificato*, *da verificare* o *non attendibile*, con il motivo.
- **Fine volo**: riconciliazione tra copia locale e centrale, sigillo dell'intera catena e marca temporale (simulata nel prototipo).
- **Export verificabile**: il CSV esportato contiene missione, numero di record e hash; qualsiasi modifica successiva viene individuata riga per riga.

### 2. Rilevamento dello spoofing GNSS
Il GNSS non viene mai considerato affidabile da solo: viene confrontato con ciò che uno spoofer non controlla (velocità, barometro, secondo ricevitore della capsula).

| Caso | Cosa lo rivela |
|---|---|
| Salto di posizione | Spostamento incompatibile con velocità e tempo |
| Ritorno al punto di partenza | In crociera la posizione torna al decollo (replay del segnale) |
| Deriva lenta | Il GNSS del drone si allontana gradualmente da quello della capsula |
| GNSS della capsula bloccato | Posizione della capsula ferma con il drone in movimento |
| Spoofing di zona | Tutti i ricevitori ingannati insieme, smentiti da barometro e velocità |
| Qualità degradata | Pochi satelliti, fix peggiorato, incertezza alta |
| Deriva graduale (indizio) | Prua e direzione GNSS divergono in modo costante: va confermata |

- **Sorveglianza in volo**: la capsula confronta di continuo la posizione prevista dalla velocità con quella GNSS e accumula le differenze nel tempo. Le differenze casuali si annullano, quelle di uno spoofer si sommano: oltre 2,5 m scatta un avviso, oltre 5 m la **safe mode**.
- **Safe mode**: il drone si ferma, l'evento viene firmato nella black box e la centrale riceve ora stimata dell'attacco e ultima posizione affidabile. L'operatore può riprendere il volo dalla centrale.
- **Allarmi non cancellabili**: ogni allarme del rilevatore viene scritto dentro il record firmato.
- **Analisi a posteriori**: si caricano uno o due voli registrati e il sistema indica quale contiene anomalie, di che tipo e in quale intervallo.

---

## Architettura

```
 CAPSULA (porta 8001)                         CENTRALE (porta 8002)
 ┌──────────────────────────┐   record       ┌──────────────────────────┐
 │ lettura telemetria       │   cifrati      │ decifratura e verifica   │
 │ hash + firma + cifratura │ ─────────────▶ │ classificazione dei dati │
 │ log locale cifrato       │                │ plausibilità             │
 │ rilevatore spoofing      │ ◀───────────── │ controllo del log locale │
 │ safe mode                │   comandi      │ riconciliazione, sigillo │
 └──────────────────────────┘                │ analisi dei voli         │
                                             └──────────────────────────┘
```

Entrambi i componenti girano in locale con FastAPI; le interfacce web si aggiornano in tempo reale via WebSocket.

---

## I dati

### Da dove arrivano
Il prototipo **simula** la capsula in volo: si carica un CSV di telemetria dal pannello della capsula e il sistema lo legge **riga per riga**, come se fossero letture dei sensori in tempo reale. Ogni riga diventa un record della black box.

Il file viene letto dal browser e passato al server locale: non viene salvato né inviato all'esterno.

### Formato
CSV con intestazione, separatore `,` `;` o tabulazione. Le colonne vengono riconosciute per nome; quelle assenti disattivano solo i controlli che le usano.

| Gruppo | Colonne |
|---|---|
| Tempo | `t_s`, `dt_s` |
| Fase di volo | `modalita_volo` |
| Posizione drone | `lat`, `lng`, `est_m`, `nord_m`, `quota_rel_m`, `quota_amsl_m` |
| Velocità | `vel_nord_ms`, `vel_est_ms`, `velocita_ms` |
| Sensori | `pressione_hpa`, `heading_deg`, `acc_x`, `acc_y`, `acc_z` |
| Qualità GNSS | `fix_gnss`, `satelliti`, `incertezza_pos_mm` |
| Posizione capsula | `caps_lat`, `caps_lng`, `caps_est_m`, `caps_nord_m`, `caps_satelliti` |
| Confronto | `distanza_drone_capsula_m` |
| Etichetta (facoltativa) | `anomalia`: usata solo per misurare le prestazioni del rilevatore |

### Dati inclusi
I file in `esempi/` e `esempio_volo.csv` sono **sintetici**, generati per i test: un volo pulito e un volo per ogni tipo di anomalia. Il repository non contiene dati di voli reali.

### Dati prodotti
| Percorso | Contenuto |
|---|---|
| `data/capsule/` | Log locale della capsula, solo record cifrati |
| `data/cloud/` | Archivio della centrale con i dati verificati |

La cartella `data/` è esclusa dal repository.

---

## Installazione

Requisiti: Python 3.10 o superiore.

```bash
git clone https://github.com/JustCromo/Corvynix.git
cd Corvynix
python -m venv .venv
.venv/bin/pip install -r requirements.txt
./avvia.sh
```

| Pagina | Indirizzo |
|---|---|
| Pannello capsula | http://127.0.0.1:8001 |
| Centrale | http://127.0.0.1:8002 |
| Analisi dei voli | http://127.0.0.1:8002/analisi |

---

## Demo

1. Nel pannello capsula carica `esempi/00_volo_pulito.csv` e avvia il volo.
2. Prova gli eventi dal pannello e osservane l'effetto nella centrale:
   - **Perdita di segnale**: i record restano cifrati nella capsula e vengono recuperati al ritorno del segnale.
   - **Malware**: modifica il log locale; la manomissione viene rilevata durante il volo.
   - **Furto delle chiavi**: il passato resta intatto, i record successivi vengono marcati come non attendibili.
   - **Spoofing lento di zona**: lo spostamento non spiegato cresce fino alla safe mode; dalla centrale si riprende il volo.
3. A fine volo consulta il riepilogo ed esporta il CSV verificabile.
4. Nella pagina di analisi confronta due voli, oppure verifica un CSV esportato.

### Valutazione del rilevatore
```bash
.venv/bin/python valuta.py esempi/
```
Per ogni file indica il caso riconosciuto e, se è presente la colonna `anomalia`, eventi rilevati, precisione, copertura e falsi allarmi.

---

## Struttura

| File | Ruolo |
|---|---|
| `capsule.py` | Capsula: lettura dati, firma, cifratura, log locale, sorveglianza, safe mode |
| `cloud.py` | Centrale: verifica, classificazione, controllo del log locale, riconciliazione, export, analisi |
| `common.py` | Primitive crittografiche condivise |
| `detector.py` | Rilevatore delle anomalie GNSS |
| `spoofwatch.py` | Sorveglianza in tempo reale dello spoofing lento |
| `valuta.py` | Valutazione del rilevatore da terminale |
| `static/` | Interfacce web |
| `esempi/` | Voli sintetici di prova |

---

## Limiti del prototipo

| Aspetto | Prototipo | Produzione |
|---|---|---|
| Custodia delle chiavi | Memoria del processo | TPM o secure element |
| Trasporto | HTTP locale | TLS 1.3 con autenticazione reciproca |
| Marca temporale | Simulata | Marca temporale qualificata eIDAS (RFC 3161) |
| Archivio della centrale | File JSON | Database cifrato con accessi controllati |
| Sorveglianza dello spoofing | Previsione dalla velocità | Innovazioni dell'EKF dell'autopilota |
| Taratura del rilevatore | Dati sintetici | Voli reali |
