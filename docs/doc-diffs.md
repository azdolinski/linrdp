# doc-diffs — rozbieżności kodu względem dokumentacji Microsoft

Data: runda 1 — 2026-09-11 (audyt i naprawy, sekcja „Stan po naprawach (runda 1)"); runda 2 — 2026-09-24 (audyt) / 2026-09-26 (naprawy #8–#27, sekcja „Runda 2").
Zakres: `docs/microsoft-docs/` = **[MS-RDPBCGR]** (pełny spec, rev. 260309) + **[MS-RDPEA]** (Audio Output Virtual Channel Extension, rev. 240423). Weryfikacja server-side (LinRDP = serwer RDP; klient = mstsc/FreeRDP). Runda 2 dodatkowo: **[MS-RDPEDYC]**, **[MS-RDPEGFX]**, **[MS-RDPEAI]**, **[MS-RDPEMT]**, **[MS-RDPEUDP]**, **[MS-RDPEDISP]**.

Legenda werdyktów:
- ✅ **ZGODNE** — kod spełnia wymóg spec (MUST/SHOULD lub struktura bajtowa).
- 🟡 **CZĘŚCIOWO** — działa, ale odstaje od reguły SHOULD / walidacji / drobnego MUST.
- 🔴 **ROZJEBANE** — jawne naruszenie normatywne MUST / MUST NOT.
- ⚪ **BRAK W KODZIE** — brak implementacji wymogu.
- ⚫ **ŚWIADOMY OMIT** — celowo nieimplementowane (deprecated / poza zakresem), struktura PDU zwykle gotowa.
- 🛠 **NAPRAWIONE** — rozbieżność usunięta w serii commitów po audycie (patrz fix-log niżej).
- ↩ **KOREKTA** — werdykt rundy 1 okazał się błędny lub niepełny; poprawiony w rundzie 2 (obok numer PR z naprawą).

## Runda 2

Runda 1 objęła tylko [MS-RDPBCGR] i [MS-RDPEA]. Runda 2 porównała serwer także z [MS-RDPEDYC], [MS-RDPEGFX], [MS-RDPEAI], [MS-RDPEMT], [MS-RDPEUDP] i [MS-RDPEDISP]. Wyszło 17 problemów, zebranych w issue #7. Każdy naprawiono w osobnym PR, z testem na bajtach PDU albo na sekwencji wymiany.

Część werdyktów rundy 1 okazała się błędna lub niepełna. Poprawiono je w tabelach niżej (znacznik ↩) i zebrano w „Korekty werdyktów rundy 1".

Weryfikacja: testy jednostkowe dla każdej zmiany. Testy E2E z mstsc i xfreerdp3 są jeszcze do wykonania; lista kontrolna jest w opisach PR-ów.

| # | Priorytet | Spec | Rozbieżność | PR |
|---|---|---|---|---|
| 1 | krytyczny | MS-RDPEAI 3.1.4.1, 3.3.5.1.1–6; MS-RDPEDYC 2.2.1 | Mikrofon nie mógł wystartować: na AUDIO_INPUT działała kliencka maszyna stanów, która nic nie wysyła. Format 44,1 kHz zamiast 48 kHz źródła, kanał otwarty przez całą sesję, a DVC serwera tworzone przed wymianą Caps. | #8, #23 |
| 2 | krytyczny | MS-RDPEDYC 3.1.5.3, 3.3.5.3.1–2; MS-RDPBCGR 2.2.15.2; MS-RDPEGFX 2.1; MS-RDPEMT 1.3.3 | Soft-Sync bez `SOFTSYNC_TCP_TO_UDP` po obu stronach i czekanie na S_OK, którego zgodny klient nie wysyła. Dane przeniesionych kanałów szły TCP aż do Response, potem wszystko tunelem, także Create/Close i kanały nieprzeniesione. Dane z tunelu przed Response zrywały sesję. `try_send` gubił PDU EGFX, a po utracie tunelu kanały milkły. | #14, #24, #25 |
| 3 | wysoki | MS-RDPEGFX 3.2.5.18, 3.2.5.1 | Ramki pobrane przed ponownym CapsAdvertise wychodziły po nowym CapsConfirm (błąd 0xD06). | #15 |
| 4 | wysoki | MS-RDPEGFX 3.2.5.13 | SUSPEND_FRAME_ACKNOWLEDGEMENT nie czyścił Unacknowledged Frames; po wznowieniu obraz zamarzał. | #9 |
| 5 | wysoki | MS-RDPBCGR 2.2.5.1.1 | Set Error Info jako goły `errorInfo`, bez nagłówków Share Control i Share Data. | #11 |
| 6 | wysoki | MS-RDPEGFX 2.2.4.1 | Glif ClearCodec trafiał do cache przy kodowaniu, a nie przy wysyłce, więc GLYPH_HIT mógł wskazać pusty slot. | #12 |
| 7 | średni | MS-RDPEUDP 3.1.5.1.3, 3.1.1.3 | SYN+ACK zawsze z wersją 3 i z MTU z konfiguracji zamiast wynegocjowanych. | #13 |
| 8 | średni | MS-RDPBCGR 3.3.5.11.1–2 | Refresh Rect ogłoszony, ale nic nie odświeżał. | #16 |
| 9 | średni | MS-RDPBCGR 2.2.1.3.6.1; MS-RDPEGFX 2.2.2.14 | TS_MONITOR_DEF w ResetGraphics bez granic inclusive; przy resize pusta lista monitorów. | #10 |
| 10 | średni | MS-RDPEDISP 3.1.5.2, 2.2.2.2, 1.3 | Brak walidacji układów, pierwszy monitor zamiast głównego, ogłaszany obszar 3840×2400 większy niż maksimum sesji. Bez EGFX zmiana rozmiaru nie uruchamiała Deactivation-Reactivation. | #17 |
| 11 | średni | MS-RDPBCGR 2.2.9.1.1.3.1, 2.2.9.1.1.4, 2.2.9.1.2.1.10–11 | Fallback slow-path z rundy 1 był niezgodny: podwójny updateType, wskaźniki jako Update PDU, surface commands i large pointer bez formy slow-path, aktualizacje za duże na jeden PDU. | #18 |
| 12 | niski | MS-RDPBCGR 2.2.1.3.2, 1.3.9 | Sondy auto-detect także do klientów bez `RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT`; `RDP_NETCHAR_RESULTS` po TCP w trybie ciągłym. | #19 |
| 13 | niski | MS-RDPBCGR 1.3.1.1, 1.3.1.3, 2.2.15.1–2 | Initiate Multitransport Request wysyłany po finalizacji i ponownie po każdej reaktywacji, zamiast w fazie 8. Finalizacja brała dowolny PDU za kolejny, a reaktywacja gubiła tunel. | #27 |
| 14 | niski | MS-RDPEGFX 3.2.5.18–19 | Błędny zestaw caps przerywał negocjację bez CapsConfirm. Bez wspólnego zestawu serwer potwierdzał V8 zamiast zamknąć DVC. | #26 |
| 15 | niski | MS-RDPBCGR 3.3.5.3.11, 5.5 | Niezweryfikowane cookie ARC odrzucało połączenie zamiast logowania poświadczeniami. | #20 |
| 16 | niski | MS-RDPBCGR 2.2.7.1.6, 2.2.8.1.1.3.1.1.7 | Ogłoszona mysz względna była ignorowana w X11 i libei. | #21 |
| 17 | niski | MS-RDPBCGR 2.2.1.2.1 | RDP_NEG_RSP bez `DYNVC_GFX_PROTOCOL_SUPPORTED`. | #22 |

### Korekty werdyktów rundy 1

| Miejsce w rundzie 1 | Było | W rzeczywistości | Naprawa |
|---|---|---|---|
| Fix-log `server` (slow-path); sekcja 3 „fallback slow-path output" | 🛠 | Fallback nie był zgodny z 2.2.9.1.1 (problem 11). | #18 |
| Fix-log `server` (multitransport); sekcja 4 „2.2.15.1/2" | 🛠 | Kanał wiadomości był już dobry, ale żądanie szło po finalizacji zamiast w fazie 8 (1.3.1.1) i powtarzało się po każdej reaktywacji (problem 13). | #27 |
| Fix-log `acceptor` (TS_UD_SC); sekcja 3 „TS_UD_SC_MULTITRANSPORT" | 🛠 | Ogłoszenie bez `SOFTSYNC_TCP_TO_UDP`. Bez tej flagi po obu stronach Soft-Sync MUST NOT być użyty (MS-RDPEDYC 3.1.5.3). | #14 |
| Sekcja 4 „3.3.5.8 gating na zgodę klienta" | ✅ | Tunel był oferowany bez sprawdzenia `SOFTSYNC_TCP_TO_UDP` klienta, a serwer czekał na S_OK, którego zgodny klient nie wysyła (2.2.15.2). | #14 |
| Fix-log `linrdp` (main); sekcja 4 „autodetect w aplikacji" | 🛠 | Sondy szły także do klientów bez `RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT`, a `RDP_NETCHAR_RESULTS` po TCP (problem 12). | #19 |
| Sekcja 4 „2.2.5.1.1 Set Error Info pduSource=0" | ✅ | PDU nie miał nagłówków Share Control i Share Data (problem 5). | #11 |
| Sekcja 2 „3.3.5.3.13–22 Demand Active → finalizacja" | ✅ | Finalizacja brała dowolny PDU za kolejny (problem 13). | #27 |
| Sekcja 4 „2.2.4.2/3 + 5.5" (ARC) | ✅ | Niezweryfikowane cookie odrzucało połączenie, a 3.3.5.3.11 zaleca (SHOULD) użyć poświadczeń (problem 15). | #20 |
| Sekcja 3 „1.3.1.3 / 2.2.3.1 Deactivate All + re-negocjacja" | ✅ | Mechanizm był, ale bez EGFX zmiana rozmiaru go nie uruchamiała (MS-RDPEDISP 1.3), a reaktywacja gubiła tunel UDP. | #17, #27 |
| „Pozostałe otwarte", pkt 5 (mysz względna) | otwarte | Naprawione (problem 16). | #21 |

## Stan po naprawach (runda 1)

> ↩ Runda 2 wykazała, że część tych napraw była niepełna; patrz „Korekty werdyktów rundy 1".

Wszystkie punkty 🔴 i niemal wszystkie naprawialne 🟡 zostały naprawione (12 commitów). Pozostałe rozbieżności to świadome omity lub optymalizacje bez znaczenia normatywnego. Ścieżka krytyczna (NLA + obraz + dźwięk + UDP bootstrap) jest teraz zgodna z [MS-RDPBCGR]/[MS-RDPEA] na ~95% punktów normatywnych.

### Fix-log (commity)

| Commit | Fix |
|---|---|
| `rdpsnd(pdu)` | negocjacja w dół nieznanego wVersion zamiast błędu dekodowania |
| `rdpsnd(server)` | cBlockNo start=1 (3.3.5.2.1.1), MUST ignore (3.1.5), TSSNDCAPS_ALIVE gating (3.3.5.2), timeouty QualityMode→DYNAMIC / TrainingConfirm→terminate (3.3.5.1.1.3/3.1.5), set_pitch z gatingiem PITCH (2.2.4.2) |
| `server` (multitransport) | Initiate Multitransport Request/Response po MCS message channel (2.2.15.1/2 — MUST); brak kanału → brak bootstrapu; fallback odbioru na I/O zostaje dla klientów niestandardowych. ↩ Runda 2: żądanie w złej fazie (#27) |
| `acceptor` (TS_UD_SC) | ogłoszenie TS_UD_SC_MULTITRANSPORT (UDP/FECR) w GCC, gdy skonfigurowany multitransport (2.2.1.4.6 + 3.3.5.8). ↩ Runda 2: bez `SOFTSYNC_TCP_TO_UDP` (#14) |
| `server` (ERRINFO) | Set Error Info gate'owany na RNS_UD_CS_SUPPORT_ERRINFO_PDU we wszystkich 5 miejscach wysyłki (3.3.5.7.1 — zamknięty KNOWN GAP) |
| `nego` | klient bez RDP Negotiation Request dostaje pusty X.224 Confirm (ConnectionConfirm::NoNegotiation), nie RDP_NEG_FAILURE (3.3.5.3.2 MUST NOT) |
| `acceptor` (ChannelJoin) | nieoczekiwany join → Confirm z result=rt-no-such-channel(3) zamiast zerwania; powtórny join ignorowany bez Confirm (3.3.5.3.8) |
| `mcs` | DomainParameters::merge — dosłowny MergeDomainParameters (3.3.5.3.3); nieudany merge → drop |
| `server` (walidacje) | originatorId=0x03EA warn (2.2.1.13.2), VCChunkSize 1600..=16256 walidacja (2.2.7.1.10), keyboardFunctionKey=0 (2.2.7.1.6 SHOULD) |
| `server` (slow-path) | fallback do slow-path Share Data Update PDUs dla klientów bez fast-path output (2.2.9.1.1) zamiast zrywania sesji. ↩ Runda 2: fallback niezgodny z 2.2.9.1.1 (#18) |
| `server` (Ultimatum) | Disconnect Provider Ultimatum (ProviderInitiated) przy serwerowym zakończeniu sesji (1.3.1.4/3.3.5.6); rozróżnione źródło rozłączenia; logi Shutdown Request/nietypowych reason-code |
| `linrdp` (main) | enable_autodetect() + enable_heartbeat() + pętla 10 s AutoDetectRttRequest (2.2.14/2.2.16.1 — było martwe w binarym). ↩ Runda 2: sondy bez sprawdzenia flagi klienta, NETCHAR po TCP (#19) |
| `linrdp` (input) | TS_UNICODE → keysym przez ChangeKeyboardMapping + XTEST; TS_SYNC_FLAGS → toggle Cap/Num/ScrollLock (2.2.8.1.1.3.1.1.4/5) |

### Punkty wycofane po weryfikacji (raport audytu nieaktualny)

- **Kolejność License Error przed Demand Active** — ZGODNA ze spec: sekcja 4.1 pokazuje dokładnie `4.1.11 Server License Error PDU` → `4.1.12 Server Demand Active PDU`, a faza 7 (Licensing) poprzedza fazę 9 (Capability Exchange) w 1.3.1.1.
- **X.224 Class 0** — już walidowany: dekoder wymaga dokładnego kodu TPDU (0xE0/0xD0), a klasa jest zakodowana w tym bajcie.
- **Limit 16 kodeków** — spec nie definiuje takiego limitu (bitmapCodecCount: „maximum allowed is 255", pole u8).

## Podsumowanie ogólne (po naprawach)

| Obszar | ZGODNE/NAPRAWIONE | POZOSTAŁE ROZJEBANIA | ŚWIADOMY OMIT |
|---|---|---|---|
| MS-RDPEA (audio out, ścieżka VC) | 21/22 | 0 | UDP RDPSND (CryptKey/WaveEncrypt) |
| RDPBCGR: połączenie/TLS/NLA/licensing | 28/28 | 0 | Standard RDP Security |
| RDPBCGR: capabilities/obraz/input | 22/23 | 0 | orders, bitmap/glyph cache, QOI-guid |
| RDPBCGR: kanały/autodetect/heartbeat/disco/ARC/multitransport | 14/14 | 0 | connect-time autodetect |

↩ Liczby są z rundy 1. Część werdyktów „ZGODNE/NAPRAWIONE" okazała się błędna; patrz „Korekty werdyktów rundy 1".

Pozostałe otwarte (nie-normatywne lub optymalizacyjne):
1. SVC wysyłka zawsze chunkiem 1600 — legalne (≤ negocjowanego rozmiaru), ale nie wykorzystuje większych negocjowanych rozmiarów (mniej ramek). Optymalizacja, nie rozbieżność.
2. Shutdown Denied — ścieżka odmowy nieistnieje, bo serwer zawsze spełnia Shutdown Request (Denied tylko gdy serwer NIE zamierza się zamknąć). Zgodne.
3. `sound.rs` (stub beep) — syntetyczny timestamp; nieużywany w produkcji (`sound_real.rs` poprawny).
4. KANA lock z TS_SYNC — bez odpowiednika w X11, pomijany.
5. ~~Mouse relative — nadal nieobsługiwany (wymaga pointer warp; absolutna mysz domyślnie negocjowana).~~ ↩ 🛠 #21 (X11 i libei).

---

# Raport oryginalny (runda 1, audyt 2026-09-11)

Poniżej oryginalne tabele audytowe z werdyktami sprzed napraw (naprawione pozycje oznaczone 🛠 w tekście). Korekty z rundy 2 oznaczone ↩.

## TOP rozbieżności (priorytet napraw)

1. ~~**🔴 Multitransport na złym kanale**~~ 🛠 — Initiate Multitransport Request i odpowiedź klienta idą po kanale I/O, a spec 2.2.15.1/2.2.15.2 wymaga (MUST) MCS message channel. `server.rs` (wysyłka/odbiór). ↩ Runda 2: żądanie szło po finalizacji zamiast w fazie 8 (1.3.1.1) — #27.
2. ~~**🔴 Set Error Info bez sprawdzenia flagi**~~ 🛠 — 3.3.5.7.1: MUST NOT bez `RNS_UD_CS_SUPPORT_ERRINFO_PDU`; wysyłano bezwarunkowo.
3. ~~**🔴 RDPSND: kanał ginie zamiast ignorować złe PDU**~~ 🛠 — MS-RDPEA 3.1.5 „MUST ignore"; stan `Stop` zabijał audio na całą sesję.
4. ~~**🔴 RDPSND: off-by-one cBlockNo**~~ 🛠 — pierwszy Wave miał blok 0 zamiast 1 (MS-RDPEA 3.3.5.2.1.1).
5. ~~**🟡 Multitransport bez TS_UD_SC_MULTITRANSPORT**~~ 🛠 — serwer inicjował UDP bez ogłoszenia w GCC (2.2.1.4.6). ↩ Runda 2: ogłoszenie bez `SOFTSYNC_TCP_TO_UDP` — #14.
6. ~~**🟡 Odrzucanie klientów bez fast-path output**~~ 🛠 — fallback slow-path (2.2.9.1.1). ↩ Runda 2: fallback był niezgodny z 2.2.9.1.1 — #18.
7. ~~**🟡 RDPSND: brak TSSNDCAPS_ALIVE + brak timeoutów QualityMode/TrainingConfirm**~~ 🛠.
8. ~~**⚪ Autodetect i heartbeat martwe w binarym**~~ 🛠 — włączone w `main.rs`. ↩ Runda 2: sondy bez sprawdzenia flagi klienta i NETCHAR po TCP — #19.

## 1. MS-RDPEA (audio output, MS-RDPSND) — `crates/ironrdp-rdpsnd`, `linrdp/src/sound*.rs`

| Spec | Wymóg | Kod | Werdykt |
|---|---|---|---|
| 2.2.1 SNDPROLOG | msgType 0x01–0x0D, BodySize | `pdu/mod.rs` | ✅ |
| 2.2.2.1 Server Formats PDU | pola LE, pierwszy PDU serwera, V8 | `server.rs` | ✅ |
| 2.2.2.1 + 3.3.5.2.1.1 | pierwszy cBlockNo = cLastBlockConfirmed+1 | startował od 0 | 🔴 → 🛠 |
| 2.2.2.1.1 AUDIO_FORMAT | OPUS 0x704F, PCM 0x0001, cbSize | `pdu/mod.rs` | ✅ |
| 2.2.2.2 Client Formats | dwFlags, wDGramPort big-endian | `pdu/mod.rs` | ✅ |
| 2.2.2.2 wVersion | dowolna wartość wersji | błąd dekodowania przy nieznanej | 🟡 → 🛠 (Version::negotiate) |
| 2.2.2.3 Quality Mode | odebranie ≥6, przechowanie | `server.rs` | ✅ |
| 3.3.5.1.1.3 | timeout QualityMode → DYNAMIC (SHOULD) | brak | ⚪ → 🛠 (5 s) |
| 2.2.2.4 Crypt Key | tylko przy UDP (MUST NOT inaczej) | nigdy nie wysyłany | ⚫ poprawny omit |
| 2.2.3.1/2 Training | echo, wPackSize | `pdu/mod.rs`, `server.rs` | ✅ |
| 3.1.5 | timeout Training Confirm | brak | 🟡 → 🛠 (5 s → terminate) |
| 2.2.3.3/4 WaveInfo+Wave | split, bPad=0, limity | `server.rs` | ✅ |
| 2.2.3.8 Wave Confirm | timestamp = wave ts + held | `sound_real.rs` | ✅ |
| 2.2.3.10 Wave2 | pola + dwAudioTimestamp, ≥8 | `server.rs` | ✅ |
| 2.2.3.10 | wTimeStamp = czas budowy PDU | `sound.rs` syntetyczny (stub, nieużywany) | 🟡 (pozostaje — stub) |
| 2.2.4.1 Volume | tylko przy TSSNDCAPS_VOLUME | `server.rs` | ✅ |
| 2.2.4.2 Pitch | tylko przy TSSNDCAPS_PITCH | brak API | 🟡 → 🛠 (set_pitch) |
| 2.2.3.5–7 UDP Wave/Encrypt/Frag | ścieżka UDP | TODO w kodzie | ⚫ (spec 5.1 zaleca VC) |
| 2.2.3.9 Close | msgType 0x01 | `server.rs` | ✅ |
| 3.1.5 | malformed/out-of-sequence MUST ignore | Stop/Err | 🔴 → 🛠 (warn + ignore) |
| 3.3.5.2 | TSSNDCAPS_ALIVE do transferu | brak sprawdzania | 🟡 → 🛠 |
| 3.3.5.2.1.1 | inkrementacja, wrap 255→0 | `overflowing_add` | ✅ |
| 1.3.2.2 | Wave2 gdy obie wersje ≥8 | `server.rs` | ✅ |

## 2. RDPBCGR — połączenie, TLS/NLA, licensing — `ironrdp-acceptor`, `linrdp/src/{auth,sam,tls}.rs`

| Spec | Wymóg | Kod | Werdykt |
|---|---|---|---|
| 3.3.5.3.1–2 | dekodowanie nego, cookie ignorowane, CORRELATION_INFO | `nego.rs`, `connection.rs` | ✅ |
| 3.3.5.3.2 | selectedProtocol = jeden wspólny; brak → NEG_FAILURE + close | `connection.rs` | ✅ |
| 3.3.5.3.2 | brak nego u klienta → NIE wysyłać danych negocjacyjnych | wysyłano NEG_FAILURE | 🟡 → 🛠 (NoNegotiation + drop) |
| 3.3.5.3.1 | walidacja TPKT/X.224 | dokładne dopasowanie kodów TPDU | ✅ (Class 0 zawarty w kodzie TPDU) |
| 5.4.5.2 | CredSSP po TLS | `connection.rs`, `server.rs` | ✅ |
| 2.2.10.2 | HYBRID_EX → EUAR przed MCS | `lib.rs` | ✅ |
| 5.4.2 | NTLM z sekretem konta (SAM) | `credssp.rs`, `sam.rs` | ✅ |
| 2.2.1.3.2/4.2 | Client/Server Core Info, echo requestedProtocols | `gcc/*`, `connection.rs` | ✅ |
| 3.3.5.3.3 | MergeDomainParameters (SHOULD) | statyczne target() | 🟡 → 🛠 (DomainParameters::merge) |
| 2.2.1.4.3 | Enhanced Security → encryptionMethod=0 | `no_security()` | ✅ |
| 2.2.1.4.4/6 | Network Data, Message Channel Data | `connection.rs` | ✅ |
| 3.3.5.3.5–9 | Erect Domain/Attach User/Channel Join | `channel_connection.rs` | ✅ / 🟡 → 🛠 (Confirm z błędem zamiast drop; repeat-join ignore) |
| 3.3.5.3.10 | Server Security Exchange (tylko Standard) | nieobecny | ⚫ spójne |
| 3.3.5.3.11 | Client Info + ARC | `connection.rs` | ✅ |
| 3.3.5.3.12 | License Error STATUS_VALID_CLIENT | `connection.rs` | ✅ (kolejność wg 4.1.11→4.1.12 — zgodna) |
| 3.3.5.3.13–22 | Demand Active → finalizacja | `connection.rs`, `finalization.rs` | ✅ ↩ 🟡 → 🛠 #27 (finalizacja brała dowolny PDU za kolejny; żądanie multitransport poza fazą 8) |
| 5.3 | brak Standard RDP Security | `main.rs` only hybrid | ⚫ potwierdzone |

## 3. RDPBCGR — capabilities, obraz, input — `ironrdp-server`, `ironrdp-pdu`, `linrdp/src/{capture,input}.rs`

| Spec | Wymóg | Kod | Werdykt |
|---|---|---|---|
| 2.2.1.13.1 | TS_DEMAND_ACTIVE_PDU | `capability_sets/mod.rs` | ✅ |
| 1.3.1.1/4.1 | License Error przed Demand Active | kolejność zgodna (4.1.11→4.1.12) | ✅ (punkt wycofany) |
| 2.2.1.13.2 | originatorId = 0x03EA | niewalidowane | 🟡 → 🛠 (warn) |
| 2.2.7.1.1 General | protocolVersion 0x0200, extraFlags | `general/mod.rs`, `capabilities.rs` | ✅ |
| 2.2.7.1.2 Bitmap | 32bpp, compressionFlag, multipleRectangle | `capabilities.rs` | ✅ |
| 2.2.7.1.3 Order | 84 B; orders nieużywane | zerowe wsparcie | ⚫ |
| 2.2.7.1.4 / 2.2.7.2.6 | Bitmap Cache | nie reklamowany | ⚫ |
| 2.2.7.1.5 Pointer | cacheSize, Large Pointer | `capabilities.rs`, `server.rs` | ✅ |
| 2.2.7.1.6 Input | keyboardFunctionKey SHOULD=0 | =128 | 🟡 → 🛠 (=0) |
| 2.2.7.1.10 VirtualChannel | chunkSize 1600–16256 | bez walidacji | 🟡 → 🛠 (walidacja + warn; wysyłka 1600 = legalne minimum) |
| 2.2.7.2.x Multifragment/LargePointer | progi | `capabilities.rs` | ✅ |
| TS_UD_SC_MULTITRANSPORT | ogłosić przed inicjacją UDP | zawsze None | 🔴/🟡 → 🛠 (announce UDP/FECR) ↩ 🔴 → 🛠 #14 (brak `SOFTSYNC_TCP_TO_UDP`) |
| 2.2.7.2.10 Bitmap Codecs | GUID-e, NSCodec CAPS | `bitmap_codecs/mod.rs` | ✅ (QOI/QOIZ = rozszerzenie; limit 16 wycofany — max 255 wg spec) |
| 2.2.9.1.1.2 | fragmentacja FP output | `encoder/fast_path.rs` | ✅ |
| 2.2.9.1.1.3.1 | TS_BITMAP_DATA | `basic_output/bitmap` | ✅ (FIXME szerokość %4 pozostaje) |
| 2.2.9.1.1.1 | Surface Commands + Frame Marker | `encoder/mod.rs` | ✅ |
| 2.2.8.1.1.x | FP/slow input, kody zdarzeń | `input/fast_path.rs` | ✅ |
| 2.2.8 (iniekcja) | TS_UNICODE / TS_SYNC | ignorowane | 🟡 → 🛠 (keysym remap + XTEST; toggle locków) |
| 3.3.5.3.x | fallback slow-path output | Err przy braku fast-path | 🔴 minor → 🛠 (slow-path Update PDUs) ↩ 🔴 → 🛠 #18 (niezgodny z 2.2.9.1.1.3.1 i 2.2.9.1.1.4) |
| 3.3.5.3.3 | clamp desktop size | `server.rs` | ✅ |
| 1.3.1.3 / 2.2.3.1 | Deactivate All + re-negocjacja | `server.rs` | ✅ ↩ 🟡 → 🛠 #17, #27 (bez EGFX resize jej nie uruchamiał; reaktywacja gubiła tunel UDP) |

## 4. RDPBCGR — kanały, autodetect, heartbeat, disco, ARC, multitransport

| Spec | Wymóg | Kod | Werdykt |
|---|---|---|---|
| 1.3.3 / 3.2.5.x | SVC chunking 1600, reasemblacja | `ironrdp-svc` | ✅ |
| 2.2.14.1/2 | struktury autodetect | `autodetect.rs` | ✅ |
| 2.2.14.3/4 | framing po message channel | `server.rs` | ✅ |
| 3.3.5.x | continuous autodetect | `autodetect.rs` | ✅ (biblioteka) |
| — | autodetect w aplikacji | nie włączony | ⚪ → 🛠 (main.rs) ↩ 🟡 → 🛠 #19 (tylko przy `RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT`, bez NETCHAR po TCP) |
| 2.2.16.1 | Heartbeat + gating + idle-only | `heartbeat.rs`, `server.rs` | ✅ (biblioteka) |
| — | heartbeat w aplikacji | nie włączony | ⚪ → 🛠 (main.rs) |
| 2.2.3.1.1 | Deactivate All shareId=0 | `server.rs` | ✅ |
| 2.2.2.1/2 | Shutdown Request/Denied | brak ścieżki odmowy | 🟡 (zgodne — serwer zawsze spełnia; dodany log) |
| 3.3.5.6 | Ultimatum przy rozłączeniu serwera | nigdy niewysyłany | 🟡 → 🛠 (ProviderInitiated, best-effort) |
| 2.2.5.1.1 | Set Error Info pduSource=0 | `server.rs` | ✅ ↩ 🔴 → 🛠 #11 (bez nagłówków Share Control i Share Data) |
| 3.3.5.7.1 | Error Info tylko z flagą ERRINFO | bezwarunkowo | 🔴 → 🛠 (gating) |
| 2.2.4.2/3 + 5.5 | ARC cookies, HMAC-MD5, rotacja | `session_info`, `server.rs` | ✅ ↩ 🟡 → 🛠 #20 (złe cookie odrzucało połączenie zamiast użyć poświadczeń, 3.3.5.3.11) |
| 3.3.5.4.3 | autoreconnect pomija re-auth | `server.rs` | ✅ |
| 2.2.15.1 | struktura Initiate MT Request | `multitransport.rs` | ✅ |
| 2.2.15.1/2 | multitransport PDU po message channel (MUST) | kanał I/O | 🔴 → 🛠 (message channel + fallback) ↩ 🟡 → 🛠 #27 (żądanie w fazie 8, nie po finalizacji) |
| 3.3.5.8 | gating na zgodę klienta | `server.rs` | ✅ ↩ 🔴 → 🛠 #14 (bez sprawdzenia `SOFTSYNC_TCP_TO_UDP` klienta; czekanie na S_OK) |
| 2.2.5.x | share headers, chunking SVC | `server.rs`, `ironrdp-svc` | ✅ |

## Wnioski (po naprawach)

- Wszystkie naruszenia MUST z audytu zostały usunięte; pozostałe rozbieżności to świadome omity (zwykle zalecane przez samą spec jako deprecated) lub optymalizacje bez znaczenia normatywnego.
- Świadome omity: Standard RDP Security (5.3), ścieżka UDP RDPSND z RC4/SHA-1 (MS-RDPEA 5.1 zaleca VC), orders/glyph/brush/bitmap cache, connect-time autodetect (warstwa PDU gotowa), RemoteFX video-mode.
- ↩ Runda 2, z zakresem rozszerzonym o DVC, EGFX, mikrofon, UDP i DISP, znalazła 17 kolejnych rozbieżności i kilka błędnych werdyktów rundy 1. Wszystkie naprawiono w #8–#27; patrz „Runda 2".
- Odnośniki: `docs/microsoft-docs/ms-rdpbcgr.txt`, `docs/microsoft-docs/ms-rdpea.txt` (ekstrakt z docx); w rundzie 2 także `ms-rdpedyc.txt`, `ms-rdpegfx.txt`, `ms-rdpeai.txt`, `ms-rdpemt.txt`, `ms-rdpeudp.txt`, `ms-rdpedisp.txt`.
