# doc-diffs — rozbieżności kodu względem dokumentacji Microsoft

Data: 2026-09-11. Zakres: `docs/microsoft-docs/` = **[MS-RDPBCGR]** (pełny spec, rev. 260309) + **[MS-RDPEA]** (Audio Output Virtual Channel Extension, rev. 240423). Weryfikacja server-side (LinRDP = serwer RDP; klient = mstsc/FreeRDP).

Legenda werdyktów:
- ✅ **ZGODNE** — kod spełnia wymóg spec (MUST/SHOULD lub struktura bajtowa).
- 🟡 **CZĘŚCIOWO** — działa, ale odstaje od reguły SHOULD / walidacji / drobnego MUST.
- 🔴 **ROZJEBANE** — jawne naruszenie normatywne MUST / MUST NOT.
- ⚪ **BRAK W KODZIE** — brak implementacji wymogu.
- ⚫ **ŚWIADOMY OMIT** — celowo nieimplementowane (deprecated / poza zakresem), struktura PDU zwykle gotowa.

## Podsumowanie ogólne

| Obszar | ZGODNE | CZĘŚCIOWO | ROZJEBANE | BRAK | ŚWIADOMY OMIT |
|---|---|---|---|---|---|
| MS-RDPEA (audio out) | 15 | 5 | 2 | 1 | 2 |
| RDPBCGR: połączenie/TLS/NLA/licensing | 24 | 4 | 0 | 0 | 1 |
| RDPBCGR: capabilities/obraz/input | 15 | 5 | 1 (+1 minor) | 0 | 3 |
| RDPBCGR: kanały/autodetect/heartbeat/disco/ARC/multitransport | 10 | 4 | 2 | 1 (aplikacja) | 1 |

Ścieżka krytyczna (NLA + podstawowy obraz + dźwięk VC) jest zgodna na ~85–90%. Pojedyncze rozbieżności nie blokują mstsc/FreeRDP, ale poniższe punkty warto naprawić.

## TOP rozbieżności (priorytet napraw)

1. **🔴 Multitransport na złym kanale** — Initiate Multitransport Request i odpowiedź klienta idą po kanale I/O, a spec 2.2.15.1/2.2.15.2 wymaga (MUST) MCS message channel. `crates/ironrdp-server/src/server.rs:3712` (wysyłka), `server.rs:3808-3835` (odbiór).
2. **🔴 Set Error Info bez sprawdzenia flagi** — 3.3.5.7.1: MUST NOT wysyłać Set Error Info PDU do klienta bez `RNS_UD_CS_SUPPORT_ERRINFO_PDU`; kod wysyła bezwarunkowo (znany, udokumentowany gap — `AcceptorResult` nie eksponuje flagi). `server.rs:2763-2793`.
3. **🔴 RDPSND: kanał ginie zamiast ignorować złe PDU** — MS-RDPEA 3.1.5 wymaga „MUST ignore malformed/unrecognized/out-of-sequence"; u nas nieoczekiwany PDU w stanie Waiting* → `state = Stop` (audio na całą sesję). `crates/ironrdp-rdpsnd/src/server.rs:310-336`.
4. **🔴 RDPSND: off-by-one cBlockNo** — pierwszy Wave/Wave2 ma cBlockNo=0, a przy cLastBlockConfirmed=0 wysłanym w Server Formats PDU pierwszy blok MUSI być 1 (MS-RDPEA 3.3.5.2.1.1). `pdu/mod.rs:357`, `server.rs:168`.
5. **🟡 Multitransport bez TS_UD_SC_MULTITRANSPORT** — serwer wysyła Initiate Multitransport Request, choć nigdy nie ogłasza wsparcia w GCC (`connection.rs:1078` = None); klient zgodny ze spec może odrzucić UDP.
6. **🟡 Odrzucanie klientów bez fast-path output** — brak fallbacku do slow-path output (`server.rs:3592-3595`); spec dopuszcza serwer slow-path.
7. **🟡 RDPSND: brak sprawdzenia TSSNDCAPS_ALIVE** przed streamowaniem fal (MS-RDPEA 3.3.5.2) + brak timeoutów na QualityMode/TrainingConfirm.
8. **⚪ Autodetect i heartbeat niedostępne w binarym** — biblioteka zgodna ze spec, ale `linrdp/src/main.rs` nie wywołuje `enable_autodetect()`/`enable_heartbeat()` (funkcjonalność martwa w aplikacji).

---

## 1. MS-RDPEA (audio output, MS-RDPSND) — `crates/ironrdp-rdpsnd`, `linrdp/src/sound*.rs`

| Spec | Wymóg | Kod | Werdykt |
|---|---|---|---|
| 2.2.1 SNDPROLOG | msgType 0x01–0x0D, BodySize, semantyka dla msgType=0x02 | `pdu/mod.rs:16-26,1207-1272` | ✅ |
| 2.2.2.1 Server Formats PDU | kolejność pól LE, pierwszy PDU serwera, wVersion=V8 | `pdu/mod.rs:328-396`, `server.rs:391-403` | ✅ |
| 2.2.2.1 + 3.3.5.2.1.1 | pierwszy cBlockNo = cLastBlockConfirmed+1 | `server.rs:168` startuje od 0 | 🔴 off-by-one |
| 2.2.2.1.1 AUDIO_FORMAT | wFormatTag/cbSize/data; OPUS 0x704F, PCM 0x0001 | `pdu/mod.rs:93,198,215-326` | ✅ |
| 2.2.2.2 Client Formats | dwFlags bitflags, wDGramPort **big-endian** | `pdu/mod.rs:404-499` | ✅ |
| 2.2.2.2 wVersion | dowolna wartość wersji | TryFrom tylko 2/5/6/8 — nowsza wersja klienta = błąd dekodowania | 🟡 |
| 3.2/3.3.5.1.1.2 | lista formatów klienta podzbiorem serwera | `negotiate_formats` — przecięcie, brak jawnej walidacji podzbioru | ✅ (funkcjonalnie) |
| 2.2.2.3 Quality Mode | odebranie przy wersji ≥6, przechowanie | `server.rs:320-334` | ✅ |
| 3.3.5.1.1.3 | timeout QualityMode → DYNAMIC (SHOULD) | brak timera — stan wisi | ⚪ |
| 2.2.2.4 Crypt Key | wysyłany tylko przy UDP (MUST NOT inaczej) | nigdy nie wysyłany, brak UDP | ⚫ poprawny omit |
| 2.2.3.1/2.2.3.2 Training | echo wTimeStamp/wPackSize, wPackSize=0 gdy brak danych | `pdu/mod.rs:618-722`, `server.rs:325,336` | ✅ |
| 3.1.5 | timeout na Training Confirm | brak timera | 🟡 |
| 2.2.3.3/2.2.3.4 WaveInfo+Wave | split 4B prefix + WaveData, bPad=0, limity długości | `pdu/mod.rs:724-907`, `server.rs:224-247` | ✅ (poza cBlockNo) |
| 2.2.3.8 Wave Confirm | semantyka timestamp = wave ts + held time | `sound_real.rs:302-326` (FIFO + wrapping_sub) | ✅ |
| 2.2.3.10 Wave2 | pola + dwAudioTimestamp, wersja ≥8 | `pdu/mod.rs:1029-1104`, `server.rs:215-223` | ✅ |
| 2.2.3.10 | wTimeStamp = czas budowy PDU | `sound.rs:90` — syntetyczny licznik (stub); `sound_real.rs:223` OK | 🟡 |
| 2.2.4.1 Volume | tylko gdy TSSNDCAPS_VOLUME, L=low word | `server.rs:254-265` | ✅ |
| 2.2.4.2 Pitch | tylko gdy TSSNDCAPS_PITCH | struktura gotowa, brak API wysyłki | 🟡 |
| 2.2.3.5–2.2.3.7 UDP Wave/Encrypt/Frag | ścieżka UDP | nieimplementowana (TODO w `pdu/mod.rs:28`) | ⚫ (spec 5.1 sam zaleca VC) |
| 2.2.3.9 Close | msgType 0x01 | `server.rs:267-269` | ✅ |
| 3.1.5 | malformed/out-of-sequence MUST be ignored | `server.rs:310-336` — zamiast ignorować: Stop/Err | 🔴 |
| 3.3.5.2 | TSSNDCAPS_ALIVE wymagane do transferu | `wave()` nie sprawdza | 🟡 |
| 3.3.5.2.1.1 | inkrementacja cBlockNo, wrap 255→0 | `overflowing_add(1)` | ✅ |
| 1.3.2.2 | Wave2 gdy obie wersje ≥8 | `server.rs:215` | ✅ |

## 2. RDPBCGR — połączenie, TLS/NLA, licensing — `ironrdp-acceptor`, `ironrdp-tls`, `linrdp/src/{auth,sam,tls}.rs`

| Spec | Wymóg | Kod | Werdykt |
|---|---|---|---|
| 3.3.5.3.1–3.3.5.3.2 | dekodowanie nego, ignorowanie cookie/routingToken, poprawny CORRELATION_INFO | `nego.rs:224-440`, `connection.rs:522-535` | ✅ |
| 3.3.5.3.2 | selectedProtocol = dokładnie jeden wspólny; brak wspólnego → NEG_FAILURE + close | `connection.rs:537-573` | ✅ |
| 3.3.5.3.2 | brak nego data u klienta → NIE wysyłać danych negocjacyjnych (MUST NOT) | klient bez nego dostaje RDP_NEG_FAILURE (praktyka Windows, formalne naruszenie) — `connection.rs:545-573` | 🟡 |
| 3.3.5.3.1 | walidacja TPKT/X.224 (Class 0) | brak jawnej weryfikacji Class 0 (pola mają być ignorowane) | 🟡 |
| 5.4.5.2 | CredSSP po TLS przed Basic Settings | `connection.rs:593-610`, `server.rs:1108-1137` | ✅ |
| 2.2.10.2 | HYBRID_EX → Early User Auth Result przed MCS | `lib.rs:131-149` | ✅ |
| 5.4.2 | NTLM z sekretem konta (SAM) | `credssp.rs:54-81`, `linrdp/src/{sam,auth}.rs` | ✅ |
| 2.2.1.3.2/2.2.1.4.2 | Client/Server Core Info, echo requestedProtocols | `gcc/core_data/*`, `connection.rs:635-646,1054-1080` | ✅ |
| 3.3.5.3.3 | MergeDomainParameters (SHOULD) | statyczne `DomainParameters::target()`, brak walidacji min/max — `connection.rs:752-757` | 🟡 |
| 2.2.1.4.3 | Enhanced Security → encryptionMethod=0/level=0 | `no_security()` | ✅ |
| 2.2.1.4.4/2.2.1.4.6 | Network Data (ioChannel+IDs), Message Channel Data | `connection.rs:739-776,1071-1077` | ✅ |
| 3.3.5.3.5–3.3.5.3.9 | Erect Domain/Attach User/Channel Join Confirm | `channel_connection.rs:82-168` | ✅ / 🟡 (nieoczekiwany channel_id → zerwanie zamiast Confirm z result≠0 — SHOULD) |
| 3.3.5.3.10 | Server Security Exchange (tylko Standard Security) | nieobecny — spójne z brakiem STANDARD | ⚫ |
| 3.3.5.3.11 | Client Info PDU + ARC | `connection.rs:820-872` | ✅ |
| 3.3.5.3.12 / 2.2.1.12.1.3 | License Error STATUS_VALID_CLIENT | `connection.rs:874-899` | ✅ (kolejność vs diagram 1.3.1.1 — patrz §3 pkt 2) |
| 3.3.5.3.13.1–3.3.5.3.22 | Demand Active → Monitor Layout (gating) → Confirm Active → Synchronize/Cooperate/Control/Font | `connection.rs:901-1044`, `finalization.rs` | ✅ |
| 5.3 | brak Standard RDP Security | `main.rs:94` tylko `with_hybrid`; brak SSL w fladze | ⚫ potwierdzone (klient only-TLS dostaje HYBRID_REQUIRED_BY_SERVER) |

## 3. RDPBCGR — capabilities, obraz, input — `ironrdp-server`, `ironrdp-pdu/capability_sets`, `linrdp/src/{capture,input}.rs`

| Spec | Wymóg | Kod | Werdykt |
|---|---|---|---|
| 2.2.1.13.1 | TS_DEMAND_ACTIVE_PDU struktura | `capability_sets/mod.rs:82-247` | ✅ |
| 1.3.1.1 (diagram) | Demand Active przed License Exchange | License Error wysyłany **przed** Demand Active — `connection.rs:874-933` | 🟡 (klienty akceptują) |
| 2.2.1.13.2 | originatorId Confirm Active = 0x03EA (MUST) | dekodowane, nie sprawdzane — `connection.rs:995-1000` | 🟡 |
| 2.2.7.1.1 General | protocolVersion 0x0200, extraFlags, refresh/suppress | `general/mod.rs`, `capabilities.rs:25-38` | ✅ |
| 2.2.7.1.2 Bitmap | 32bpp, compressionFlag, multipleRectangle | `bitmap/mod.rs`, `capabilities.rs:40-50` | ✅ |
| 2.2.7.1.3 Order | struktura 84 B; orderSupport | wysyłany, ale orders nieużywane (zerowe wsparcie) | ⚫ |
| 2.2.7.1.4 / 2.2.7.2.6 | Bitmap Cache / Cache V3 | dekoder gotowy, serwer nie reklamuje | ⚫ |
| 2.2.7.1.5 Pointer | cacheSize 2048/2048, honorowanie 0 i Large Pointer | `capabilities.rs:67-72`, `server.rs:3640-3668` | ✅ |
| 2.2.7.1.6 Input | maski zgodne; keyboardFunctionKey SHOULD=0 | =128 — `capabilities.rs:74-88` | 🟡 |
| 2.2.7.1.10 VirtualChannel | chunkSize 1600–16256 walidowany | nie walidowany przy dekodowaniu | 🟡 |
| 2.2.7.2.x Multifragment/LargePointer | progi 38055/608299 | `capabilities.rs:97-123` | ✅ |
| TS_UD_SC_MULTITRANSPORT (2.2.1.4.6) | ogłosić wsparcie przed inicjacją UDP | zawsze `None` — `connection.rs:1078`, a serwer wysyła Initiate Multitransport (`server.rs:3705-3720`) | 🔴/🟡 |
| 2.2.7.2.10 Bitmap Codecs | GUID-e (NSCodec/RemoteFX/ImageRemoteFX/Ignore), NSCodec CAPS clamp 1–7 | `bitmap_codecs/mod.rs`, `server.rs:3616-3660`; QOI/QOIZ = rozszerzenie poza spec | ✅ (+⚫ niestandardowe GUID-y) |
| 2.2.9.1.1.2 | fragmentacja FP output SINGLE/FIRST/NEXT/LAST | `encoder/fast_path.rs:51-108` | ✅ |
| 2.2.9.1.1.3.1 | TS_BITMAP_DATA rect inclusive, compr header | `basic_output/bitmap/mod.rs`, `encoder/bitmap.rs` (FIXME: szerokość %4) | ✅ |
| 2.2.9.1.1.1 | Surface Commands + Frame Marker | `capabilities.rs:61-65`, `encoder/mod.rs:467-480` | ✅ |
| 2.2.8.1.1.x | nagłówki FP/slow input, kody zdarzeń i flagi | `input/fast_path.rs:59-264`, `server.rs:4013-4041` | ✅ |
| 2.2.8 (aplikacyjnie) | TS_UNICODE / TS_SYNC | dekodowane, ale iniekcja XTEST ignoruje — `linrdp/src/input.rs:103-124` | 🟡 |
| 3.3.5.3.x | fallback do slow-path output | klient bez FASTPATH_OUTPUT → błąd połączenia — `server.rs:3592-3595` | 🔴 minor |
| 3.3.5.3.3 | clamp desktop size zamiast disconnect | `server.rs:339,3603-3613` | ✅ |
| 1.3.1.3 / 2.2.3.1 | Deactivate All (shareId=0) + re-negocjacja | `server.rs:2691-2695,4291-4311` | ✅ |

## 4. RDPBCGR — kanały statyczne, autodetect, heartbeat, rozłączanie, auto-reconnect, multitransport

| Spec | Wymóg | Kod | Werdykt |
|---|---|---|---|
| 1.3.3 / 3.2.5.x | SVC chunking FIRST/LAST, reasemblacja, 1600 | `ironrdp-svc/src/lib.rs:174-475,869` | ✅ (chunk zawsze 1600, negocjowany rozmiar niewykorzystany — 🟡 kosmetycznie) |
| 2.2.14.1/2.2.14.2 | struktury autodetect req/rsp (RTT/BW/NETCHAR, kody 0x0001/0x0014/0x0429/0x0840…) | `autodetect.rs:285-431,632-735` | ✅ |
| 2.2.14.3/2.2.14.4 | framing po MCS message channel | `server.rs:4113-4131,3895-3970` | ✅ |
| 3.3.5.x | continuous autodetect (RTT + BW bez payloadu) | `ironrdp-server/src/autodetect.rs:143-253` | ✅ (biblioteka) |
| 1.3.9 | connect-time autodetect | konstruktory gotowe, brak ścieżki | ⚫ |
| 3.3.5.x | włączenie autodetect w aplikacji | `main.rs` nie wysyła `AutoDetectRttRequest` | ⚪ w binarym |
| 2.2.16.1 | Heartbeat PDU + gating SUPPORT_HEARTBEAT + idle-only | `heartbeat.rs:46-66`, `server.rs:3264,3437-3474` | ✅ (biblioteka) |
| 2.2.16.1 | heartbeat w aplikacji | `main.rs` nie wywołuje `enable_heartbeat()` | ⚪ w binarym |
| 2.2.3.1.1 | Deactivate All shareId=0 | `server.rs:4291-4309` | ✅ |
| 2.2.2.1/2.2.2.2 | Shutdown Request / Shutdown Denied | Request kończy sesję; brak ścieżki odmowy (`headers.rs:540` nieużywany) | 🟡 |
| 3.3.5.6 | serwer może wysłać Disconnect Provider Ultimatum | nigdy nie wysyłany; obce reason codes ignorowane bez logu | 🟡 |
| 2.2.5.1.1 | Set Error Info pduSource=0 | `server.rs:2771-2793` | ✅ |
| 3.3.5.7.1 | MUST NOT wysyłać Error Info bez RNS_UD_CS_SUPPORT_ERRINFO_PDU | wysyłane bezwarunkowo (KNOWN GAP — flaga nieeksponowana) — `server.rs:2763-2770` | 🔴 |
| 2.2.4.2/2.2.4.3 + 5.5 | ARC cookies, HMAC-MD5 securityVerifier, rotacja godzinowa | `logon_extended.rs:104-172`, `client_info.rs:374-387`, `server.rs:1546-1640,3425-3435` | ✅ |
| 3.3.5.4.3 | autoreconnect pomija re-autentykację | `server.rs:3497-3521` | ✅ |
| 2.2.15.1 | Initiate Multitransport Request — struktura | `multitransport.rs`, `server.rs:4269-4288` | ✅ |
| 2.2.15.1/2.2.15.2 | multitransport PDU **wyłącznie po MCS message channel** (MUST) | wysyłka i odbiór na kanale I/O — `server.rs:3712,3808-3835` | 🔴 |
| 3.3.5.8 | gating multitransport na zgodę klienta (GCC) | `server.rs:3707-3719` | ✅ (ale patrz TS_UD_SC wyżej) |
| 2.2.5.x | share headers, chunking SVC w SendDataIndication | `server.rs:~4160`, `ironrdp-svc` | ✅ |

---

## Wnioski

- **Największe realne ryzyka interoperacyjne:** multitransport (zły kanał + brak TS_UD_SC_MULTITRANSPORT — klient ściśle zgodny ze spec odrzuci UDP) oraz wrażliwość audio na jeden uszkodzony PDU (RDPSND `Stop` zamiast ignore).
- **Szybkie fixy (niska kosztowność):** cBlockNo off-by-one, sprawdzenie TSSNDCAPS_ALIVE, timeouty QualityMode/TrainingConfirm, włączenie `enable_autodetect()`/`enable_heartbeat()` w `main.rs`, eksport flagi ERRINFO z acceptora.
- **Świadome omity** (Standard RDP Security, ścieżka UDP RDPSND z RC4/SHA-1, orders/glyph/brush cache, connect-time autodetect) są spójne z polityką projektu i zwykle zalecane przez samą spec (deprecated).
- Pełne szczegóły z file:line w tabelach powyżej; odnośniki do dokumentacji: `docs/microsoft-docs/ms-rdpbcgr.txt`, `docs/microsoft-docs/ms-rdpea.txt` (ekstrakt z docx).
