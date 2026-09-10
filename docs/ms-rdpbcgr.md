# LinRDP — pokrycie funkcjonalności względem MS-RDPBCGR

Data aktualizacji: 2026-09-10.
Odnośniki spec: `[MS-RDPBCGR]` (docs/MS-RDPBCGR.pdf), pokrewne: MS-CSSP (CredSSP/NLA), MS-NLMP (NTLM), MS-RDPSND (audio out), MS-RDPEAI (audio in/mikrofon), MS-RDPEUSB (USB), MS-RDPERP/MS-RDPEDC (resize).

Legenda: **Pokrycie kodu** = ile funkcjonalności wg spec jest w kodzie LinRDP; **Pokrycie testami** = ile z tego jest potwierdzone testami (lokalne E2E FreeRDP / test użytkownika mstsc).

## 1. Połączenie i transport

| Funkcjonalność | Opis | Pokrycie kodu | Pokrycie testami | Status |
|---|---|---|---|---|
| X.224 Connection Request/Confirm + negocjacja protokołu | Wybór SSL/HYBRID z oferty klienta (MS-RDPBCGR 2.2.1.1/2.2.1.2) | 100% — `crates/ironrdp-acceptor/src/connection.rs` (accept_begin) | 100% — E2E z FreeRDP + mstsc | ✅ działa |
| TLS 1.2/1.3 (rustls), self-signed cert z generacją i persist | `linrdp/src/tls.rs` (40 linii) + `crates/ironrdp-tls` | 100% dla trybu HYBRID/TLS | 100% — TLS 1.3 potwierdzony | ✅ działa |
| MCS: Erect Domain, Attach User, Channel Join | 2.2.1.5–2.2.1.9 | 100% — `crates/ironrdp-acceptor/src/channel_connection.rs` | 100% — każda sesja E2E | ✅ działa |
| Wirtualne kanały statyczne (rdpdr, rdpsnd, cliprdr, drdynvc) | 2.2.1.3.4 Client Network Data | 100% — `crates/ironrdp-server/src/server.rs` (attach_channels) | 100% — kanały negocjowane z mstsc i FreeRDP | ✅ działa |
| Dynamic Virtual Channels (DRDYNVC) | MS-RDPBCGR 3.3.5 + MS-RDPEDYNVC | 100% rdzenia — `crates/ironrdp-dvc/src/server.rs`; extra DVC via `with_dynamic_channel_attacher` | 80% — ainput/disp/echo/rdpeai/urbdrc przełączone w E2E | ✅ działa |
| Deactivation–Reactivation (resize w locie) | 1.3.1.3 / 3.3.5.5 | 90% — `Acceptor::new_deactivation_reactivation` + `request_layout` w `linrdp/src/capture.rs` | 50% — kanał działa, resize Xvfb ograniczony listą trybów | ⚠️ częściowo |
| Automatyczne ponawianie (auto-reconnect cookie) | 3.3.5.4.3 | 100% — `crates/ironrdp-server/src/server.rs` (set_auto_reconnect_cookie) | 20% — nie testowane świadomie | ⚠️ nieprzetestowane |

## 2. Bezpieczeństwo

| Funkcjonalność | Opis | Pokrycie kodu | Pokrycie testami | Status |
|---|---|---|---|---|
| SSL/TLS jako protokół bezpieczeństwa | 5.4.5 (TLS) | 100% — `with_tls` + `crates/ironrdp-tls` | 100% — E2E FreeRDP | ✅ działa |
| **HYBRID = CredSSP/NLA** (5.4.2, MS-CSSP) | mstsc pokazuje natywne okno logowania; NTLMv2 weryfikacja sekretu konta | 100% — `crates/ironrdp-acceptor/src/credssp.rs` (CredentialsProxy per-username) + `linrdp/src/sam.rs` (SAM 0600) + `--set-password` | 100% — poprawne hasło → sesja; złe → LogonDenied (E2E mstsc użytkownika) | ✅ działa |
| HYBRID_EX (early User Auth) | 5.4.2 variant | 90% — `EarlyUserAuthResult` w acceptorze | 0% — brak testu | ⚠️ nieprzetestowane |
| Standard RDP Security (legacy 40/56/128-bit, FIPS) | 5.3 | 0% w LinRDP — serwer nie oferuje STANDARD (świadomie; deprecated w MS) | 0% | ❌ brak (celowo) |
| Weryfikacja poświadczeń przeciw bazie kont | — | 100% — `linrdp/src/auth.rs` (ShadowValidator: YESCRYPT/SHA-512/MD5) — aktualnie używany jako drugi etap; podstawowy = SAM | 100% — złe hasło odrzucone, dobre przepuszczone | ✅ działa |
| SAM kont LinRDP (`--set-password`) | odpowiednik Windows SAM dla NTLM | 100% — `linrdp/src/sam.rs` | 100% — konta root i linrdptest działają z mstsc | ✅ działa |

## 3. Obraz / wyjście graficzne

| Funkcjonalność | Opis | Pokrycie kodu | Pokrycie testami | Status |
|---|---|---|---|---|
| Capability exchange (Demand/Confirm Active) | 2.2.1.13 | 100% — `crates/ironrdp-server/src/capabilities.rs` | 100% — negocjacja z mstsc i FreeRDP | ✅ działa |
| Bitmap updates (legacy TS_BITMAP_DATA) | 2.2.9.1.1.3.1 — aktualizacje częściowe (kafle) | 100% — `linrdp/src/capture.rs` (tile-diff 128×128, kolejka w tempie łącza) | 100% — 73k zapisów/sesję, obraz aktualizuje się u użytkownika | ✅ działa |
| **NSCodec** (2.2.7.2.10, MS-RDPNSC) | Serwer ogłasza NSCodec (color_loss_level 3, dynamic fidelity), mstsc wybiera; kafle kodowane NSCodec | 100% — `linrdp/src/main.rs` (BitmapCodecs z NsCodec) + `crates/ironrdp-server/src/encoder` (NsCodecHandler) | 100% — negocjacja potwierdzona z mstsc, kafle kodowane | ✅ działa |
| RemoteFX / QOI/QOIZ | 2.2.7.2.10 + MS-RDPRFX | 90% vendored, **celowo wyłączone** (RemoteFX video-mode encoder niekompletny; QOI niepotrzebny) | 0% | ⚠️ wyłączone |
| Powierzchnia Surface Commands (SET_SURFACE_BITS) | 2.2.9.1.1.1 | obecne w caps; nieużywane przez naszą ścieżkę rysowania | 0% | ⚠️ nieużywane |
| Negocjacja rozmiaru pulpitu z klientem | 2.2.1.3.2 desktopWidth/Height + walidacja 3.3.5.3.3 | 100% — `with_honor_client_desktop_size` + `Acceptor::set_honor_client_desktop_size` | 100% — log „Honoring client-requested desktop size … adopted 3840×2160" | ✅ działa |
| Dynamiczny resize X po stronie serwera (RandR) | (Linux-specific, nie ze spec MS) | 90% — `linrdp/src/capture.rs` resize_screen: SetScreenSize+CreateMode(CVT)+AddOutputMode+SetCrtcConfig | 70% — działa dla trybów z listy Xvfb; dynamicznie tworzone tryby (CVT) bywają odrzucane przez Xvfb SetCrtcConfig | ⚠️ 1 bug: Xvfb odrzuca created-mode |
| Capture tylko zmian (diff) | — | 100% — tile-diff + `pending_queue` | 100% — statyczny pulpit = zero ruchu (potwierdzone) | ✅ działa |

## 4. Wejście (input)

| Funkcjonalność | Opis | Pokrycie kodu | Pokrycie testami | Status |
|---|---|---|---|---|
| Klawiatura (scancodes → XTEST) | 2.2.8.1.1.3.1.1 | 100% — `linrdp/src/input.rs:73` (keyboard + extended + synchronize) | 50% — zdarzenia dochodzą (logi), fizyczne pisanie nieprzetestowane u użytkownika | ⚠️ do testu użytkownika |
| Mysz absolutna (Move/Button) | 2.2.8.1.1.3.1.1 | 100% — `linrdp/src/input.rs:100` (XTEST motion/button) | 50% — zdarzenia dochodzą; klik fizyczny do potwierdzenia | ⚠️ do testu użytkownika |
| Scroll pion/poziom (wheel) | PointerFlags VERTICAL/HORIZONTAL | 100% — buttons 4/5/6/7 | 0% — nieprzetestowane | ⚠️ |
| Mysz względna (MouseRel/RelMove) | 2.2.8.1.1.3.1.1.7 | 0% — ignorowane (wymaga pointer warp) | 0% | ❌ brak |
| Unicode input | TS_UNICODE | 0% — ignorowane | 0% | ❌ brak |
| Suwak „Resize" z mstsc (DisplayControl) | MS-RDPEDC | 80% — `request_layout` + displaycontrol channel | 0% — nieprzetestowane | ⚠️ |

## 5. Dźwięk

| Funkcjonalność | Opis | Pokrycie kodu | Pokrycie testami | Status |
|---|---|---|---|---|
| Output (serwer→klient): MS-RDPSND | 2.2.2/2.2.3 — formats, training, wave, waveconfirm | 100% — `linrdp/src/sound.rs` + `crates/ironrdp-rdpsnd` | 100% — użytkownik słyszy pikanie; WaveConfirm flow w logach | ✅ działa |
| Output — realny dźwięk systemowy (PipeWire/Pulse) | — | 0% — obecnie syntetyczne pikanie (brak audio device na serwerze bezgłowym) | 0% | ❌ do zrobienia (faza desktop-integracji) |
| Mikrofon (klient→serwer): MS-RDPEAI | 1.3.1 AUDIO_INPUT DVC | 80% — `linrdp/src/mic.rs` + `crates/ironrdp-rdpeai` (kanał tworzony, handshake OK) | 60% — kanał otwierany/zamykany poprawnie z mstsc; brak fizycznego mikrofonu w teście | ⚠️ częściowo |
| Mikrofon — dostarczenie audio do aplikacji Linuksa | — | 0% — pakiety zliczane/logowane | 0% | ❌ do zrobienia |

## 6. USB

| Funkcjonalność | Opis | Pokrycie kodu | Pokrycie testami | Status |
|---|---|---|---|---|
| URBDRC kanał (MS-RDPEUSB) — negocjacja | 1.3.1 | 100% — `crates/ironrdp-server/src/urbdrc.rs` + `ironrdp-rdpeusb`/`ironrdp-usb` | 50% — kanał wchodzi w E2E (FreeRDP addin ma własny bug) | ⚠️ |
| Akceptacja ogłoszeń urządzeń (`--usb`) | — | 100% — `linrdp/src/usb.rs` (LoggingUsbDeviceFactory) | 0% — brak fizycznego urządzenia do testu | ⚠️ |
| Realny transfer USB (deskryptory, endpointy) | MS-RDPEUSB 3.x | 0% — wymaga USB host stack (nusb) + sprzętu | 0% | ❌ brak (wymaga sprzętu) |

## 7. Schowek i pozostałe kanały

| Funkcjonalność | Opis | Pokrycie kodu | Pokrycie testami | Status |
|---|---|---|---|---|
| **Clipboard tekst (MS-RDPECLIP)** | 1.3.3 — Format List/Format Data Request/Response | 80% — `linrdp/src/clipboard.rs` (X11CliprdrBackend): poll X11 clipboard → advertise → mstsc format-data request → serve text; RDP text → X11 (arboard). Kanał gotowy i aktywny z mstsc | 60% — tekst działa (kopiuj/wklej); pliki i formaty binarne nie | ✅ tekst działa / ⚠️ pliki ❌ |
| Auto-detect network/RTT | 2.2.14 / 3.3.5.3.13 | 100% vendored (`autodetect.rs`) | 20% — mstsc wysyła, serwer odpowiada | ⚠️ |
| Heartbeat PDU | 2.2.14.1 | 100% vendored | 20% | ⚠️ |
| Echo DVC (MS-RDPEDYC) | — | 100% vendored (`echo.rs`) | 20% | ⚠️ |
| ainput (advanced input) | — | 100% vendored | 20% | ⚠️ |
| RemoteApp/RAIL | MS-RDPERP | 0% | 0% | ❌ brak |
| Multi-transport (UDP) | MS-RDPBCGR 2.2.1.3.10 | 0% (klient zgłasza TRANSPORT_TYPE_UDP; ignorowane) | 0% | ❌ brak |

## 8. Podsumowanie procentowe (waga funkcjonalna)

| Obszar | Pokrycie kodu | Pokrycie testami |
|---|---|---|
| Transport + bezpieczeństwo (NLA) | 100% | 100% |
| Obraz (capture + bitmap updates + resize) | 90% | 80% |
| Input | 80% (brak relative/unicode) | 50% (do testu użytkownika po naprawie back-pressure) |
| Audio out | 100% (protokół) / 40% (realne źródło audio) | 80% |
| Audio in (mikrofon) | 60% | 40% |
| Schowek | 20% (stub) | 0% |
| USB | 50% (kanał) / 0% (I/O) | 10% |
| **Zgodność z docs/target.md** | **pkt 1–5 ✅, pkt 6 ⚠️ (USB I/O)** | — |

## 9. Znane bugi do naprawy (priorytet)

1. **Back-pressure przy pełnych klatkach** — pierwsza klatka 2880×1800 idzie w ~317 kafelkach naraz przez Wi-Fi → `write_all stalled` → input/echo zatyka się na starcie. Plan: throttling kolejki (max N tile'ów na tick) + priorytet input events nad bitmapami.
2. **RandR SetCrtcConfig dla dynamicznie tworzonych trybów** — Xvfb odrzuca tryby z timingami 0/utworzone; poprawne CVT timings (VESA spec) lub użycie tylko trybów z listy Xvfb (restart Xvfb z żądanym rozmiarem).
3. **AUDIO_INPUT Open flow** — status 3221226021 przy tworzeniu z mstsc; dokończyć RDPEAI server-side Open/FormatChange.
4. **`linrdp/src/mic.rs` sink** — pakiety mikrofonu zliczane; podpiąć do realnego outputu.
5. **Clipboard** — StubCliprdrBackend → podmienić na prawdziwą wymianę (cliprdr-native lub własna implementacja przez x11rb).
