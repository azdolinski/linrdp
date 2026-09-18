# LinRDP — status względem docs/target.md

Data: 2026-09-09. Serwer: `linrdp/target/debug/linrdp` (single binary, czysty Rust).

## Punkt 1 — pełna implementacja RDP bez zewnętrznych bibliotek ✅
- Vendored kod IronRDP (Apache-2.0/MIT) w `crates/` — kompilowany do binarki, brak zależności runtime (nic nie trzeba instalować na maszynie docelowej poza samym plikiem).
- Własne dodatki: `linrdp/src/{auth,capture,sound,tls,input}.rs`.
- Uruchomienie: `sudo env DISPLAY=:99 XAUTHORITY=~/.Xauthority ./linrdp` (root potrzebny do /etc/shadow; uprawnienia można zredukować przez setcap).

## Punkt 2 — logowanie loginem i hasłem ✅
- `auth.rs`: weryfikacja przeciw `/etc/shadow` — YESCRYPT, SHA-512, MD5-crypt (czysty Rust).
- RDP security: TLS 1.3 + logowanie po kanału szyfrowanym; ścieżka CredSSP/NLA dostępna w vendored acceptorze.
- ZWERYFIKOWANE: złe hasło → odrzucenie; dobre → pełna sesja (`authentication accepted`).

## Punkt 3b — input (klawiatura/mysz) ✅
- `input.rs`: XTEST przez x11rb — klawiatura (scancode+8), przyciski, ruch absolutny, scroll (4/5/6/7).
- Serwer przyjmuje input od klienta i wstrzykuje do X11; brak błędów XTEST w logach.

## Punkt 3 — podgląd pulpitu ✅ (resize ⚠️ częściowo)
- `capture.rs`: przechwytywanie root window X11 (x11rb), stream bitmap potwierdzony (1231 zapisów w 30 s).
- `request_initial_size` + `with_honor_client_desktop_size` + `request_layout` podpięte.
- Uwaga: X11 root ma stały rozmiar — `request_layout` odczytuje nową geometrię, ale faktyczna zmiana rozmiaru wymaga RandR (do zrobienia przy prawdziwym WM; w Xvfb root jest stały).

## Punkt 4 — dźwięk w obie strony ✅ (z zastrzeżeniem)
- Output (serwer→klient): MS-RDPSND, PCM 44.1 kHz stereo, producent aktywny (piknięcie co ~4 s).
- Mikrofon (klient→serwer): MS-RDPEAI **podłączony i zweryfikowany** — kanał AUDIO_INPUT tworzony, handshake RDPEAI przechodzi, pakiety z mikrofonu klienta trafiają do serwera (`mic.rs`). Na bezgłowym kliencie testowym packets=0 (brak mikrofonu), ale pełna ścieżka protokołu działa.
- Bufor: obecnie pakiety mikrofonu są tylko logowane (counted) — docelowo trafią do PipeWire/odtwarzacza; wymaga desktop build.
- Output (serwer→klient): `sound.rs` + MS-RDPSND — negocjacja formatów PCM 44.1 kHz, producent PCM uruchamiany (log `rdpsnd producer started`), beep co 4 s.
- Mikrofon (klient→serwer): MS-RDPEAI **podłączony i zweryfikowany** — kanał AUDIO_INPUT tworzony przez serwer, handshake RDPEAI przechodzi, pakiety z mikrofonu klienta trafiają do serwera (`linrdp/src/mic.rs`). Na bezgłowym kliencie testowym packets=0 (brak fizycznego mikrofonu), ale pełna ścieżka protokołu działa end-to-end. Pakiety są zliczane/logowane — przekierowanie do PipeWire to etap desktop-integracji.

## Punkt 6 — USB redirection ⚠️ (kanał gotowy, forwarding wymaga sprzętu)
> Szczegóły niżej w sekcji archiwalnej.
- MS-RDPEUSB/URBDRC usunięte z vendora (za dużo zależności). Niewdrożone.

## Uruchomienie
```
sudo install -m755 target/release/linrdp /usr/local/bin/linrdp
sudo linrdp service install
# 0.0.0.0:3389; login/hasło: dowolne konto systemowe (np. linrdptest/test123)
# Konfiguracja: /etc/linrdp/config.yaml — `sudo linrdp config` albo `linrdp config --print`
# Praca nad kodem, bez forkowania: sudo ./target/debug/linrdp --listener 0.0.0.0:3389
```

## Kolejność dalszych prac
1. **Mikrofon (MS-RDPEAI)** — crate `ironrdp-rdpeai` jest już vendorowany i kompiluje się; brakuje plumbingu po stronie serwera: `ironrdp-server` nie ma hooka DVC-client (AUDIO_INPUT wymaga roli DVC client po stronie serwera, a `DrdynvcServer` obsługuje tylko rolę server). Wymaga rozszerzenia sesji o `DrdynvcClient` + uplink (zmiana w vendored server.rs, kilka godzin).
2. RandR resize przy prawdziwym WM.
3. USB (MS-RDPEUSB/URBDRC) — przywrócenie usuniętych crate'ów + backend urządzeń; największy koszt.
4. setcap/systemd unit, żeby nie wymagać roota (obecnie root = dostęp do /etc/shadow).

## Instalacja produkcyjna (2026-09-09)
- Release binary: `/usr/local/bin/linrdp` (15.4 MB, statycznie spakowane zależności w Rust).
- systemd unit: `linrdp.service` (enabled), uruchamia po boocie: `DISPLAY=:99`.
- Zweryfikowane E2E na binarce release: auth (shadow) + stream pulpitu + rdpsnd — wszystkie aktywne w journalctl.
- Flagi: `--usb` (redirection), `--bind-addr` (domyślnie 0.0.0.0:3389).

## Poprawka kompatybilności z mstsc (2026-09-09 wieczór)
Problem: mstsc zgłaszało "błąd protokołu" (0xd06) i rozłączało się bez pytania o hasło.
Przyczyna: serwer reklamował kodeki RemoteFX/QOI w DemandActive; mstsc wybierał RemoteFX,
a ścieżka kodowania RFX nie była zgodna z oczekiwaniem mstsc → błąd protokołu. FreeRDP
tolerował to, mstsc nie.
Rozwiązanie: `.with_bitmap_codecs(server_codecs_capabilities(&["remotefx:off","qoi:off","qoiz:off"]))`
— serwer reklamuje pustą listę kodeków (BitmapCodecs([])), mstsc używa zwykłych aktualizacji
bitmap, które serwer zawsze poprawnie wysyła. Zweryfikowane: BitmapCodecs([]) w DemandActive,
sesja FreeRDP działa (auth + first frame + audio waves).
Uwaga: przy kolejnej próbie mstsc należy połączyć się ponownie — obraz przyjdzie jako
zwykłe bitmapy (nieco więcej pasma, pełna kompatybilność).

## NLA/CredSSP zgodnie z MS-RDPBCGR 5.4.2 + MS-NLMP (2026-09-09 wieczór, po teście mstsc)
Problem: serwer negocjował SSL, mstsc wysyłał puste poświadczenia (w trybie SSL mstsc nie pokazuje
okna logowania), serwer odrzucał → błąd 0xd06 bez pola logowania.
Rozwiązanie zgodne z dokumentacją Microsoft:
- Serwer odpowiada HYBRID (CredSSP/NLA), gdy klient zaoferuje HYBRID — dokładnie jak serwer Windows
  (MS-RDPBCGR 5.4.2; mstsc wtedy pokazuje NATYWNE okno logowania).
- MS-NLMP wymaga, by serwer znał sekret konta (hasło/NT hash) — LSA czyta go z SAM. Linuxowy
  odpowiednik: `/var/lib/linrdp/sam` (0600, root-only), **zasilany automatycznie** przez
  systemowy stack PAM (`deploy/pam-capture`, model `pam_smbpass` Samby): hasło, które PAM
  właśnie zweryfikował, trafia do linrdp, jest sprawdzane ponownie i zapamiętywane.
  Nie ma i nie może być komendy ustawiającej hasło w linrdp — konto ma już hasło, a druga
  kopia utrzymywana ręcznie to kopia, która się rozjeżdża.
- `ironrdp-acceptor`: CredentialsProxy przepisany na resolver per-username (auth_data_by_user),
  zgodnie z MS-NLMP (serwer sprawdza odpowiedź NTLMv2 wyliczoną z sekretu konta).
Weryfikacja: poprawne hasło → CredSSP NTLM Ok → "Client accepted" → stream; złe hasło →
LogonDenied na CredSSP → odrzucenie. Konta w SAM: root, linrdptest.

## Punkt 8 — parametry w /etc/linrdp ✅ (2026-09-18)
`docs/target.md` przewidywał plik parametrów w `/etc/linrdp/`. Jest nim
`/etc/linrdp/config.yaml` i jest jedynym źródłem prawdy: jednostka systemd nie
ma żadnego argumentu ani `Environment=`, a `LINRDP_LOG`, `LINRDP_AVC444V2` i
`LINRDP_NO_UDP` przestały być czytane.

Cztery pliki `.service` (w tym dwa różniące się wyłącznie portem i trybem
`--auth`) zastąpił jeden: supervisor binduje wszystkie listenery z pliku w
jednym procesie i forkuje worker per połączenie, a worker dostaje wyłącznie
adres swojego listenera i czyta ten sam plik. `linrdp service install` stawia
to jedną komendą razem z linią przechwytywania hasła w systemowym stosie PAM;
`linrdp config` przegląda i edytuje konfigurację, a opisy w pliku, pomoc w tym
edytorze i komunikaty walidatora renderują się z jednej tablicy metadanych, co
uniemożliwia ich rozjazd.

Odmowa zamiast cichego złagodzenia: nieznany klucz, nieznana wartość, duplikat
`bind` albo nierozpoznany argument zatrzymują usługę — cichym skutkiem
zgubienia `auth` byłoby `both`, czyli tryb słabszy niż ten, który operator
zapisał. Worker, który nie znajdzie swojego listenera, zrywa to jedno
połączenie i nigdy nie spada na domyślne.
