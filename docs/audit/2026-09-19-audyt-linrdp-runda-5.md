# LinRDP — piąty przebieg audytu, 19 września 2026

> Kontynuacja [rundy 4](2026-09-19-audyt-linrdp-runda-4.md). Zbadano stan po
> wdrożeniu poprawek U01–U04. Ten przebieg nie zmieniał kodu produkcyjnego —
> zgodnie z prośbą jest raportem znaleziska.

**Wynik: 1 nowe ustalenie P2 w kodzie produkcyjnym.** Nie potwierdzono nowego
P0/P1. Poprawki U01–U04 w sprawdzonych ścieżkach się bronią; obszary
autoryzacji, gate'u, pollera schowka, operacji plikowych i lifecycle sesji
przejrzano ponownie pod kątem nowych defektów, a nie tylko regresji ostatniego
diffu.

Badano bieżące, **niezatwierdzone zmiany** na bazie
`99b25881d1bea496e968a937241337282a4c3b5d`, w tym poprawki z poprzednich zadań.
Model zagrożeń bez zmian: nieuwierzytelniony klient TCP, złośliwy legalny klient
RDP, lokalne konto bez roota, współbieżne sesje różnych użytkowników, usługa
uruchomiona jako root.

## Weryfikacja i naprawa V01 — 19 września 2026

**V01 potwierdzone i naprawione.** Poniższy opis audytu zachowuje stan sprzed
naprawy. W `serve()` bezpośrednio po adopcji gniazda wywoływane jest
`prepare_worker_socket`, które przywraca `FD_CLOEXEC` przed obsługą połączenia
oraz ustawia dotychczasowy tryb nieblokujący. Błąd `fcntl` przerywa obsługę
z kontekstem diagnostycznym i zamyka posiadane gniazdo.

Test `worker_socket_tests::handed_over_socket_stays_usable_but_does_not_survive_exec`
korzysta z rzeczywistego połączenia TCP i `exec` powłoki. Kontrola przed
naprawą potwierdza dziedziczenie gniazda z wyczyszczonym `FD_CLOEXEC`; po
przygotowaniu gniazda dziecko już go nie widzi w `/proc/self/fd`. Test
sprawdza też tryb nieblokujący, przesłanie danych przez workera i EOF u klienta
po zamknięciu gniazda workera.

Weryfikacja: `cargo test -p linrdp` — **314 testów zaliczonych**, bez błędów
(308 jednostkowych i 6 integracyjnych). Kompilator nadal zgłasza ostrzeżenia
w projekcie. Nie wykonywano pełnego logowania RDP ani inspekcji działającego
keepera/pulpitu; dowód dynamiczny obejmuje dziedziczenie przez rzeczywisty
`exec` dziecka korzystającego z tej samej funkcji przygotowania gniazda co worker.

## Ustalenia

### V01 [P2] Ustaw close-on-exec na gnieździe klienta w workerze — `linrdp/src/main.rs:896`

**Defekt dziedziczenia deskryptorów, istniejący wcześniej; potwierdzony
statycznie pełną ścieżką wywołań.** Supervisor umieszcza zaakceptowane gniazdo
klienta na deskryptorze 3 i **czyści na nim `FD_CLOEXEC`**, żeby przetrwało
`execve` do workera (`supervisor.rs:433`, `fcntl(3, F_SETFD, 0)`). Worker
adoptuje ten deskryptor (`main.rs:896`, `from_raw_fd(fd)`) i nigdy nie
przywraca na nim close-on-exec. Deskryptor 3 pozostaje więc otwarty i
dziedziczny przez cały czas życia workera.

Worker następnie rozwidla i wykonuje `exec` na kilku procesach, z których żaden
nie potrzebuje tego gniazda i żaden go nie zamyka:

- **Keeper** — `spawn_keeper` startuje go przez `std::process::Command`
  (`session/mod.rs:186`–`238`). `Command` ustawia tylko 0/1/2 oraz jawnie
  przekazywane 4 (blokada ekranu) i 5 (blokada konta); deskryptor 3, bez
  CLOEXEC, jest dziedziczony i przeżywa `execve` keepera. Keeper jest procesem
  **długożyjącym**, przeparentowanym do init i trzymającym sesję do jej końca.
- **Serwer X i pulpit** — keeper uruchamia je przez `keeper::spawn_child`
  (surowy `fork`/`execve`, `keeper.rs:221`). `redirect_stdio` dotyka wyłącznie
  0/1/2 i nie zamyka deskryptora 3. Oba procesy działają **jako użytkownik
  sesji** po `drop_to`. Dziedziczą więc gniazdo TCP połączenia RDP.
- **Pomocnik plików** — `FileAgent::start` (`fileagent.rs:182`) używa
  `Command` i przekazuje własny socketpair na fd 4; deskryptor 3 dziedziczy
  tak samo. Pomocnik działa **jako użytkownik sesji**.
- **Serwer X ekranu logowania** — `Greeter::start` woła `keeper::spawn_child`
  wewnątrz procesu workera, więc Xvfb greetera (jako root) również dziedziczy
  fd 3.

Sam moduł potwierdza świadomość, czym jest fd 3: „3 is where the supervisor
puts a worker's accepted connection" (`fileagent.rs:53`–`55`,
`session/mod.rs` przy `KEEPER_LOCK_FD`). Mimo to nic nie chroni tego
deskryptora przed rozwidleniem pomocników.

**Skutek.** To nie jest ujawnienie między kontami: gniazdo należy do
połączenia tego samego użytkownika, który się uwierzytelnił, a ruch nad nim
jest szyfrowany TLS w przestrzeni workera (rustls), więc procesy sesji widzą
tylko szyfrogram. Realne konsekwencje są dwie:

1. **Wyciek deskryptora / zawieszone gniazdo.** Keeper (życie = cała sesja)
   oraz procesy pulpitu trzymają kopię gniazda klienta, który utworzył sesję.
   Gdy ten klient się rozłączy i worker zakończy pracę, gniazdo **nie jest w
   pełni zamykane**, bo referencje w keeperze/Xvfb/pulpicie żyją dalej —
   połączenie zostaje w stanie półzamkniętym (np. `CLOSE_WAIT`) przez cały
   czas trwania sesji. Jeden przypięty, martwy deskryptor gniazda na żywą
   sesję.
2. **Higiena izolacji.** Proces pulpitu użytkownika (a w razie kompromitacji —
   dowolna aplikacja w sesji) trzyma surowe gniazdo transportu RDP i może
   `write()` w strumień TLS (zrywając własną sesję) albo `read()` odbierając
   bajty spod workera. To dokładnie ta klasa „deskryptor ucieka do procesu,
   który go nie zażądał", którą projekt zamykał w R02 (CLOEXEC na blokadzie
   ekranu) i w poprawce `MSG_CMSG_CLOEXEC` dla `SCM_RIGHTS`. Tu została
   pominięta.

**Granica dowodu:** potwierdzenie statyczne pełnego łańcucha wywołań
(`supervisor.rs:433` → `main.rs:896` → `session/mod.rs:238` /
`fileagent.rs:203` → `keeper.rs:221`). Nie uruchamiano serwera ani nie
odczytywano `/proc/<pid>/fd` żywego pulpitu; nie wykazano dostępu między UID —
i nie twierdzę, że istnieje, bo gniazdo należy do tego samego konta.

**Naprawa i kryterium odbioru:** w `serve()`, zaraz po adopcji deskryptora
(`main.rs:896`), ustaw na nim `FD_CLOEXEC` (`fcntl(fd, F_SETFD, FD_CLOEXEC)`).
Worker używa gniazda wyłącznie w procesie przez `tokio::net::TcpStream` i nigdy
nie wykonuje `exec` sam na siebie, więc close-on-exec nie zmienia jego
działania, a odcina dziedziczenie do keepera, pomocnika plików, serwera X i
pulpitu. Ścieżka odmowy (`main.rs:502`) zamyka gniazdo od razu i jej nie
dotyczy. Test: uruchom pulpit i keepera, sprawdź, że `/proc/<keeper>/fd` i
`/proc/<desktop>/fd` nie zawierają gniazda połączenia — najlepiej przez
rzeczywisty `exec` dziecka i inspekcję jego deskryptorów, analogicznie do
`an_adopted_claim_does_not_survive_into_the_sessions_processes` w
`display_alloc.rs`.

## Obszary sprawdzone bez nowego ustalenia

Poniższe przejrzano w tym przebiegu i uznano za spójne z opisem w
poprzednich raportach — „spójne" dotyczy zbadanej ścieżki, nie certyfikacji
podsystemu.

- **U01 — jawny kontekst X11 odczytu schowka.** `x11_get_text` nie zmienia już
  środowiska procesu i czyta przez `read_selection_target_with_auth`
  (`x11_selection.rs`), z obsługą INCR ograniczoną do 8 MiB i 3 s. Poller nie
  przywraca `DISPLAY`/`XAUTHORITY`; `gate::clipboard_target` bierze parę pól z
  jednego snapshotu pod mutexem. Pętla pollera usypia na początku iteracji,
  więc `continue` dla niezwiązanego workera nie jest busy-spinem
  (`clipboard.rs:748`).
- **U02 — blokada konta przekazywana keeperowi.** Deskryptory 4/5 są
  rozłączne od źródła (`F_DUPFD_CLOEXEC` z minimum 10) i CLOEXEC po adopcji
  (`AccountLock::adopt`, `DisplayLease::adopt`), więc nie wyciekają do pulpitu
  — w przeciwieństwie do fd 3 z V01.
- **U03 — publikowanie elementów głównych transferu.** `publication_roots`
  publikuje korzenie wyboru, a niepowodzenie dowolnego elementu tłumi cały
  korzeń; puste foldery są uwzględniane. Logika kluczy/statusu jest poprawna.
- **U04 — test pollera na Xvfb.** Test sprawdza `JoinHandle` i traktuje panikę
  wątku jako błąd.
- **Autoryzacja (T03).** `decide` = `login_from_pam(pam::authenticate(...))`;
  każdy błąd loadera/`pam_start` to `BackendFailed` → `Login::Unavailable` →
  odmowa. Brak automatycznego fallbacku do shadow. `password_matches_shadow`
  pozostaje wyłącznie dla capture-helpera wewnątrz PAM.
- **Pomocnik plików.** Przejście `openat`/`mkdirat` z `O_NOFOLLOW | O_DIRECTORY`
  po komponentach, `unlinkat` + `O_CREAT|O_EXCL|O_NOFOLLOW` na pliku
  (`fileagent.rs`); `checked_relative` odrzuca nie-`Normal` komponenty. Sweep
  starych katalogów działa jako użytkownik i tylko na jego katalogach.
- **Limity supervisora, RANGE, xauth per ekran, rejestr, drop_to** — zgodne z
  wcześniejszymi rundami; `range_response_len` liczy pułap przed alokacją.

## Otwarte pozostają

Wszystkie ryzyka i punkty planu z poprzednich raportów, których ten przebieg
nie zmienił:

- Materiał kluczowy SAM wyprowadzony z tożsamości hosta (DMI + `machine-id`).
- Czas życia haseł w pamięci (kopie `String`, mapa SAM, dane konwersacji PAM).
- Root w workerze parsującym wejście sieciowe i dane schowka.
- Rozdzielenie keeperów od workerów w zarządzaniu jednostkami systemd.
- Niepełna implementacja USB i mikrofonu.
- Klucze testowe PEM w repozytorium (`linrdp/linrdp-*.pem`).
- Nie wykonano: pełnych logowań RDP/PAM/logind, macierzy rzeczywistych
  klientów, Wayland, fuzzingu parserów, aktualnego skanu CVE/zależności, prób
  między UID na działającej maszynie.

## Metoda

Ręczny przegląd ukierunkowany na granice uprawnień i dziedziczenie zasobów, ze
szczególnym naciskiem na ścieżki zmienione w rundach 3–4 oraz na politykę
deskryptorów całego łańcucha supervisor → worker → keeper → pulpit / pomocnik.
Nie budowano ani nie uruchamiano serwera w tym przebiegu; V01 udokumentowano
śladem statycznym z numerami linii. Kodu produkcyjnego nie zmieniano —
utworzono wyłącznie ten raport.
