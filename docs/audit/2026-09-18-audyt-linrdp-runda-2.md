# LinRDP — drugi przebieg audytu, 18 września 2026

Badany commit: `35caab4c1a0a278294afc1da38bf6ce00b39660f`. Porównanie napraw ze stanem pierwszego audytu: `5f6fb9cdeec2819dc2c7b2c8fbcfdde372be99c6`. Drzewo robocze przed przeglądem było czyste. Przeczytano raport wraz z dopisanymi notatkami napraw, prześledzono zmienione ścieżki i ich wywołania. Zakres obejmuje również wcześniej istniejące błędy, które ujawnił przegląd napraw; nie jest ograniczony do regresji diffu.

## Ustalenia wymagające dalszej pracy

**10 ustaleń: 2 × P1, 8 × P2.** Numery R identyfikują problemy i próby komponentowe, a kolejność poniżej odpowiada priorytetowi. „Statycznie” oznacza wykazaną ścieżkę w kodzie, nie wykonany atak end-to-end. Nie zmieniano kodu produkcyjnego.

### R01 [P1] Utwórz katalog runtime greetera przed zapisem ciasteczka — `linrdp/src/session/xauth.rs:183`

**Regresja naprawy F01; potwierdzona wykonaniem kodu produkcyjnego.** `write_as_user` zastąpiło `create_dir_all` pojedynczym `create_dir`. Zwykły runtime użytkownika powstaje przez PAM, ale `Greeter::start` przekazuje nową ścieżkę `state_dir/greeter-N`, której nie tworzy (`greeter.rs:160`). Próba utworzenia `greeter-N/linrdp` kończy się ENOENT. Na świeżym stanie listener `auth: greeter` nie pokaże formularza i zakończy worker błędem. Dotyczy klienta, który potrzebuje formularza, a nie przesłał wcześniej poprawnych poświadczeń pozwalających go pominąć.

Próba komponentowa wywołała aktualne `write_cookie` jako root z istniejącym katalogiem stanu i nieistniejącym `greeter-10`. Otrzymano dokładnie `No such file or directory` dla `greeter-10/linrdp`.

**Naprawa:** twórz prywatny runtime greetera jawnie w jego lifecycle, zachowując zapis ciasteczka z docelowym UID. Dodaj test startu na pustym stanie, wymagający sukcesu. Obecny test symlinka dopuszcza `write_cookie` kończące się błędem i dlatego tej regresji nie wykrywa. Nie przywracaj uprzywilejowanego zapisu w dowolnej ścieżce użytkownika.

### R05 [P1] Obejmij autoryzacją także bezpośredni tryb `--listener` — `linrdp/src/main.rs:597`

**Niepełne pokrycie F05/F06; problem istniejący także wcześniej, potwierdzony statycznie.** Router instaluje się tylko przy `serve_fd.is_some()`. Kod nadal obsługuje `linrdp --listener <adres>` bez `--serve-fd`, który uruchamia `server.run()` i podłącza ambient/shared X display. Przy `auth: greeter` validator celowo zwraca `Accept` również bez poprawnych poświadczeń (`auth.rs:151–158`), lecz na tej drodze nie ma routera, który narysuje formularz i zatrzyma dostęp do pulpitu. Jeżeli proces ma dostęp do działającego X, klient może otrzymać pulpit bez uwierzytelnienia. Dla NLA w tej samej drodze nadal brakuje nowego `authorize_for_desktop`, więc nieaktualny SAM nie jest ponownie kontrolowany.

Nie jest to obejście domyślnego uruchomienia przez supervisor. Warunkiem jest jawne uruchomienie istniejącego trybu bezpośredniego. Nazwanie go trybem deweloperskim w komentarzu nie usuwa luki, ponieważ przyjmuje rzeczywiste połączenia i konfigurację listenera, bez wymuszenia bezpiecznego ograniczenia.

**Naprawa:** usuń tę drogę obsługi, jednoznacznie odmawiaj niedozwolonych kombinacji lub zapewnij jej te same niezmienniki uwierzytelniania i gate'u. Testy macierzy supervisor/direct × NLA/system/greeter mają wykazać, że brak tożsamości nigdy nie prowadzi do pulpitu. Nie wykonywano pełnego połączenia RDP do cudzego ekranu.

### R02 [P2] Zamknij dziedziczenie blokady ekranu po jej adopcji — `linrdp/src/session/display_alloc.rs:70`

**Regresja naprawy F02; potwierdzona przez proces z obniżonym UID.** Worker usuwa `FD_CLOEXEC`, aby przekazać keeperowi rezerwację. `DisplayLease::adopt` nie przywraca tej flagi. Keeper uruchamia X i desktop przez `fork`/`execve`, nie zamykając dodatkowych deskryptorów (`keeper.rs:221–237`). Pulpit użytkownika dziedziczy więc deskryptor rootowego pliku blokady oraz ten sam open file description. Może wykonać `flock(fd, LOCK_UN)` i zwolnić rezerwację nadal żyjącego keepera. Samo zachowanie kopii przez potomka może też przedłużyć rezerwację po śmierci keepera. To łamie podstawę `is_stale` i bezpiecznego ponownego użycia numeru.

Próba użyła produkcyjnych `adopt` i `spawn_child`: dziecko z UID użytkownika 1000 zdjęło blokadę, po czym alokator ponownie przydzielił ten sam ekran, mimo żywego obiektu rezerwacji. Numer deskryptora w próbie wynosił 100, aby nie kolidować z narzędziem; w produkcji wynosi 4. Nie wykazano przejęcia pulpitu innego UID ani nie uruchamiano rzeczywistych ekranów.

**Naprawa:** ustaw `FD_CLOEXEC` natychmiast po adopcji, ogranicz deskryptory dziedziczone przez procesy sesji i pomocniki. Test ma uruchamiać rzeczywiste dziecko przez `exec`, nie tylko przenosić obiekt w jednym procesie. Przy okazji uściślij `adopt`: obecny `flock` potrafi założyć nową blokadę na dowolnym lockowalnym pliku; nie dowodzi, że przekazano wcześniej utrzymywaną blokadę konkretnego ekranu.

### R04 [P2] Wywołaj obsługę rozłączenia w drodze używanej przez worker — `linrdp/src/main.rs:921`

**F09 nadal funkcjonalnie niezamknięte; potwierdzenie komponentowe i statyczne.** Zapisanie wspólnego `bound_display` oraz identyfikatora logind jest poprawną zmianą, ale blokada nadal znajduje się w `SessionRouter::on_disconnected`. Worker wywołuje `server.run_connection(stream)`, a następnie kończy pracę. `run_connection_with` czyści kanały i zwraca wynik, lecz nie woła handlera (`crates/ironrdp-server/src/server.rs:2244`). Jedyny produkcyjny dispatch `handler.on_disconnected` znajduje się w pętli `run` (`server.rs:2736`), z której supervisorowy worker nie korzysta. W konsekwencji zwykłe odłączenie workera nie wykonuje nowej blokady ani sygnału do wskazanego logind.

Próba dołączyła handler z licznikiem, uruchomiła `run_connection` na cichym strumieniu z deadline i potwierdziła zero wywołań po powrocie. Nie była to pełna sesja pulpitu; z analizy wspólnego wrappera wynika, że nie ma tam dispatchu również po normalnym zakończeniu sesji.

**Naprawa:** zapewnij jednorazowe wywołanie cleanup/lifecycle w publicznej drodze workera, także dla błędu. Nie dubluj callbacku w `run`. Test integracyjny musi sprawdzać efekt w rekordzie i adresowany sygnał logind po rzeczywistym połączeniu, nie tylko bezpośrednio wołać metodę handlera.

### R03 [P2] Serializuj tworzenie sesji tego samego konta — `linrdp/src/session/mod.rs:251`

**Pozostała luka współbieżności F02; potwierdzenie statyczne i komponentowe.** Utrzymywanie rezerwacji zamyka pierwotny wyścig różnych kont o ten sam numer. Nie serializuje jednak `attach_live` → `create` dla tego samego konta. Dwa połączenia przed publikacją rekordu mogą wybrać dwa różne ekrany i uruchomić dwa keepery tego użytkownika. Oba zapisują ten sam `/run/user/<uid>/linrdp/Xauthority`, zawierający tylko pojedynczy wpis. Drugi zapis usuwa ciasteczko pierwszego ekranu; ponowne połączenie do pierwszego może zakończyć się błędem „holds no cookie”, a wybór istniejącej sesji jest niejednoznaczny.

Próba wykonała dwa produkcyjne `write_cookie`, dla ekranów 21 i 22, z tym samym UID i runtime. Po drugim zapisie `cookie_for(..., 21)` odmawia. Sam harmonogram dwóch pełnych logowań nie był wykonywany; brak blokady konta i scenariusz dwóch nieopublikowanych rekordów są widoczne w kodzie.

**Naprawa:** blokada per UID obejmująca ponowną kontrolę istniejącej sesji i utworzenie/publikację; dodatkowo ciasteczko per ekran lub poprawny wielowpisowy magazyn. Test z barierą przed publikacją powinien wymusić równoczesność. Stwierdzenie w dopisku F02, że równoległość została całkowicie zamknięta konstrukcyjnie, jest zbyt szerokie.

### R06 [P2] Uruchom pomocnik plików po przejściu z greetera do pulpitu — `linrdp/src/clipboard.rs:640`

**Regresja F03; potwierdzona statycznie.** `start_file_helper` wywoływane jest tylko w `on_ready` kanału. Kiedy CLIPRDR jest już gotowy, a użytkownik nadal wpisuje dane w formularzu, gate nie ma jeszcze właściciela i funkcja zostawia `files=None`. Późniejsze `gate::bind` po zalogowaniu nie ponawia startu helpera; poller śledzi własną generację CLIPRDR, nie zmianę właściciela gate'u. Bez ponownej inicjalizacji kanału kopiowanie plików pozostaje wyłączone przez resztę połączenia. Na świeżym stanie R01 zatrzymuje ten scenariusz wcześniej; problem R06 ujawni się po naprawie R01 albo przy istniejącym runtime greetera.

**Naprawa:** reaguj na zmianę generacji/UID sesji lub inicjalizuj helper leniwie przed operacją, z synchronizacją i odmową przed uwierzytelnieniem. Test: kanał ready przed loginem → bind użytkownika → udany transfer, bez renegocjacji CLIPRDR. Należy przy tym odświeżyć docelowy display/Xauthority klientów schowka.

### R07 [P2] Rozdziel katalogi kolejnych transferów w tej samej sesji — `linrdp/src/session/fileagent.rs:542`

**Regresja F04; potwierdzona wykonaniem helpera.** Przed zmianą kolejny zestaw plików otrzymywał nowy numer katalogu. Teraz `paste_dir` jest tworzony raz na całe życie helpera; każde `on_remote_file_list` otrzymuje tę samą ścieżkę. `create_below` usuwa poprzedni plik o tej samej nazwie i tworzy nowy. Dwa kolejne kopiowania `report.txt` w jednym połączeniu podmieniają zawartość pod wcześniej udostępnionym URI. Aplikacja, która jeszcze odwołuje się do pierwszego transferu, może pobrać dane drugiego. Izolacja między użytkownikami jest poprawiona, ale izolacja generacji transferu została utracona.

Próba wykazała identyczną ścieżkę `paste_dir` i zmianę treści pod URI poprzedniego pliku po następnym `create_file`.

**Naprawa:** losowy podkatalog na transfer/generację w prywatnym katalogu sesji, powiązany z konkretnym `Download`. Zachowuj wcześniejsze pliki tak długo, jak mogą ich używać opublikowane URI. Testuj identyczne nazwy w dwóch kolejnych transferach i niezależność obu zawartości.

### R08 [P2] Numeruj deskryptory według listy rzeczywiście reklamowanej klientowi — `linrdp/src/clipboard.rs:793`

**Wcześniej istniejący defekt, ujawniony przy kontroli F03; potwierdzony statycznie.** Po odrzuceniu ścieżki przez `stat` lub `!is_file`, lista `descriptors` jest zwarta, ale mapa `offered` nadal używa indeksów oryginalnego `paths`. Dla wejścia `[katalog, a.txt, b.txt]` klient widzi indeksy 0 = a, 1 = b, podczas gdy backend przechowuje 1 = a, 2 = b. Pierwsze żądanie zostanie odrzucone, a kolejne może zwrócić zawartość a jako b. Dotyczy mieszanych zaznaczeń katalogów i plików oraz plików usuniętych w trakcie kopiowania. Nowy helper nie usuwa tego rozjazdu.

**Naprawa:** użyj indeksu z `descriptors.len()` przed dodaniem poprawnego deskryptora, a nie z `paths.enumerate()`. Testuj pominięty element na początku i w środku oraz rzeczywiste żądania SIZE/RANGE każdego reklamowanego indeksu.

### R09 [P2] Waliduj dodatnie limity także przy wczytaniu YAML — `linrdp/src/config/mod.rs:243`

**Regresja konfiguracji F07; potwierdzona produkcyjnym parserem i walidatorem.** TUI odrzuca zero w `parse_limit`, ale `Limits` deserializuje zwykłe `u32`, a wspólne `config::validate` nie sprawdza nowych pól. Konfiguracja z `max_workers: 0` lub `max_per_client: 0` jest uznawana za poprawną, usługa może związać port i następnie odrzucać wszystkich klientów. `handshake_seconds: 0` również jest przyjmowane mimo deklarowanego minimum 1. To wprowadza odmienną semantykę konfiguracji edytowanej w TUI i ręcznie.

**Naprawa:** wspólna walidacja trzech wartości przed startem supervisora/workera. Próba w załącznikach deserializuje YAML z trzema zerami i potwierdza `validate(...).is_ok()`. Testy powinny osobno sprawdzić każde zero i poprawne wartości graniczne.

### R10 [P2] Nie zastępuj błędu inicjalizacji działającego PAM decyzją z shadow — `linrdp/src/auth.rs:226`

**Niepełna naprawa F06; potwierdzona statycznie.** Raport napraw deklaruje fallback wyłącznie wtedy, gdy libpam nie można załadować. W rzeczywistości `decide` przechodzi do shadow po każdym `Err` z `pam::authenticate`. Ten sam `Err` jest zwracany również po niepowodzeniu `pam_start` (`pam.rs:283–285`), już po poprawnym załadowaniu biblioteki. Przy błędzie inicjalizacji PAM, poprawnym haśle lokalnym i niewygasłym wpisie shadow można uzyskać `Accept`, choć reguły `pam_access`, `pam_time` czy inne wymagania stosu w ogóle nie zostały wykonane. Znaczenie ma zwłaszcza reconnect/console, bez późniejszego otwarcia nowej sesji PAM.

To nie jest dowód, że zdalny klient może dowolnie spowodować błąd `pam_start`; jest to niebezpieczna ścieżka awarii backendu. Nie wymuszano awarii systemowego PAM podczas audytu.

**Naprawa:** typowane rozróżnienie „brak opcjonalnej biblioteki” i „błąd skonfigurowanego backendu”. Drugi stan musi zamykać dostęp. Ewentualny tryb bez PAM powinien być jawną polityką administratora, nie efektem błędu. Testy z wstrzykiwanym backendem: brak biblioteki zgodny z konfiguracją, błąd `pam_start`, odmowa auth, odmowa account.

## Weryfikacja ustaleń pierwszego raportu

„Zamknięte” poniżej dotyczy konkretnego pierwotnego defektu w badanym kodzie, nie certyfikacji całego obszaru.

| Pierwotne ustalenie | Ocena po drugim przebiegu | Dowód / pozostała praca |
|---|---|---|
| F01 — root zapisuje Xauthority przez symlink | Pierwotna eskalacja usunięta; regresja funkcjonalna | Zapis następuje po `drop_to`, brak chown celu; R01 blokuje świeży greeter |
| F02 — utrata rezerwacji i sesja innego konta | Częściowo zamknięte | Rezerwacja przekazywana bez przerwy, kontrola nazwy konta w dwóch miejscach; R02 i R03 pozostają |
| F03 — pliki schowka czytane jako root | Pierwotny defekt zamknięty | Rzeczywisty exec helpera: odczyt własnego pliku działa, root 0600 i drugi UID 0600 odrzucone; R06 dotyczy startu helpera |
| F04 — wspólny przewidywalny katalog | Pierwotna kolizja między workerami usunięta | Losowa nazwa, prywatny katalog, operacje jako UID; R07 dotyczy kolejnych transferów jednego workera |
| F05 — brak aktualnej kontroli konta NLA | Naprawione w drodze supervisorowej; nie globalnie | `authorize_for_desktop` przed attach i console; R05 dotyczy direct, R10 awarii backendu |
| F06 — hash zastępuje politykę PAM | Zasadniczo poprawione; niepełne zamknięcie | PAM-first i kontrola wieku shadow; R05 i R10; bez testu zmiany/wygaśnięcia rzeczywistych kont |
| F07 — nieograniczone workery i ciche handshake | Pierwotny mechanizm poprawiony | Rejestr PID, limity, timeout; dodatkowa próba timeoutu udana; R09 dotyczy konfiguracji |
| F08 — nieograniczona alokacja RANGE | Zamknięte w badanej funkcji | Ograniczenie do 512 KiB i pozostałego rozmiaru przed alokacją, testy przechodzą |
| F09 — brak blokady po greeterze | Nadal otwarte funkcjonalnie | Wspólny stan i jawny logind ID są, lecz R04 uniemożliwia wykonanie cleanup przez worker |
| F10 — utrata aktualizacji SAM | Zamknięte w prześledzonych writerach | Stały plik flock obejmuje read–modify–write oraz migrację; test synchronizacji przechodzi |
| F11 — `$5$` weryfikowane jako `$6$` | Zamknięte | Rozdzielone algorytmy, testy poprawnych/błędnych haseł przechodzą |

## Wyniki wykonanych kontroli

- `cargo test -p linrdp --offline --no-default-features`: **297 jednostkowych + 2 integracyjne, wszystkie zaliczone**.
- `cargo test -p ironrdp-server --offline --lib`: **14 testów, wszystkie zaliczone**.
- Razem: **313 testów projektu**. Nie jest to pełny workspace ani wszystkie warianty features.
- Dodatkowe próby: produkcyjne moduły Xauthority, privilege, allocator, keeper i fileagent; rzeczywisty proces helpera i dziecko uruchomione z niższym UID; wrapper połączenia z timeoutem; parser konfiguracji. Wyniki i źródła znajdują się w [round2/](round2/).
- Próba timeoutu zakończyła cichy strumień po około 51 ms przy limicie 50 ms. To kontrola mechanizmu w pamięci, nie test TCP/TLS/CredSSP end-to-end.
- Operacje wymagające roota dotyczyły wyłącznie tymczasowych plików kontrolnych i dzieci testu. Użyto istniejących UID, nie zmieniano kont, PAM, usług ani plików systemowych. Nie odczytywano rzeczywistych sekretów.

Reprodukcja po zbudowaniu projektu:

```sh
python3 docs/audit/round2/reproduce.py
python3 docs/audit/round2/connection-proof.py
python3 docs/audit/round2/config-proof.py
```

Pierwszy skrypt wymaga lokalnego `sudo -n` i istniejącego nieuprzywilejowanego użytkownika oraz konta `nobody`; odmowa uprawnień oznacza niewykonaną próbę. Wykorzystuje produkcyjne pliki przez `#[path]`, a nie kopie ich implementacji. Asercje oznaczone R potwierdzają obecność defektu i po naprawie wymagają odwrócenia. Skrypty wybierają dostępne artefakty `.rlib`, więc służą temu checkoutowi i wymagają aktualnego builda; nie są samodzielnym pakietem testowym.

## Korekty interpretacji dokumentu napraw

Notatki dobrze opisują kierunek zmian, ale określenia „wszystkie ścieżki” i „zrobione” są w kilku miejscach silniejsze od dowodów. R05 pokazuje pominięte wejście, R04 niewykonywany callback, R02 różnicę między przekazaniem rezerwacji a ograniczeniem dostępu do niej. Pomyślny test komponentu nie wystarcza, jeśli produkcyjny caller go nie uruchamia.

Brak możliwości skompilowania starego `reproduce.py` po zmianie API **nie jest dowodem usunięcia podatności**. Poprzedni opis należy rozumieć jako informację o nieaktualnym narzędziu. Nowe próby kompilują obecne API i sprawdzają konkretne skutki. Test handoff w jednym procesie nie wykrywa dziedziczenia przez exec, a test callbacku wołanego ręcznie nie wykrywa braku dispatchu w workerze.

Opis `limits` mówi, że nie dotyczą uwierzytelnionych sesji, podczas gdy `Workers.live` trzyma PID do zakończenia procesu i nie dostaje sygnału zakończenia auth. W praktyce limit dotyczy również aktywnych połączeń, w tym wielu użytkowników za jednym NAT-em. To należy jasno udokumentować lub zmienić model budżetów; nie traktuję samego ograniczenia całkowitej liczby połączeń jako luki.

Dodatkowo odebrany przez `SCM_RIGHTS` deskryptor nie ma CLOEXEC — zaobserwowano to w próbie. Warto zastosować `MSG_CMSG_CLOEXEC` i przegląd całej polityki dziedziczenia. Nie przypisuję temu osobno eskalacji uprawnień bez wykazanego uprzywilejowanego celu.

## Ocena końcowa i kolejność prac

**Nastąpiła istotna poprawa bezpieczeństwa, ale deklaracja, że wszystkie punkty zostały skutecznie zamknięte, nie jest jeszcze prawdziwa.** Szczególnie wartościowa jest faktycznie sprawdzona separacja operacji plikowych według UID. Nadal nie rekomenduję dopuszczenia do niezaufanego środowiska bez usunięcia P1 i domknięcia lifecycle oraz rezerwacji.

1. Napraw R01 i R05: świeży greeter musi działać, a każdy tryb nasłuchu wymuszać autoryzację.
2. Napraw R02–R04 i R10: własność rezerwacji, pojedyncza sesja konta, wykonanie blokady i odmowa przy awarii polityki PAM.
3. Napraw R06–R09: start helpera po loginie, niezależne generacje transferu, spójne indeksy i konfiguracja.
4. Wykonaj testy rzeczywistego logowania NLA/system/greeter, odwołania dostępu przy istniejącej sesji i rozłączenia z logind. Dodaj deterministyczne bariery w testach współbieżności zamiast uznawać taki test za niemożliwy.

Pozostają ryzyka wskazane poprzednio: materiał kluczowy SAM oparty na identyfikatorach hosta, pamięć haseł, root w workerze parsującym protokół, rozdzielenie keeperów od workerów w systemd i stan implementacji urządzeń. W tym przebiegu nie wykonano aktualnego skanowania CVE, pełnego audytu parserów/unsafe, fuzzingu, Wayland ani macierzy prawdziwych klientów. Nie należy na podstawie zielonych testów wyciągać wniosku o bezpieczeństwie tych obszarów.
