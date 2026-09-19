# LinRDP — drugi przebieg audytu, 18 września 2026

> Weryfikacja napraw: [trzeci przebieg audytu](2026-09-18-audyt-linrdp-runda-3.md). Trzeci przebieg wskazał dalszą pracę przy R05, R06 i R10; naprawy z 19 września opisano na końcu trzeciego raportu. Poniższe notatki zachowano jako zapis wcześniejszego stanu.

Badany commit: `35caab4c1a0a278294afc1da38bf6ce00b39660f`. Porównanie napraw ze stanem pierwszego audytu: `5f6fb9cdeec2819dc2c7b2c8fbcfdde372be99c6`. Drzewo robocze przed przeglądem było czyste. Przeczytano raport wraz z dopisanymi notatkami napraw, prześledzono zmienione ścieżki i ich wywołania. Zakres obejmuje również wcześniej istniejące błędy, które ujawnił przegląd napraw; nie jest ograniczony do regresji diffu.

## Ustalenia wymagające dalszej pracy

**10 ustaleń: 2 × P1, 8 × P2.** Numery R identyfikują problemy i próby komponentowe, a kolejność poniżej odpowiada priorytetowi. „Statycznie” oznacza wykazaną ścieżkę w kodzie, nie wykonany atak end-to-end. Nie zmieniano kodu produkcyjnego.

### R01 [P1] Utwórz katalog runtime greetera przed zapisem ciasteczka — `linrdp/src/session/xauth.rs:183`

**Regresja naprawy F01; potwierdzona wykonaniem kodu produkcyjnego.** `write_as_user` zastąpiło `create_dir_all` pojedynczym `create_dir`. Zwykły runtime użytkownika powstaje przez PAM, ale `Greeter::start` przekazuje nową ścieżkę `state_dir/greeter-N`, której nie tworzy (`greeter.rs:160`). Próba utworzenia `greeter-N/linrdp` kończy się ENOENT. Na świeżym stanie listener `auth: greeter` nie pokaże formularza i zakończy worker błędem. Dotyczy klienta, który potrzebuje formularza, a nie przesłał wcześniej poprawnych poświadczeń pozwalających go pominąć.

Próba komponentowa wywołała aktualne `write_cookie` jako root z istniejącym katalogiem stanu i nieistniejącym `greeter-10`. Otrzymano dokładnie `No such file or directory` dla `greeter-10/linrdp`.

**Naprawa:** twórz prywatny runtime greetera jawnie w jego lifecycle, zachowując zapis ciasteczka z docelowym UID. Dodaj test startu na pustym stanie, wymagający sukcesu. Obecny test symlinka dopuszcza `write_cookie` kończące się błędem i dlatego tej regresji nie wykrywa. Nie przywracaj uprzywilejowanego zapisu w dowolnej ścieżce użytkownika.

**Naprawiono 18 września 2026** (`a3cbb81`). Dokładnie tak: `Greeter::start` tworzy `state_dir/greeter-N` sama, z trybem 0700 — czyli ta sama połowa kodu, której `Drop` ten katalog kilkanaście linii dalej usuwa. `write_cookie` nadal tworzy wyłącznie katalog `linrdp` **wewnątrz** istniejącego runtime i nadal pisze z docelowym UID; uprzywilejowany zapis w dowolnej ścieżce nie wraca. `create_dir` zamiast `create_dir_all` zostaje celowo: dla prawdziwej sesji runtime należy do `pam_systemd`, a pisarz ciasteczka tworzący go za niego zakrywałby jego brak.

Przy okazji `write_as_user` pomija `drop_to`, gdy już jest tym użytkownikiem — inaczej wywołanie spod właściwego UID kończyło się `initgroups: Operation not permitted`.

Test: `a_cookie_is_written_when_the_runtime_directory_exists` (`xauth.rs`) wymaga **sukcesu** na świeżym drzewie i osobno sprawdza, że nieistniejący runtime nadal jest błędem, a nie czymś do utworzenia. To odpowiada na uwagę, że test symlinka dopuszcza błąd: tamten musi go dopuszczać, bo pod nie-rootem zrzucenie uprawnień ma prawo się nie udać.

### R05 [P1] Obejmij autoryzacją także bezpośredni tryb `--listener` — `linrdp/src/main.rs:597`

**Niepełne pokrycie F05/F06; problem istniejący także wcześniej, potwierdzony statycznie.** Router instaluje się tylko przy `serve_fd.is_some()`. Kod nadal obsługuje `linrdp --listener <adres>` bez `--serve-fd`, który uruchamia `server.run()` i podłącza ambient/shared X display. Przy `auth: greeter` validator celowo zwraca `Accept` również bez poprawnych poświadczeń (`auth.rs:151–158`), lecz na tej drodze nie ma routera, który narysuje formularz i zatrzyma dostęp do pulpitu. Jeżeli proces ma dostęp do działającego X, klient może otrzymać pulpit bez uwierzytelnienia. Dla NLA w tej samej drodze nadal brakuje nowego `authorize_for_desktop`, więc nieaktualny SAM nie jest ponownie kontrolowany.

Nie jest to obejście domyślnego uruchomienia przez supervisor. Warunkiem jest jawne uruchomienie istniejącego trybu bezpośredniego. Nazwanie go trybem deweloperskim w komentarzu nie usuwa luki, ponieważ przyjmuje rzeczywiste połączenia i konfigurację listenera, bez wymuszenia bezpiecznego ograniczenia.

**Naprawa:** usuń tę drogę obsługi, jednoznacznie odmawiaj niedozwolonych kombinacji lub zapewnij jej te same niezmienniki uwierzytelniania i gate'u. Testy macierzy supervisor/direct × NLA/system/greeter mają wykazać, że brak tożsamości nigdy nie prowadzi do pulpitu. Nie wykonywano pełnego połączenia RDP do cudzego ekranu.

**Naprawiono 18 września 2026** (`a3cbb81`). Zastosowano dwie z trzech zaproponowanych opcji naraz, bo jedna nie wystarcza.

Router jest teraz instalowany dla **każdego** połączenia, które ten proces obsługuje — `route_connections` jest bezwarunkowe, nie `serve_fd.is_some()`. Tryb bezpośredni ma więc te same niezmienniki: `bind_to_desktop` z obowiązkowym `authorize_for_desktop`, gałąź console z własną kontrolą, greeter rysujący formularz.

Niezależnie od tego `--listener` bez `--serve-fd` jest **odmawiany na starcie**, gdy nie jest to tryb console. Powód jest strukturalny, nie brakiem pracy: gate sesji jest globalny dla procesu i wiąże się raz, więc druga osoba, która się połączy, nie ma dokąd trafić; nie ma też procesu na połączenie, w którym mieszkałoby sprzątanie sesji. Console jest jedynym kształtem, który w jednym procesie działa naprawdę, bo każde połączenie pokazuje ten sam ekran. Komunikat odmowy kieruje do supervisora (`linrdp` bez argumentów, albo `linrdp debug`). Zaktualizowano też pomoc CLI, README i `docs/target-status.md`, które polecały tę drogę do pracy nad kodem.

Macierzy supervisor/direct × NLA/system/greeter nie uruchomiono jako testu — wymaga rzeczywistych połączeń RDP. Dwie z czterech kombinacji direct już nie istnieją (odmowa startu), a pozostałe przechodzą przez ten sam `bind_to_desktop`, co droga supervisorowa.

### R02 [P2] Zamknij dziedziczenie blokady ekranu po jej adopcji — `linrdp/src/session/display_alloc.rs:70`

**Regresja naprawy F02; potwierdzona przez proces z obniżonym UID.** Worker usuwa `FD_CLOEXEC`, aby przekazać keeperowi rezerwację. `DisplayLease::adopt` nie przywraca tej flagi. Keeper uruchamia X i desktop przez `fork`/`execve`, nie zamykając dodatkowych deskryptorów (`keeper.rs:221–237`). Pulpit użytkownika dziedziczy więc deskryptor rootowego pliku blokady oraz ten sam open file description. Może wykonać `flock(fd, LOCK_UN)` i zwolnić rezerwację nadal żyjącego keepera. Samo zachowanie kopii przez potomka może też przedłużyć rezerwację po śmierci keepera. To łamie podstawę `is_stale` i bezpiecznego ponownego użycia numeru.

Próba użyła produkcyjnych `adopt` i `spawn_child`: dziecko z UID użytkownika 1000 zdjęło blokadę, po czym alokator ponownie przydzielił ten sam ekran, mimo żywego obiektu rezerwacji. Numer deskryptora w próbie wynosił 100, aby nie kolidować z narzędziem; w produkcji wynosi 4. Nie wykazano przejęcia pulpitu innego UID ani nie uruchamiano rzeczywistych ekranów.

**Naprawa:** ustaw `FD_CLOEXEC` natychmiast po adopcji, ogranicz deskryptory dziedziczone przez procesy sesji i pomocniki. Test ma uruchamiać rzeczywiste dziecko przez `exec`, nie tylko przenosić obiekt w jednym procesie. Przy okazji uściślij `adopt`: obecny `flock` potrafi założyć nową blokadę na dowolnym lockowalnym pliku; nie dowodzi, że przekazano wcześniej utrzymywaną blokadę konkretnego ekranu.

**Naprawiono 18 września 2026** (`a3cbb81`). `DisplayLease::adopt` ustawia `FD_CLOEXEC` natychmiast, więc `execve` X-a i pulpitu w `keeper::spawn_child` już go nie przenosi. Deskryptor pomocnika plików dostał to samo z drugiej strony: `SCM_RIGHTS` odbierane jest z `MSG_CMSG_CLOEXEC`, czyli przychodzące deskryptory też nie wyciekają dalej — to odpowiedź na uwagę z sekcji „Korekty interpretacji".

Uściślono również `adopt`, i to w dwóch miejscach naraz, bo sama uwaga o `flock` nie wyczerpuje problemu:

- **Tożsamość.** Deskryptor musi wskazywać plik blokady *tego* ekranu — porównanie po urządzeniu i i-węźle z `display-N.lock`, a nie na słowo wołającego.
- **Trzymanie.** Że blokada jest trzymana, nie da się sprawdzić z procesu, który ją trzyma: `flock` na deskryptorze, którego opis otwartego pliku już ją ma, kończy się sukcesem i niczego nie zmienia — nieodróżnialnie od wzięcia jej na świeżo. Sprawdzane jest więc coś równoważnego i sprawdzalnego: że **nikt inny** nie może jej wziąć — niezależne otwarcie tej samej ścieżki musi polec na `LOCK_EX | LOCK_NB`.

Testy: `an_adopted_claim_does_not_survive_into_the_sessions_processes` uruchamia rzeczywiste dziecko przez `exec` (`/bin/sh -c 'test -e /proc/self/fd/N'`) i wymaga, żeby deskryptora tam nie było — przenoszenie obiektu w jednym procesie przeszłoby tak czy inaczej, co było właśnie zarzutem. `adopting_a_descriptor_that_is_not_this_displays_lock_is_refused` pokrywa zamknięty deskryptor, właściwy deskryptor na niewłaściwym pliku i właściwy plik, którego nikt nie trzyma.

### R04 [P2] Wywołaj obsługę rozłączenia w drodze używanej przez worker — `linrdp/src/main.rs:921`

**F09 nadal funkcjonalnie niezamknięte; potwierdzenie komponentowe i statyczne.** Zapisanie wspólnego `bound_display` oraz identyfikatora logind jest poprawną zmianą, ale blokada nadal znajduje się w `SessionRouter::on_disconnected`. Worker wywołuje `server.run_connection(stream)`, a następnie kończy pracę. `run_connection_with` czyści kanały i zwraca wynik, lecz nie woła handlera (`crates/ironrdp-server/src/server.rs:2244`). Jedyny produkcyjny dispatch `handler.on_disconnected` znajduje się w pętli `run` (`server.rs:2736`), z której supervisorowy worker nie korzysta. W konsekwencji zwykłe odłączenie workera nie wykonuje nowej blokady ani sygnału do wskazanego logind.

Próba dołączyła handler z licznikiem, uruchomiła `run_connection` na cichym strumieniu z deadline i potwierdziła zero wywołań po powrocie. Nie była to pełna sesja pulpitu; z analizy wspólnego wrappera wynika, że nie ma tam dispatchu również po normalnym zakończeniu sesji.

**Naprawa:** zapewnij jednorazowe wywołanie cleanup/lifecycle w publicznej drodze workera, także dla błędu. Nie dubluj callbacku w `run`. Test integracyjny musi sprawdzać efekt w rekordzie i adresowany sygnał logind po rzeczywistym połączeniu, nie tylko bezpośrednio wołać metodę handlera.

**Naprawiono 18 września 2026** (`a3cbb81`). Ustalenie jest trafne i szersze, niż sugeruje jego numer: skoro `on_disconnected` nigdy nie wykonywało się w drodze workera, to w trybie supervisorowym — czyli domyślnym — **nigdy nie działała ani blokada sesji przy rozłączeniu, ani przywrócenie konsoli** z `SessionController`. Nie było to niedomknięcie F09, tylko martwy callback od początku.

Dispatch jest teraz w `run_connection_with`, dokładnie raz i także dla błędu (`result.as_ref().err()` idzie do handlera). Duplikatu w `run` nie ma i nie może być: `run` woła `run_connection_inner` bezpośrednio, nie tę metodę — jest to napisane w komentarzu przy obu, żeby następna osoba nie „uprościła" jednego w drugie. Adres peera pochodzi od tego, kto połączenie przyjął: worker przekazuje go przez nowe `set_peer_addr`, a bez niego handler dostaje adres nieokreślony, nie zmyślony. Zaktualizowano kontrakt `ConnectionHandler` w dokumentacji, który wcześniej stwierdzał, że callback jest `run`-only.

Testy: `run_connection_runs_the_embedders_teardown` i `an_unknown_peer_is_reported_as_unspecified` (`crates/ironrdp-server/src/server.rs`) — pierwszy sprawdza dokładnie jedno wywołanie (zero było błędem, dwa byłyby nowym) i że przekazany adres dociera. Zgodnie z uwagą nie wołają metody handlera wprost, tylko przechodzą przez `run_connection`. Testu integracyjnego sprawdzającego rekord i adresowany sygnał logind po rzeczywistym połączeniu nadal nie ma — wymaga X, logind i klienta RDP.

### R03 [P2] Serializuj tworzenie sesji tego samego konta — `linrdp/src/session/mod.rs:251`

**Pozostała luka współbieżności F02; potwierdzenie statyczne i komponentowe.** Utrzymywanie rezerwacji zamyka pierwotny wyścig różnych kont o ten sam numer. Nie serializuje jednak `attach_live` → `create` dla tego samego konta. Dwa połączenia przed publikacją rekordu mogą wybrać dwa różne ekrany i uruchomić dwa keepery tego użytkownika. Oba zapisują ten sam `/run/user/<uid>/linrdp/Xauthority`, zawierający tylko pojedynczy wpis. Drugi zapis usuwa ciasteczko pierwszego ekranu; ponowne połączenie do pierwszego może zakończyć się błędem „holds no cookie”, a wybór istniejącej sesji jest niejednoznaczny.

Próba wykonała dwa produkcyjne `write_cookie`, dla ekranów 21 i 22, z tym samym UID i runtime. Po drugim zapisie `cookie_for(..., 21)` odmawia. Sam harmonogram dwóch pełnych logowań nie był wykonywany; brak blokady konta i scenariusz dwóch nieopublikowanych rekordów są widoczne w kodzie.

**Naprawa:** blokada per UID obejmująca ponowną kontrolę istniejącej sesji i utworzenie/publikację; dodatkowo ciasteczko per ekran lub poprawny wielowpisowy magazyn. Test z barierą przed publikacją powinien wymusić równoczesność. Stwierdzenie w dopisku F02, że równoległość została całkowicie zamknięta konstrukcyjnie, jest zbyt szerokie.

**Naprawiono 18 września 2026** (`a3cbb81`). Uwaga o zbyt szerokim sformułowaniu jest słuszna: przekazanie rezerwacji zamyka wyścig o numer, nie wyścig o sesję konta. To dwie różne rzeczy i dopisek do F02 zlewał je w jedno.

Obie zaproponowane naprawy, nie jedna z nich:

- **Blokada per UID.** `AccountLock` bierze `flock` na `base/account-<uid>.lock` i trzyma go przez całe `attach_or_create`, czyli przez ponowną kontrolę istniejącej sesji, utworzenie i oczekiwanie na publikację rekordu. Kluczem jest uid, nie nazwa jak wpisana, żeby `Alice` i `alice` nie trafiły po dwóch stronach tej samej blokady. Drugie połączenie tego konta albo znajdzie sesję zrobioną przez pierwsze, albo na nią poczeka — nigdy nie zacznie drugiej.
- **Ciasteczko per ekran.** `cookie_path` zwraca `Xauthority-<display>`. Jednowpisowy plik nie jest już współdzielony między ekranami jednego konta, więc scenariusz z próby — zapis dla :22 kasujący ciasteczko :21 — nie ma jak zajść nawet gdyby blokadę kiedyś ominięto.

Test: `one_account_creates_one_session_at_a_time` (`session/mod.rs`) — cztery wątki po dwadzieścia przebiegów, z licznikiem wykrywającym jakiekolwiek nałożenie się sekcji krytycznych, plus sprawdzenie, że inne konto nie czeka. Nie jest to bariera przed publikacją rekordu z dwoma prawdziwymi logowaniami: to wymaga X, PAM i roota. Ćwiczony jest mechanizm, pod którym `attach_or_create` teraz w całości działa.

### R06 [P2] Uruchom pomocnik plików po przejściu z greetera do pulpitu — `linrdp/src/clipboard.rs:640`

**Regresja F03; potwierdzona statycznie.** `start_file_helper` wywoływane jest tylko w `on_ready` kanału. Kiedy CLIPRDR jest już gotowy, a użytkownik nadal wpisuje dane w formularzu, gate nie ma jeszcze właściciela i funkcja zostawia `files=None`. Późniejsze `gate::bind` po zalogowaniu nie ponawia startu helpera; poller śledzi własną generację CLIPRDR, nie zmianę właściciela gate'u. Bez ponownej inicjalizacji kanału kopiowanie plików pozostaje wyłączone przez resztę połączenia. Na świeżym stanie R01 zatrzymuje ten scenariusz wcześniej; problem R06 ujawni się po naprawie R01 albo przy istniejącym runtime greetera.

**Naprawa:** reaguj na zmianę generacji/UID sesji lub inicjalizuj helper leniwie przed operacją, z synchronizacją i odmową przed uwierzytelnieniem. Test: kanał ready przed loginem → bind użytkownika → udany transfer, bez renegocjacji CLIPRDR. Należy przy tym odświeżyć docelowy display/Xauthority klientów schowka.

**Naprawiono 18 września 2026** (`a3cbb81`). Wybrano wariant leniwy: `start_file_helper` zniknęło z `on_ready`, a `with_files` uruchamia pomocnika przy pierwszym użyciu — pod muteksem, który i tak trzyma, więc synchronizacja jest ta sama. Odmowa przed uwierzytelnieniem zostaje: bez właściciela w gate `with_files` zwraca błąd i niczego nie startuje.

Pomocnik jest powiązany z kontem, dla którego powstał (`SessionFiles { owner, agent }`), i **wymieniany**, gdy właściciel się zmieni. To jest przekazanie greetera: ekran logowania nie jest niczyją sesją, a pomocnik działający jako niewłaściwe konto to cała klasa błędów, przed którą ten moduł istnieje.

Uwaga o display/Xauthority była trafna i dotyczyła osobnej rzeczy: backend zapamiętywał je przy konstrukcji, czyli przy `auth: greeter` — ekran formularza. Po przekazaniu schowek rozmawiał dalej z X-em formularza. Teraz `X11CliprdrBackend::target()` czyta je z gate przy każdym użyciu, a wątek pollera porównuje `gate::generation()` i przy zmianie przestawia `DISPLAY`/`XAUTHORITY` oraz czyści zapamiętany stan schowka — poprzedni ekran nie mówi nic o obecnym.

Testu „ready przed loginem → bind → udany transfer" nie ma w tej formie: wymaga dwóch serwerów X i pełnego CLIPRDR. Pokryte jest to, że bez właściciela transfer jest odmawiany (`a_paste_without_a_file_helper_is_refused`) i że przy właścicielu przechodzi cała ścieżka pobierania (`file_download_streams_to_disk`, który sam startuje pomocnika przez `with_files`).

### R07 [P2] Rozdziel katalogi kolejnych transferów w tej samej sesji — `linrdp/src/session/fileagent.rs:542`

**Regresja F04; potwierdzona wykonaniem helpera.** Przed zmianą kolejny zestaw plików otrzymywał nowy numer katalogu. Teraz `paste_dir` jest tworzony raz na całe życie helpera; każde `on_remote_file_list` otrzymuje tę samą ścieżkę. `create_below` usuwa poprzedni plik o tej samej nazwie i tworzy nowy. Dwa kolejne kopiowania `report.txt` w jednym połączeniu podmieniają zawartość pod wcześniej udostępnionym URI. Aplikacja, która jeszcze odwołuje się do pierwszego transferu, może pobrać dane drugiego. Izolacja między użytkownikami jest poprawiona, ale izolacja generacji transferu została utracona.

Próba wykazała identyczną ścieżkę `paste_dir` i zmianę treści pod URI poprzedniego pliku po następnym `create_file`.

**Naprawa:** losowy podkatalog na transfer/generację w prywatnym katalogu sesji, powiązany z konkretnym `Download`. Zachowuj wcześniejsze pliki tak długo, jak mogą ich używać opublikowane URI. Testuj identyczne nazwy w dwóch kolejnych transferach i niezależność obu zawartości.

**Naprawiono 18 września 2026** (`a3cbb81`). Dokładnie tak: operacja `PasteDir` zmieniła się w `NewTransfer`, która przy każdym wywołaniu tworzy nowy losowy podkatalog `t<8 bajtów hex>` w prywatnym katalogu sesji i zwraca obie potrzebne połowy — nazwę (prefiks każdej ścieżki względnej tego transferu, żeby pomocnik rozwiązywał je w obrębie właściwej generacji) i ścieżkę bezwzględną (do budowania URI). `on_remote_file_list` woła ją raz na `Download`, więc katalog jest powiązany z konkretnym transferem.

Wcześniejsze pliki nie są ruszane: URI wydane pulpitowi mają zachować znaczenie. Usuwa je dopiero dobowy przegląd pomocnika, który i tak dotyka tylko katalogów należących do tego UID.

Test: `a_second_transfer_does_not_overwrite_the_first` (`fileagent.rs`) kopiuje `report.txt` dwa razy w jednym połączeniu i sprawdza, że katalogi są różne, a obie zawartości nadal czytelne pod swoimi ścieżkami — czyli że URI pierwszego transferu nadal znaczy to, co znaczyło.

### R08 [P2] Numeruj deskryptory według listy rzeczywiście reklamowanej klientowi — `linrdp/src/clipboard.rs:793`

**Wcześniej istniejący defekt, ujawniony przy kontroli F03; potwierdzony statycznie.** Po odrzuceniu ścieżki przez `stat` lub `!is_file`, lista `descriptors` jest zwarta, ale mapa `offered` nadal używa indeksów oryginalnego `paths`. Dla wejścia `[katalog, a.txt, b.txt]` klient widzi indeksy 0 = a, 1 = b, podczas gdy backend przechowuje 1 = a, 2 = b. Pierwsze żądanie zostanie odrzucone, a kolejne może zwrócić zawartość a jako b. Dotyczy mieszanych zaznaczeń katalogów i plików oraz plików usuniętych w trakcie kopiowania. Nowy helper nie usuwa tego rozjazdu.

**Naprawa:** użyj indeksu z `descriptors.len()` przed dodaniem poprawnego deskryptora, a nie z `paths.enumerate()`. Testuj pominięty element na początku i w środku oraz rzeczywiste żądania SIZE/RANGE każdego reklamowanego indeksu.

**Naprawiono 18 września 2026** (`a3cbb81`). Indeks pochodzi z `descriptors.len()` sprzed dodania wpisu, wyodrębniony jako `advertised_index`, żeby reguła dała się sprawdzić bez schowka X11.

Test: `offered_files_are_keyed_by_the_index_the_client_will_ask_for` (`clipboard.rs`) przechodzi zaznaczenie z elementem pominiętym na początku **i** w środku, i wymaga kluczy 0, 1, 2 bez dziur. Rzeczywistych żądań SIZE/RANGE dla każdego reklamowanego indeksu nie testowano — wymaga klienta CLIPRDR.

### R09 [P2] Waliduj dodatnie limity także przy wczytaniu YAML — `linrdp/src/config/mod.rs:243`

**Regresja konfiguracji F07; potwierdzona produkcyjnym parserem i walidatorem.** TUI odrzuca zero w `parse_limit`, ale `Limits` deserializuje zwykłe `u32`, a wspólne `config::validate` nie sprawdza nowych pól. Konfiguracja z `max_workers: 0` lub `max_per_client: 0` jest uznawana za poprawną, usługa może związać port i następnie odrzucać wszystkich klientów. `handshake_seconds: 0` również jest przyjmowane mimo deklarowanego minimum 1. To wprowadza odmienną semantykę konfiguracji edytowanej w TUI i ręcznie.

**Naprawa:** wspólna walidacja trzech wartości przed startem supervisora/workera. Próba w załącznikach deserializuje YAML z trzema zerami i potwierdza `validate(...).is_ok()`. Testy powinny osobno sprawdzić każde zero i poprawne wartości graniczne.

**Naprawiono 18 września 2026** (`a3cbb81`). `check_limits` w `config::validate` — czyli tam, gdzie przechodzi i plik pisany ręcznie, i plik zapisany przez przeglądarkę ustawień, więc obie drogi znaczą to samo. Zero jest odmawiane w każdym z trzech pól, z podaną wartością domyślną w komunikacie.

Dołożono regułę, której raport nie wymagał, ale która jest z tej samej rodziny: `max_per_client` powyżej `max_workers` parsuje się poprawnie, a mimo to nie może nigdy zadziałać — pojedynczy klient miałby prawo do większej liczby połączeń niż cała maszyna obsługuje.

Testy: `a_limit_of_zero_is_refused_wherever_it_was_written` (osobno każde z trzech pól, przez produkcyjny parser YAML), `the_smallest_real_limits_are_accepted` (wartości graniczne 1 oraz wbudowane domyślne) i `one_client_may_not_be_allowed_more_than_the_whole_machine`.

### R10 [P2] Nie zastępuj błędu inicjalizacji działającego PAM decyzją z shadow — `linrdp/src/auth.rs:226`

**Niepełna naprawa F06; potwierdzona statycznie.** Raport napraw deklaruje fallback wyłącznie wtedy, gdy libpam nie można załadować. W rzeczywistości `decide` przechodzi do shadow po każdym `Err` z `pam::authenticate`. Ten sam `Err` jest zwracany również po niepowodzeniu `pam_start` (`pam.rs:283–285`), już po poprawnym załadowaniu biblioteki. Przy błędzie inicjalizacji PAM, poprawnym haśle lokalnym i niewygasłym wpisie shadow można uzyskać `Accept`, choć reguły `pam_access`, `pam_time` czy inne wymagania stosu w ogóle nie zostały wykonane. Znaczenie ma zwłaszcza reconnect/console, bez późniejszego otwarcia nowej sesji PAM.

To nie jest dowód, że zdalny klient może dowolnie spowodować błąd `pam_start`; jest to niebezpieczna ścieżka awarii backendu. Nie wymuszano awarii systemowego PAM podczas audytu.

**Naprawa:** typowane rozróżnienie „brak opcjonalnej biblioteki” i „błąd skonfigurowanego backendu”. Drugi stan musi zamykać dostęp. Ewentualny tryb bez PAM powinien być jawną polityką administratora, nie efektem błędu. Testy z wstrzykiwanym backendem: brak biblioteki zgodny z konfiguracją, błąd `pam_start`, odmowa auth, odmowa account.

**Naprawiono 18 września 2026** (`a3cbb81`). Rozróżnienie jest typowane: `pam::NoVerdict::NotInstalled` (nie ma libpam ani brakuje symbolu — na tej maszynie nie ma polityki do ominięcia) kontra `NoVerdict::BackendFailed` (biblioteka się załadowała i stos zawiódł — polityka istnieje i nie wykonała się). `decide` schodzi do `/etc/shadow` wyłącznie na pierwszym, a na drugim zwraca `Login::Unavailable`, które wszyscy wołający traktują jako zamknięcie dostępu — nie `Deny`, żeby nie dało się go pomylić ze złym hasłem. Niepowodzenie `pam_start` jest od teraz `BackendFailed`, i to był ten konkretny przypadek z raportu.

Jawnego trybu „bez PAM jako polityka administratora" nie dodano: to nowy przełącznik konfiguracji, a nie naprawa tej luki. Obecne zachowanie — fallback wyłącznie przy faktycznym braku biblioteki — jest zawężeniem, nie rozszerzeniem uprawnień.

Test: `a_broken_pam_stack_closes_the_door_while_an_absent_one_falls_back` (`auth.rs`). Testów z wstrzykiwanym backendem PAM (odmowa auth, odmowa account) nie ma — `pam.rs` ładuje libpam przez `dlopen` do statycznego `OnceLock`, więc wstrzyknięcie wymagałoby wprowadzenia warstwy abstrakcji, czego przy tej poprawce nie robiono.

## Weryfikacja ustaleń pierwszego raportu

„Zamknięte” poniżej dotyczy konkretnego pierwotnego defektu w badanym kodzie, nie certyfikacji całego obszaru.

Kolumna „Po naprawach R" dopisana 18 września 2026, po zamknięciu ustaleń R01–R10 (`a3cbb81`).

| Pierwotne ustalenie | Ocena po drugim przebiegu | Dowód / pozostała praca | Po naprawach R |
|---|---|---|---|
| F01 — root zapisuje Xauthority przez symlink | Pierwotna eskalacja usunięta; regresja funkcjonalna | Zapis następuje po `drop_to`, brak chown celu; R01 blokuje świeży greeter | R01 naprawione — greeter tworzy własny runtime |
| F02 — utrata rezerwacji i sesja innego konta | Częściowo zamknięte | Rezerwacja przekazywana bez przerwy, kontrola nazwy konta w dwóch miejscach; R02 i R03 pozostają | R02 i R03 naprawione — CLOEXEC po adopcji, blokada per UID |
| F03 — pliki schowka czytane jako root | Pierwotny defekt zamknięty | Rzeczywisty exec helpera: odczyt własnego pliku działa, root 0600 i drugi UID 0600 odrzucone; R06 dotyczy startu helpera | R06 naprawione — start leniwy, przy zmianie właściciela |
| F04 — wspólny przewidywalny katalog | Pierwotna kolizja między workerami usunięta | Losowa nazwa, prywatny katalog, operacje jako UID; R07 dotyczy kolejnych transferów jednego workera | R07 naprawione — katalog na transfer |
| F05 — brak aktualnej kontroli konta NLA | Naprawione w drodze supervisorowej; nie globalnie | `authorize_for_desktop` przed attach i console; R05 dotyczy direct, R10 awarii backendu | R05 i R10 naprawione — router wszędzie, awaria PAM zamyka |
| F06 — hash zastępuje politykę PAM | Zasadniczo poprawione; niepełne zamknięcie | PAM-first i kontrola wieku shadow; R05 i R10; bez testu zmiany/wygaśnięcia rzeczywistych kont | R05 i R10 naprawione; testy rzeczywistych kont nadal brak |
| F07 — nieograniczone workery i ciche handshake | Pierwotny mechanizm poprawiony | Rejestr PID, limity, timeout; dodatkowa próba timeoutu udana; R09 dotyczy konfiguracji | R09 naprawione — wspólna walidacja limitów |
| F08 — nieograniczona alokacja RANGE | Zamknięte w badanej funkcji | Ograniczenie do 512 KiB i pozostałego rozmiaru przed alokacją, testy przechodzą | bez zmian |
| F09 — brak blokady po greeterze | Nadal otwarte funkcjonalnie | Wspólny stan i jawny logind ID są, lecz R04 uniemożliwia wykonanie cleanup przez worker | R04 naprawione — cleanup wykonuje się w drodze workera |
| F10 — utrata aktualizacji SAM | Zamknięte w prześledzonych writerach | Stały plik flock obejmuje read–modify–write oraz migrację; test synchronizacji przechodzi | bez zmian |
| F11 — `$5$` weryfikowane jako `$6$` | Zamknięte | Rozdzielone algorytmy, testy poprawnych/błędnych haseł przechodzą | bez zmian |

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

## Stan prac po drugim przebiegu — 18 września 2026

Dopisane po wykonaniu napraw; notatki pod poszczególnymi ustaleniami opisują każdą z nich osobno. Wszystkie dziesięć ustaleń R01–R10 jest naprawionych w `a3cbb81`.

1. **R01 i R05 — zrobione.** Świeży greeter tworzy własny katalog runtime i rysuje formularz. Autoryzację wymusza każdy tryb nasłuchu: router jest instalowany bezwarunkowo, a tryb bezpośredni bez `--serve-fd` jest odmawiany na starcie poza console. Macierzy rzeczywistych logowań supervisor/direct × NLA/system/greeter nie uruchomiono.
2. **R02–R04 i R10 — zrobione.** Rezerwacja jest zamykana przed `exec` i weryfikowana po tożsamości pliku oraz po tym, że nikt inny nie może jej wziąć. Sesja konta jest serializowana blokadą per UID. Sprzątanie po rozłączeniu wykonuje się w drodze workera, dokładnie raz, także dla błędu. Awaria skonfigurowanego stosu PAM zamyka dostęp zamiast schodzić do shadow.
3. **R06–R09 — zrobione.** Pomocnik plików startuje przy pierwszym użyciu i jest wymieniany przy zmianie właściciela sesji; schowek podąża za przekazaniem także w `DISPLAY`/`XAUTHORITY`. Każdy transfer ma własny katalog. Indeksy deskryptorów pochodzą z listy faktycznie wysłanej klientowi. Limity są walidowane wspólnie, niezależnie od tego, czym zapisano plik.
4. **Punkt 4 planu — niezrobiony.** Testy rzeczywistego logowania NLA/system/greeter, odwołania dostępu przy istniejącej sesji i rozłączenia z logind nadal nie istnieją: wymagają X, PAM, logind i klienta RDP. Uwaga o deterministycznych barierach została przyjęta tam, gdzie dało się ją spełnić bez tego — blokada konta (R03) i blokada magazynu SAM (F10) mają testy współbieżności z licznikiem wykrywającym nałożenie sekcji krytycznych, a nie adnotację „niemożliwe". Tam, gdzie bariera wymaga dwóch prawdziwych logowań, test nadal nie powstał i jest to zapisane pod danym ustaleniem, nie przemilczane.

Przyjęte zostały też trzy uwagi z sekcji „Korekty interpretacji dokumentu napraw":

- Deskryptory z `SCM_RIGHTS` odbierane są z `MSG_CMSG_CLOEXEC`.
- Opis `limits` nie twierdzi już, że limity nie dotyczą uwierzytelnionych sesji. Worker jest liczony od `accept` do zakończenia procesu, więc `max_workers` i `max_per_client` ograniczają połączenia żywe, a `max_per_client` liczy po adresie źródłowym — co zapisano wprost w opisach kluczy, razem z konsekwencją dla wielu użytkowników za jednym NAT-em. Model budżetów pozostaje bez zmian; zmieniona jest dokumentacja, która go opisywała nieprawdziwie.
- Sformułowanie z dopisku F02, że równoległość została zamknięta konstrukcyjnie, było za szerokie: zamknięty był wyścig o numer ekranu, nie o sesję konta. To drugie zamyka dopiero R03.

Pozostają otwarte wszystkie ryzyka wymienione w akapicie powyżej oraz punkt 5 planu z pierwszego raportu — niezależna weryfikacja, ponowne testy scenariuszy atakujących, aktualny audyt zależności i fuzzing parserów. Ocena z sekcji „Ocena końcowa" co do dopuszczenia do niezaufanego środowiska należy do audytora i ten dopisek jej nie zmienia.

Walidacja po naprawach: `cargo test -p linrdp --offline --no-default-features` — 306 testów jednostkowych i 2 integracyjne, wszystkie zaliczone; `cargo test -p ironrdp-server --offline --lib` — 16 zaliczonych; razem 324. `cargo clippy --all-targets` dla obu pakietów bez błędów. Nie wykonano testów end-to-end z rzeczywistymi klientami RDP, prób między UID na działającej maszynie ani niczego z tego, co wyżej oznaczono jako niezrobione.

Skrypty z [round2/](round2/) nie były modyfikowane. Uruchomione po naprawach zachowują się tak, jak zapowiadał raport — asercje oznaczone R przestały przechodzić:

| Skrypt | Wynik po naprawach |
|---|---|
| `config-proof.py` | `assertion failed: config::validate(&parsed).is_ok()` — konfiguracja z trzema zerami nie jest już poprawna (R09) |
| `connection-proof.py` | asercja F07 (cichy strumień zrywany po deadline) nadal przechodzi; `assert_eq!(called, 0)` zawodzi — `on_disconnected` jest teraz wołane (R04) |
| `reproduce.py` | nie kompiluje się: `no method named paste_dir` — operacja jest teraz `new_transfer`, katalog powstaje na transfer, nie na sesję (R07) |

Zgodnie z uwagą samego raportu: brak kompilacji **nie jest** dowodem naprawy, a odwrócona asercja dowodzi tylko tego, co dosłownie sprawdza. Dowodami są testy wymienione pod poszczególnymi ustaleniami.
