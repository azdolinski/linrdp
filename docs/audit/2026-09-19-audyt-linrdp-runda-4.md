# LinRDP — czwarty przebieg audytu, 19 września 2026

> Dalsza weryfikacja: [runda 5 — 19 września](2026-09-19-audyt-linrdp-runda-5.md), która po wdrożeniu U01–U04 wskazuje jedno nowe ustalenie (V01: brak close-on-exec na gnieździe klienta w workerze).

> Aktualizacja: wdrożono poprawki U01–U04. Szczegóły oraz wyniki 329 testów znajdują się w sekcji „Naprawy wdrożone po rundzie 4” na końcu dokumentu.

**Wynik: 4 ustalenia P2 wymagające interwencji — 3 w kodzie produkcyjnym i 1 w teście regresyjnym.** W badanym zakresie nie potwierdzono nowego P0/P1. T01 i T03 z trzeciego raportu są zamknięte w aplikacji; T02 poprawiono w samym pollerze, lecz pozostała inna droga przywracania starego środowiska X11.

Badano bieżące, **niezatwierdzone zmiany** na bazie `99b25881d1bea496e968a937241337282a4c3b5d`, w tym poprawki z poprzedniego zadania. Sam SHA commitu nie identyfikuje tego stanu: [sumy kontrolne badanych plików](round4/source-sha256.txt). Zakres obejmuje diff napraw, ich testy oraz powiązane ścieżki autoryzacji, lifecycle sesji, gate, schowka i operacji plikowych. Szersze ustalenia oznaczono jako istniejące wcześniej, aby nie przypisywać ich ostatnim poprawkom.

## Ustalenia

### U01 [P2] Usuń przywracanie globalnego środowiska w odczycie tekstu schowka — `linrdp/src/clipboard.rs:100–104`

**Pozostały problem obszaru T02/R06, nie regresja ostatniego diffu.** Poller nie zapisuje już środowiska, ale `x11_get_text` nadal zapisuje `DISPLAY` i `XAUTHORITY` z otrzymanych argumentów. `on_format_data_request` → `read_x11_text` pobiera parę przez `target()`, a następnie wywołuje tę funkcję. Równolegle wątek greeter może wykonać `gate::bind` i zmienić sesję. Jeśli snapshot powstał przed bind, a getter wykona się po nim, getter nadpisze nowe środowisko wartościami greeter. Generacja gate nie zmieni się ponownie i nowy poller celowo nie naprawia już środowiska. Odczyty arboard korzystają wtedy z niewłaściwego ekranu, a jawne operacje X11 mogą dostać cookie innego ekranu. Następne poprawne żądanie może przywrócić środowisko, ale bez niego awaria pozostaje.

[Próba komponentowa](round4/reproduce.py) wykonuje wyciętą bez zmian funkcję produkcyjną z prawdziwym arboard. Kontrolowany harmonogram to: stary snapshot → nowe środowisko po handover → odczyt ze starego snapshotu. Potwierdza nadpisanie obu zmiennych nawet przy niedostępnym X. Nie symuluje pełnego połączenia RDP ani nie dowodzi odczytu danych innego konta. Możliwość takiego przeplotu wynika z oddzielnego wątku `SessionRouter::show_greeter` i braku synchronizacji getter/bind.

**Naprawa:** operacje schowka powinny używać jawnego, spójnego kontekstu X11 sesji; odczyt nie może modyfikować globalnego środowiska. Samo usunięcie zapisów z jednego wątku nie zamyka problemu. Test z barierami powinien zatrzymać callback po pobraniu starego kontekstu, wykonać handover, wznowić odczyt i sprawdzić właściwy ekran/cookie oraz brak nadpisania środowiska.

### U02 [P2] Utrzymuj rezerwację konta do zakończenia lub anulowania startu keepera — `linrdp/src/session/mod.rs:159–160,300–305`

**Niepełne zamknięcie R03; istniejący wcześniej przypadek awarii lifecycle.** `AccountLock` należy do workera i jest zwalniany po powrocie `create`. `create` czeka na rekord tylko 20 sekund. Timeout z `wait_for_record` nie anuluje odłączonego keepera, którego PID nie jest zwracany przez `spawn_keeper`. Keeper może nadal czekać w PAM, potem uruchomić X i zapisać rekord. Przed tym zapisem kolejny login zdobywa zwolniony lock konta, nie znajduje rekordu i tworzy drugi keeper na innym ekranie. Pierwszy numer jest chroniony przez display lease, ale konto nie ma już ochrony przed drugim startem.

Dotyczy to opóźnionego startu, np. PAM/SSSD trwającego ponad 20 sekund, oraz analogicznie śmierci workera przed publikacją rekordu. Skutkiem mogą być dwa pulpity tego samego UID, zużycie zasobów i niejednoznaczne ponowne podłączenie, bo `registry::find` zwraca pierwszy pasujący numer. Osobne cookie zapobiegają poprzedniemu nadpisaniu cookie, ale nie zapobiegają podwójnemu pulpitowi. Nie wykazano dostępu do sesji innego UID.

[Próba](round4/reproduce.py) używa produkcyjnych `AccountLock`, `wait_for_record`, attach, registry i allocator. Po skróconym timeout zachowuje pierwszy display lease, zwalnia lock konta jak powrót `create`, tworzy drugi rekord, następnie publikuje spóźniony pierwszy. Wynik: dwa zajęte numery i dwa rekordy tego samego użytkownika. **Publikację keepera steruje harness; nie uruchamia się prawdziwych PAM/X ani procesów keepera.** To dowód błędu protokołu lifecycle, nie test całego logowania.

**Naprawa:** przekaż keeperowi ochronę stanu „konto jest w trakcie startu” albo wprowadź trwały, weryfikowany stan startującej sesji. Przy timeout anuluj konkretny start i potwierdź zakończenie przed dopuszczeniem nowego. Testy muszą obejmować spóźnioną publikację i śmierć workera; wzajemne wykluczanie tylko podczas poprawnego powrotu nie wystarcza.

### U03 [P2] Publikuj katalogi główne transferu zamiast wyłącznie pobranych plików — `linrdp/src/clipboard.rs:1251–1259`

**Defekt funkcjonalny istniejący wcześniej; potwierdzenie statyczne.** Dla deskryptora katalogu `on_remote_file_list` tworzy katalog i wykonuje `continue`, nie dodając go do zbioru publikowanego na schowku. `Download.done` zawiera wyłącznie ścieżki plików. `download_finished` publikuje je bezpośrednio jako URI, a dla pustej listy nie publikuje niczego.

W rezultacie kopia pustego folderu z Windows na Linux niczego nie oferuje do wklejenia, mimo utworzenia folderu w staging. Kopia drzewa `A/sub/file.txt` oferuje URI samego `file.txt`, więc menedżer plików wkleja liść zamiast drzewa `A`. Dwa pliki o tej samej nazwie w różnych podkatalogach stają się konfliktującymi elementami wklejenia. Katalogi są tworzone na dysku, lecz tracona jest semantyka wyboru użytkownika.

**Naprawa:** oddziel listę pobieranych plików od listy elementów głównych publikowanych do wklejenia. URI powinny obejmować wybrane foldery i samodzielne pliki, bez powtarzania dzieci folderów; uwzględnij puste katalogi i nieudane pobrania. Testuj pusty folder, drzewo z podfolderem oraz dwa jednakowe basename w różnych folderach. Nie wykonano w tym przebiegu rzeczywistego transferu folderów przez klienta CLIPRDR; ustalenie wynika z pełnej ścieżki budowy `pending` → `done` → URI.

### U04 [P2] Sprawdzaj pracę wątku pollera, a nie tylko sukces procesu testowego — `linrdp/src/clipboard.rs:1432–1440`

**Regresja testu dodanego przy ostatniej naprawie, potwierdzona wykonaniem.** Test używa ekranów `:59998` i `:59997`. W użytej wersji `x11rb-protocol` przygotowanie połączenia dodaje do numeru ekranu bazę portu 6000; w debug powoduje to overflow `u16`. Wątek `linrdp-cliprdr-poll` panikuje przy pierwszej iteracji. Jego `JoinHandle` nie jest sprawdzany, więc proces testu nadal kończy się sukcesem: asercje widzą zmienne ustawione przez sam gate. Druga faza „handover” sprawdzana jest już bez działającego pollera.

Zapis [poller-test-output.txt](round4/poller-test-output.txt) pokazuje kolejno `attempt to add with overflow`, a następnie `test ... ok`. Odtworzenie:

```sh
LINRDP_TEST_POLLER_BINDING=1 cargo test -p linrdp --offline --no-default-features \
  --bin linrdp clipboard::tests::poller_does_not_restore_the_screen_captured_before_binding \
  -- --exact --nocapture
```

**Naprawa:** wybierz poprawne numery ekranów i wprowadź obserwowalny sygnał pracy pollera po każdym bind, z kontrolą zakończenia/paniki. Najlepiej testuj rzeczywistą selekcję na izolowanych Xvfb. Zmiana samych numerów usuwa panic, ale nadal nie dowodzi właściwego odczytu schowka. Nie przypisuję tego panic zwykłym wdrożeniom z domyślnym zakresem ekranów — wykazana usterka dotyczy testu.

## Weryfikacja ostatnich trzech poprawek

| Punkt | Ocena w rundzie 4 |
|---|---|
| T01 — direct console pomija router | Zamknięte w aplikacji: odmowa bez `--serve-fd` przed inicjalizacją; brak wywołania `server.run()`. Console przez supervisor pozostaje dostępne. Ogólnej pętli preemption biblioteki nie naprawiano i nie należy do niej wracać bez odrębnej naprawy. |
| T02 — poller startuje ze starym ekranem | Konkretny snapshot pollera usunięty. Cały obszar wymaga U01; poprzedni dowód testowy ma wadę U04. |
| T03 — błąd loadera PAM uruchamia shadow | Zamknięte w badanej drodze. Loader zwraca błąd zamykający dostęp; `decide` nie ma już fallbacku. Próby niekompletnej/uszkodzonej biblioteki, błędu startu i odmów PAM przechodzą. |

Decyzje kompatybilności z poprzedniego zadania są widoczne w README/pomocy: brak trybu direct także dla console i wymóg działającego PAM. Nie traktuję ich jako regresji wymagających przywrócenia niebezpiecznego zachowania.

## Testy i ograniczenia dowodowe

Ponownie uruchomiono:

- `cargo test -p linrdp --offline --no-default-features`: 305 jednostkowych + 2 capture + 1 direct + 3 loader PAM.
- `cargo test -p ironrdp-server --offline --lib`: 16.
- **327 testów zgłoszonych jako zaliczone**, lecz z istotnym zastrzeżeniem U04. Zielony wynik Cargo nie jest tu dowodem, że poller przeżył scenariusz.
- Próby komponentowe U01/U02: [źródło](round4/reproduce.py), [wynik](round4/output.txt). Uruchomienie: `python3 docs/audit/round4/reproduce.py` po aktualnym buildzie. Wymagane `rustc` i bieżące `.rlib`; nie wymaga sudo. Harness kompiluje wybrane niezmienione fragmenty produkcyjne i całe wskazane moduły, a sterowanie przebiegiem opisano przy ustaleniach.
- [Podsumowanie testów](round4/test-results.txt), [osobny wynik wadliwego testu](round4/poller-test-output.txt).

Nie zmieniano kodu produkcyjnego ani jego testów w tym przebiegu. Utworzono raport, skrypt dowodowy i zapisy wyników; poprzedni raport otrzymał odsyłacz. Nie zmieniano systemowego PAM, kont, usług ani istniejących ekranów.

To audyt ukierunkowany, nie pełna certyfikacja projektu. Nie wykonano nowych pełnych loginów RDP, rzeczywistego opóźnienia PAM, testów logind, macierzy Wayland/urządzeń, fuzzingu ani aktualnego skanu zależności/CVE. Ryzyka wcześniej opisane dla SAM, pamięci haseł i uprzywilejowanych workerów pozostają poza potwierdzonym zamknięciem. Najpierw należy usunąć U01 i poprawić test U04, następnie zabezpieczyć lifecycle U02 i semantykę transferu katalogów U03.

## Naprawy wdrożone po rundzie 4 — 19 września 2026

Na polecenie użytkownika zmieniono kod dla U01–U04. Ustalenia powyżej i `source-sha256.txt` pozostają historycznym zapisem stanu przed naprawami.

### U01 — jawny kontekst odczytu X11

`x11_get_text` nie zapisuje już zmiennych środowiska i nie korzysta z arboard do odczytu. Otwiera połączenie z jawnym ekranem i cookie przez `read_selection_target_with_auth`. Poller używa tej samej drogi dla tekstu i list URI. `gate::clipboard_target` pobiera ekran oraz ścieżkę cookie z jednego snapshotu pod mutexem, więc nie miesza pól dwóch sesji. Odczyt rozpoczęty ze starym snapshotem może dokończyć się na starym ekranie, ale nie przekieruje kolejnych odczytów ani środowiska nowej sesji.

Zachowano obsługę długiego tekstu: odczyt X11 rozpoznaje INCR i odbiera części z limitem 8 MiB oraz 3 sekund dla transferu przyrostowego. Zwykłe oczekiwanie na selekcję pozostaje ograniczone do 300 ms. Niekompletny lub przekraczający limit wynik nie jest przedstawiany jako kompletny tekst.

### U02 — blokada konta przekazywana keeperowi

Worker przekazuje dodatkowo keeperowi ten sam opis otwartego pliku blokady konta na fd 5. Źródłowy duplikat jest umieszczany poza fd 4/5, aby przekazanie blokady ekranu nie nadpisało źródła blokady konta. Keeper przywraca CLOEXEC przed uruchamianiem potomków i utrzymuje blokadę do zakończenia zapisu rekordu sesji. Błąd lub śmierć keepera zamyka jego kopię automatycznie.

Timeout albo śmierć workera nie zwalnia już trwającego startu konta. Kolejne logowanie czeka na rozstrzygnięcie istniejącego startu zamiast tworzyć drugi pulpit. To nie dodaje anulowania zawieszonego PAM: dopóki keeper rzeczywiście pozostaje w trakcie startu, rezerwacja konta pozostaje zajęta. Publiczne wejście `attach_or_create` obejmuje blokadą lookup/create; `create` jest prywatne i wymaga przekazania blokady.

Test uruchamia rzeczywisty proces przez exec, adoptuje fd, wymusza timeout oczekiwania na rekord, zamyka kopię workera i sprawdza odmowę niezależnego flock. Następnie sprawdza oba zakończenia: publikację rekordu oraz zabicie procesu przed publikacją. W obu przypadkach blokada zostaje zwolniona; po publikacji istniejąca sesja jest widoczna. To test protokołu przekazania blokady i rejestru, bez otwierania prawdziwej sesji PAM/X przez keepera.

### U03 — publikowanie kompletnych elementów głównych

Download zachowuje osobno listę oczekiwanych ścieżek i listę ukończonych plików/katalogów. Publikowane są elementy główne wyboru, a nie wszystkie jego liście. Puste foldery są uwzględniane. Niepowodzenie dowolnego wymaganego elementu wyłącza publikację jego całego folderu; niezależne poprawne elementy mogą być wklejone. Zbiór ukończonych elementów i mapa statusu korzeni eliminują potrzebę wielokrotnego przeszukiwania całej listy dla każdego pliku.

Test przechodzi przez produkcyjne `on_remote_file_list` i pomocnika plików: sprawdza pusty katalog, drzewo `A/sub/same.txt`, `B/same.txt` i samodzielny plik. Potem podaje rzeczywistą odpowiedź błędu FileContents i wymaga opublikowania tylko niezależnego poprawnego pliku.

### U04 — test działającego pollera na Xvfb

Zastąpiono sztuczne numery ekranów dwoma izolowanymi Xvfb z automatycznym przydziałem numeru. Test wymaga Xvfb w PATH; jego brak nie jest cicho pomijany. Sprawdza reklamowanie danych przez poller na pierwszym i drugim ekranie, treść odczytów po handover, odczyt ze starego snapshotu bez nadpisania nowego środowiska oraz tekst długości 1 000 000 bajtów serwowany przez arboard. Na końcu zatrzymuje poller i sprawdza jego `JoinHandle`; panika wątku jest błędem testu. Syntetyczne serwery i katalog cookie są sprzątane.

### Wyniki

- `cargo test -p linrdp --offline --no-default-features`: **307 jednostkowych + 2 capture + 1 direct + 3 loader PAM**, wszystkie zaliczone.
- `cargo test -p ironrdp-server --offline --lib`: **16 zaliczonych**.
- Łącznie **329 testów Cargo**. Osobno uruchomiony test pollera na Xvfb również przeszedł bez paniki.
- `cargo clippy -p linrdp --offline --no-default-features --all-targets`: bez błędów, z ostrzeżeniami.
- `git diff --check`: bez błędów.
- [Zapis wyników po naprawach](round4/fix-results.txt).

Nie zmieniano kont ani systemowej konfiguracji PAM, nie wdrażano usługi. Nie wykonano pełnej sesji klienta RDP ani rzeczywistego powolnego logowania PAM. Wyniki potwierdzają wskazane komponenty i scenariusze regresyjne; nie zastępują odrębnego audytu całego produktu.
