# LinRDP — trzeci przebieg audytu, 18 września 2026

> Dalsza weryfikacja: [runda 4 — 19 września](2026-09-19-audyt-linrdp-runda-4.md), w tym pozostała droga nadpisania środowiska schowka i korekta oceny testu pollera.

> Aktualizacja 19 września 2026: wdrożono poprawki T01–T03. Szczegóły i wyniki testów w sekcji „Naprawy wdrożone” na końcu dokumentu.

Badany commit: `99b25881d1bea496e968a937241337282a4c3b5d`. Podstawa porównania: `35caab4c1a0a278294afc1da38bf6ce00b39660f`; naprawy: `a3cbb81`. Przeczytano [drugi raport wraz z notatkami napraw](2026-09-18-audyt-linrdp-runda-2.md), zmiany kodu produkcyjnego i testów oraz powiązane ścieżki wywołań.

**Wynik: 3 ustalenia wymagające pracy — 1 × P1, 2 × P2.** Siedem punktów drugiego raportu można zamknąć w zakresie opisanych defektów. Trzy wymagają częściowego ponownego otwarcia: R05, R06, R10. To nie oznacza, że ich poprawki niczego nie naprawiły; poniżej rozdzielono naprawione przypadki od pozostałych luk. Wszystkie **324 testy projektu** uruchomione w tym przebiegu przeszły.

## Ustalenia

### T01 [P1] Zachowaj kontrolę autoryzacji podczas obsługi połączenia z preemption — `linrdp/src/main.rs:628`

**R05 częściowo otwarte; potwierdzenie statyczne pełnej ścieżki wywołań.** Bezwarunkowe zainstalowanie routera nie zapewnia jego wykonania w dozwolonym nadal trybie `--listener` + console. `main.rs:793` włącza `with_preempt_existing_session(true)`. W `RdpServer::run`, `server.rs:2583`, handler jest wyjmowany przez `self.connection_handler.take()` **przed** uruchomieniem `run_connection_inner` lub `serve_negotiated`. Wraca do `self` dopiero po zakończeniu sesji (`server.rs:2733`). Tymczasem `client_accepted` wywołuje `on_connection_info` wyłącznie przez `self.connection_handler` (`server.rs:3804–3814`), który przez ten czas jest `None`. Lokalny handler w pętli obsługuje `on_accept`, ale nie ten callback.

Skutek dla NLA: poprawny dowód wobec starego hasła zachowanego w SAM może nadal otworzyć współdzielony pulpit po odwołaniu dostępu w PAM lub zmianie hasła systemowego. HYBRID/HYBRID_EX nie wypełnia `AcceptorResult.credentials` z Client Info (`crates/ironrdp-acceptor/src/connection.rs:930`), więc dodatkowy `ShadowValidator` jest pomijany; zamierzony aktualny werdykt leży właśnie w niewywołanej gałęzi console routera (`session/router.rs:283–307`). Nie jest to dostęp bez dowodu NLA: atakujący musi nadal znać sekret akceptowany przez SAM. Problem dotyczy jawnego trybu bezpośredniego, nie standardowego workera używającego `run_connection`. Nieprzypisanie `CONSOLE_USER` wyłącza też pomocnika plików w tym trybie.

**Naprawa:** zapewnij niepomijalną autoryzację także w pętli preemption; jako ograniczenie doraźne można odmówić również bezpośredniego console. Samo przeniesienie routera do buildera nie wystarcza. Test powinien wykonać udane negocjacje przez `run()` z preemption, sprawdzić callback zarówno dla pierwszego klienta, jak i zwycięskiego kandydata, oraz odrzucić login przy aktualnej odmowie PAM. Testy cichych socketów i `on_accept` nie dochodzą do tego miejsca.

**Granica dowodu:** nie wykonano pełnego logowania RDP ze starym hasłem ani zmiany prawdziwego konta. Wykazano pominięcie jedynej kontroli wskazanej przez poprawkę na tej drodze. Zakaz direct poza console poprawnie zamyka poprzedni przypadek greeter bez formularza.

### T02 [P2] Zainicjalizuj poller schowka z aktualnego powiązania sesji — `linrdp/src/clipboard.rs:750–752`

**R06 częściowo otwarte; deterministyczna próba inicjalizacji i analiza kolejności wywołań.** Poller bierze `display` i `xauthority` ze snapshotu backendu, ale `bound_at` z aktualnej generacji gate. Backend powstaje w `attach_channels` przed negocjacją (`server.rs:2336`, `2010`), a router wiąże ekran przed startem kanałów (`server.rs:3804–3839`). Gdy worker odziedziczył niepuste `DISPLAY`/`XAUTHORITY` sprzed tego powiązania, poller uruchamia się więc ze starym ekranem, jednocześnie uznając aktualną generację za już obsłużoną. Dla zwykłego NLA/system nie ma kolejnego handover, który to naprawi. Kod dodatkowo nadpisuje środowisko procesu starymi wartościami (`clipboard.rs:755–761`).

Przykład: backend zapisuje `:77`, router wiąże `:88` i zwiększa generację do 1, po czym poller zapisuje `display=:77, bound_at=1`. Kolejne porównanie `now != bound_at` jest fałszywe. Schowek lokalny nie synchronizuje właściwego pulpitu; jeśli stary ekran nadal jest osiągalny z przechwyconym cookie, odczyty dotyczą jego schowka. Nie wykazano rzeczywistego wycieku danych między kontami. Przy pustym środowisku startowym część operacji może poprawnie korzystać z nowego środowiska — problemu nie należy opisywać jako bezwarunkowej awarii każdego wdrożenia.

**Naprawa:** również pierwszy odczyt pollera musi pobrać ekran i cookie z aktualnego gate, w spójności z generacją. Najlepiej przekazywać jawny snapshot sesji do operacji X11 zamiast przywracać globalne środowisko z konstrukcji backendu. Testy: bind przed `on_ready`, bind po starcie pollera oraz greeter → desktop, z różnymi początkowymi wartościami środowiska.

**Dowód:** [poller-proof.py](round3/poller-proof.py) wycina i wykonuje bez zmian produkcyjny fragment inicjalizacji w kontrolowanym harnessie z generacją 1. Potwierdza stare wartości i nadpisanie środowiska; nie jest testem całego backendu ani klienta X11/RDP. [Wynik](round3/poller-output.txt). Leniwy start helpera według aktualnego użytkownika jest poprawiony; nowa funkcja `target()` również korzysta z gate, ale poller jej nie używa na starcie.

### T03 [P2] Odróżnij awarię ładowania PAM od faktycznego braku biblioteki — `linrdp/src/pam.rs:299–301`

**R10: konkretny błąd `pam_start` naprawiony, szerszy mechanizm fail-open nadal obecny.** Każdy błąd `load_pam` mapuje się na `NoVerdict::NotInstalled`, także brak symbolu po udanym `dlopen`. `auth::decide` wówczas przechodzi do shadow (`auth.rs:242–259`). Brak symbolu w bibliotece lub niespełniona zależność loadera nie dowodzą, że administrator nie skonfigurował polityki PAM. Uszkodzona lub niekompatybilna instalacja może więc zmienić politykę autoryzacji z PAM na samo lokalne hasło i reguły shadow. Dotyczy to zwłaszcza console/reconnect, gdzie późniejsze otwarcie nowej sesji PAM nie zatrzyma dostępu.

Próba załadowała kontrolną bibliotekę `libpam.so.0` z funkcjami uwierzytelniania, ale bez `pam_getenvlist`. Rzeczywiste `pam::authenticate` zwróciło `NotInstalled("missing symbol pam_getenvlist")`. To symbol obsługi środowiska sesji, a jego brak blokuje nawet sprawdzenie hasła i konta, po czym umożliwia fallback. Nie zmieniano systemowej biblioteki ani konfiguracji PAM; `LD_LIBRARY_PATH` ustawiono tylko dla procesu próby. Nie wykazano możliwości wywołania tej awarii przez zdalnego klienta.

**Naprawa:** nieudane `dlsym` po załadowaniu biblioteki traktuj jako `BackendFailed`. Błędu `dlopen` również nie utożsamiaj automatycznie z brakiem instalacji; najlepiej dopuścić shadow-only wyłącznie jako jawną politykę. Testuj produkcyjny loader i decyzję, w osobnych procesach ze względu na `OnceLock`: brak biblioteki, niekompletna biblioteka, błąd `pam_start`, odmowa auth i odmowa account.

**Dowód:** [pam-proof.py](round3/pam-proof.py) kompiluje produkcyjny `pam.rs` oraz tymczasową bibliotekę kontrolną. [Wynik](round3/pam-output.txt). Próba potwierdza klasyfikację błędu; przejście do shadow wynika z rzeczywistego `decide`, bez sprawdzania prawdziwych haseł. Test `a_broken_pam_stack_closes_the_door_while_an_absent_one_falls_back` sprawdza pomocnicze funkcje testowe i skonstruowany enum, nie drogę loader → `decide`, dlatego nie wykrywa tego przypadku.

## Status ustaleń drugiego raportu

„Zamknięte” dotyczy konkretnego defektu i podanego zakresu dowodowego, nie całego podsystemu.

| Punkt | Stan po trzecim przebiegu | Podstawa |
|---|---|---|
| R01 — brak runtime greeter | Zamknięte | `Greeter::start` tworzy katalog; rzeczywisty zapis cookie do świeżego przygotowanego runtime działa. Bez pełnego uruchomienia formularza/X. |
| R02 — dziedziczenie blokady ekranu | Zamknięte | Produkcyjne `adopt` + `keeper::spawn_child`: dziecko z niższym UID po exec nie ma fd 100, numer pozostaje zajęty. Przetestowano również CLOEXEC otrzymanego fd pliku. |
| R03 — równoległe tworzenie sesji konta | Zamknięte w badanej ścieżce | Blokada per UID obejmuje lookup i create/wait-for-record; test wzajemnego wykluczania przechodzi. Osobna próba potwierdza zachowanie cookie pierwszego ekranu po zapisie drugiego. Bez dwóch rzeczywistych równoległych loginów. |
| R04 — brak callbacku rozłączenia workera | Zamknięte | Produkcyjny `run_connection` z timeoutem wywołuje callback dokładnie raz. Wrapper obejmuje powrót sukcesu i błędu. Nie testowano faktycznego zablokowania ekranu przez logind. |
| R05 — autoryzacja direct | Częściowo otwarte → T01 | Direct bez console odmawiany, ale console + preemption pomija callback routera. |
| R06 — helper i schowek po handover | Częściowo otwarte → T02 | Helper startuje leniwie według gate; początkowy stan pollera nadal może pochodzić z innego ekranu. |
| R07 — nadpisywanie poprzedniego transferu | Zamknięte | Rzeczywisty helper tworzy dwa katalogi; zapis tego samego basename w drugim zachowuje treść pierwszego URI. |
| R08 — indeksy po filtrowaniu plików | Zamknięte | Indeks z `descriptors.len()` przed push jest wspólny dla mapy i wysłanej listy; test przechodzi. Bez pełnego klienta CLIPRDR. |
| R09 — zerowe limity YAML | Zamknięte | Produkcyjny parser i wspólna walidacja testowane osobno dla każdego zera; dodatnie granice przechodzą. |
| R10 — fallback po awarii PAM | Częściowo otwarte → T03 | `pam_start` daje teraz odmowę; błędy loadera nadal dopuszczają shadow. |

W notatkach drugiego raportu należy zawęzić deklaracje „każdy tryb nasłuchu”, „schowek podąża za przekazaniem” i „fallback wyłącznie przy faktycznym braku biblioteki”. Obecny kod nie spełnia ich we wszystkich opisanych wyżej przypadkach. Korekty dokumentacji limitów odpowiadają rzeczywistemu zliczaniu żywych workerów.

## Wykonana walidacja i reprodukcje

- `cargo test -p linrdp --offline --no-default-features`: **306 jednostkowych + 2 integracyjne**, wszystkie zaliczone.
- `cargo test -p ironrdp-server --offline --lib`: **16**, wszystkie zaliczone.
- Łącznie **324 testy**, bez pełnego workspace i wszystkich features. Podsumowanie: [test-results.txt](round3/test-results.txt).
- [reproduce.py](round3/reproduce.py): produkcyjne moduły przez `#[path]`, rzeczywisty exec helpera i dziecka z obniżonym UID; [wynik](round3/component-output.txt). Własny plik można czytać, kontrolne pliki root 0600 i innego UID 0600 są odrzucane.
- [connection-proof.py](round3/connection-proof.py): cichy strumień przerwany po około 51 ms przy limicie 50 ms, callback raz; [wynik](round3/connection-output.txt).
- Dwie próby T02/T03 opisane przy ustaleniach. T01 potwierdzono analizą kodu, bez testu end-to-end.

Polecenia po aktualnym buildzie:

```sh
python3 docs/audit/round3/reproduce.py
python3 docs/audit/round3/connection-proof.py
python3 docs/audit/round3/pam-proof.py
python3 docs/audit/round3/poller-proof.py
```

Pierwszy skrypt wymaga `sudo -n`, istniejącego nieuprzywilejowanego konta oraz `nobody`. Uprawnienia root wykorzystano tylko do tymczasowych plików kontrolnych i dzieci testu; nie zmieniano kont, usług, systemowych bibliotek ani konfiguracji PAM. Nie odczytywano rzeczywistych sekretów. Skrypty korzystające z `.rlib` wymagają aktualnych artefaktów tego checkoutu. Historyczne skrypty `round2` pozostawiono bez zmian.

## Ocena i następne kroki

Postęp jest potwierdzony mocniejszymi dowodami niż sama kompilacja: rzeczywiste dzieci nie dziedziczą blokady, pomocnik zachowuje separację UID, kolejne transfery nie nadpisują wcześniejszych, a worker wykonuje callback. **Nie można jednak potwierdzić deklaracji zamknięcia wszystkich ustaleń.** Najpierw należy naprawić T01, następnie T02 i T03, i wykonać macierz rzeczywistych logowań oraz odwołania dostępu przy istniejącej sesji.

To ukierunkowany ponowny audyt zmian i powiązanych granic bezpieczeństwa, nie certyfikacja całego projektu. Nie wykonano pełnych sesji mstsc/FreeRDP, Wayland, urządzeń USB/mikrofonu, fuzzingu parserów ani aktualnego skanu CVE/zależności. Pozostają poprzednio opisane ryzyka konstrukcji magazynu SAM, przechowywania haseł w pamięci, parsowania protokołu przez root oraz cyklu życia workerów/keeperów w systemd. Nie przypisano im nowych numerów bez nowego, odrębnego dowodu defektu.

W tym przebiegu zmieniono wyłącznie dokumentację i artefakty audytu w `docs/audit/`; kodu produkcyjnego nie poprawiano.

## Naprawy wdrożone 19 września 2026

Na polecenie użytkownika poprawiono kod dla T01–T03. Powyższe ustalenia opisują stan badanego commitu sprzed tych zmian.

- **T01 — zamknięta podatna ścieżka LinRDP.** `serve()` odrzuca każde wywołanie bez `--serve-fd` przed wczytaniem konfiguracji i inicjalizacją ekranu. Usunięto wywołanie `server.run()` z aplikacji. Console nadal działa przez supervisor i `run_connection`, z routerem autoryzacji. Nie przebudowywano ogólnej pętli preemption biblioteki; jej ponowne wykorzystanie do obsługi LinRDP wymagałoby osobnej naprawy i testów. Test integracyjny uruchamia prawdziwy program z `--listener`, nieistniejącą konfiguracją i niedostępnym ekranem, wymagając jednoznacznej odmowy trybu direct.
- **T02 — poprawiony start i aktualizacja pollera.** Pierwsza oraz każda kolejna iteracja odczytuje ekran z gate; nie ma początkowego snapshotu backendu. Niezwiązany uzbrojony worker pomija odczyt. Poller nie zapisuje już `DISPLAY` ani `XAUTHORITY`, więc nie przywraca wartości sprzed powiązania. Generacja zaczyna się jako `None`, dzięki czemu pierwszy odczyt zeruje cache także po wcześniejszym bind. Test uruchamia prawdziwe `on_ready` w osobnym procesie, wiąże greeter przed startem, następnie sesję użytkownika, i potwierdza zachowanie właściwego środowiska po obu etapach. Nie wymaga działającego ekranu; nie stanowi testu transferu schowka end-to-end.
- **T03 — usunięty automatyczny fallback autoryzacji do shadow.** Błędy loadera i `pam_start` klasyfikowane są jako `BackendFailed`. Produkcyjna funkcja decyzji akceptuje wyłącznie pozytywny wynik PAM; każdy błąd oznacza `Unavailable`. Usunięto wariant `NotInstalled` oraz martwą implementację zastępczej polityki wieku shadow z jej dwoma testami. Porównywanie hasła z shadow pozostaje dla capture-helpera wywoływanego wewnątrz PAM, bez nadawania mu roli autoryzacji pulpitu. To celowa zmiana kompatybilności: host bez działającego PAM nie pozwoli się zalogować.

Testy loadera kompilują tymczasową bibliotekę i uruchamiają osobny proces dla każdego wariantu: brak symbolu, błąd `pam_start`, odmowa auth, odmowa account, uszkodzone oba pliki biblioteki. Nie podmieniano systemowego PAM. Test funkcji `login_from_pam`, której używa produkcyjne `decide`, potwierdza odmowę po błędach zamiast testowania osobnej kopii reguły.

Walidacja po naprawach:

- `cargo test -p linrdp --offline --no-default-features`: 305 testów jednostkowych, 2 capture-helpera, 1 direct listener i 3 testy w pakiecie loadera PAM — wszystkie zaliczone. Próby poszczególnych wariantów biblioteki wykonują dodatkowe procesy wewnątrz jednego testu.
- `cargo test -p ironrdp-server --offline --lib`: 16 zaliczonych. **Łącznie 327 testów Cargo.**
- `cargo clippy -p linrdp --offline --no-default-features --all-targets`: ukończone bez błędów; zgłasza ostrzeżenia, więc nie jest to wynik „bez ostrzeżeń”.
- `git diff --check`: bez błędów.

Nie wykonano pełnych loginów RDP/PAM/logind ani testów rzeczywistego schowka między dwoma klientami. Naprawy zamykają opisane scenariusze w aplikacji, nie stanowią kolejnego niezależnego audytu całego rozwiązania. Skrypty `round3/` pozostają historycznymi dowodami stanu sprzed napraw; aktualne regresje są w `linrdp/tests/direct_listener.rs`, `linrdp/tests/pam_loader.rs` oraz testach modułów `clipboard` i `auth`.
