# Audyt kodu LinRDP — 18 września 2026

Badany commit: `5f6fb9cdeec2819dc2c7b2c8fbcfdde372be99c6`. Drzewo robocze przed audytem było czyste. Raport dotyczy stanu rozwiązania, a nie regresji konkretnego PR. Zgodnie z prośbą zakres skilla `review-agent` rozszerzono na istniejące defekty i zapis raportu; kod produkcyjny pozostał niezmieniony. Nie znaleziono obowiązujących plików AGENTS.md w sprawdzonych katalogach nadrzędnych ani repozytorium.

## Ustalenia — od najpoważniejszych

Priorytet P1 oznacza pilną naprawę, P2 — defekt do zaplanowanej naprawy. Nie przypisuję P0 ani liczbowego CVSS bez pełnej walidacji środowiska i sposobu wdrożenia. „Potwierdzone statycznie” oznacza wykazaną ścieżkę w kodzie, nie wykonany atak na działający serwer.

### F01 [P1] Zapisuj Xauthority bez uprawnień roota i bez podążania za symlinkami — `linrdp/src/session/xauth.rs:99`

`write_cookie` działa w keeperze jako root, przed uruchomieniem procesów użytkownika. Katalog `/run/user/<uid>` należy do użytkownika, który może przygotować `linrdp/Xauthority` jako symlink. `OpenOptions` z `truncate(true)` podąża za linkiem, a następnie `chown_to` podąża za nim ponownie. Rozpoczęcie nowej sesji może więc nadpisać plik chroniony uprawnieniami roota oraz oddać jego własność użytkownikowi. Podmiana katalogu nadrzędnego dodatkowo obchodzi zabezpieczenie ograniczone do samego pliku. To ścieżka lokalnej eskalacji uprawnień dla użytkownika mogącego uruchomić sesję.

**Dowód:** test komponentowy wywołał produkcyjne `write_cookie` na symlinku do pliku kontrolnego i potwierdził jego nadpisanie. Nie nadpisywano plików systemowych ani nie wykonywano eskalacji między UID. Wywołanie uprzywilejowane: `session/keeper_main.rs:75`.

**Naprawa i kryterium odbioru:** operacje w katalogu użytkownika wykonuje proces z jego UID; ewentualna obsługa uprzywilejowana używa deskryptorów katalogów, kontroli właściciela i rozwiązywania ścieżek bez symlinków w całym łańcuchu. Testy muszą obejmować link w pliku, link w katalogu i podmianę między otwarciem a zmianą właściciela. Samo `O_NOFOLLOW` na końcowym pliku nie rozwiązuje wszystkich wariantów.

### F02 [P1] Powiąż wynik tworzenia sesji z użytkownikiem i konkretnym keeperem — `linrdp/src/session/mod.rs:118`

`create` przydziela numer ekranu tylko na czas sondy, po czym zwalnia blokadę przed uruchomieniem keepera. Dwa procesy mogą wybrać ten sam numer. Keeper przegranego nie uzyska blokady, ale `wait_for_record` oczekuje wyłącznie rekordu dla numeru, bez sprawdzenia użytkownika lub identyfikatora żądania. `spawn_keeper` obserwuje zakończenie procesu odłączającego, nie gotowość właściwego keepera. Gdy zwycięzca opublikuje rekord, oba workery mogą go przyjąć. Router wiąże ekran z `rec.user`, nie porównując go z uwierzytelnionym kontem (`session/router.rs:183`). Skutkiem może być dostęp do pulpitu innego użytkownika przy równoczesnym tworzeniu sesji.

**Dowód:** deterministyczny test produkcyjnego alokatora wykazał identyczny numer dwóch sond i odmowę drugiej rezerwacji. Produkcyjna funkcja `wait_for_record` przyjęła następnie rekord zwycięzcy „bob” dla przegranego żądania. Testuje to wadliwy mechanizm; nie przeprowadzono pełnego równoległego logowania RDP. Odbiór rekordu: `session/keeper_main.rs:259`.

**Naprawa i kryterium odbioru:** przekazuj utrzymywaną rezerwację do keepera lub atomowo przydzielaj ją w keeperze z odpowiedzią przez prywatny kanał IPC. Odpowiedź musi zawierać zweryfikowane UID i identyfikator żądania; przed `gate::bind` ponownie sprawdź zgodność. Dodaj test równoczesnego tworzenia sesji różnych użytkowników i osobno dwóch połączeń tego samego użytkownika.

### F03 [P1] Czytaj pliki schowka jako właściciel sesji — `linrdp/src/clipboard.rs:1094`

Worker nadal działa jako root; zrzucanie uprawnień dotyczy dzieci keepera. Poller schowka akceptuje wskazane przez sesję ścieżki `file://`, sprawdza `metadata` jako root i wpisuje je do `outgoing_files` (`clipboard.rs:688`). `read_file_range` otwiera wskazany plik również jako root. Użytkownik pulpitu może ustawić lokalną selekcję na ścieżkę pliku, do którego sam nie ma dostępu, i pobrać jego zawartość klientem RDP. Nie trzeba uzyskać praw odczytu w sesji — wystarczy umieścić URI. To narusza granicę dostępu do plików i może ujawnić m.in. systemowe dane uwierzytelniające.

**Potwierdzenie:** prześledzono URI → deskryptor → mapa plików → `on_file_contents_request` → `File::open`; brak zmiany UID w workerze. Nie pobierano rzeczywistych sekretów.

**Naprawa i kryterium odbioru:** osobny proces obsługujący pliki z UID i grupami użytkownika, przekazywanie otwartych deskryptorów zamiast ponownego otwierania ścieżek jako root. Test: konto A wskazuje plik roota oraz plik konta B; oba żądania mają zakończyć się odmową. Sprawdzenie `access()` przed uprzywilejowanym `open()` nie usuwa wyścigu.

### F04 [P1] Izoluj katalogi plików przychodzących i odrzucaj symlinki — `linrdp/src/clipboard.rs:1041`

Każdy worker rozpoczyna `PASTE_SEQ` od zera i tworzy ten sam `/tmp/linrdp-paste-0`. Katalogi nie mają identyfikatora sesji ani jawnie prywatnych uprawnień. Dwie sesje z identyczną nazwą pliku trafiają w ten sam plik; `File::create` go obcina (`clipboard.rs:191`, `201`, `973`). Przy typowym umask 022 pliki są również czytelne dla innych lokalnych kont. Lokalny użytkownik może wcześniej przygotować katalog i symlink do celu; tekstowa kontrola `safe_join` nie zapobiega podążaniu za linkami podczas zapisu jako root. Wariant z podstawionym celem może prowadzić do zapisu treści dostarczonej przez klienta w pliku uprzywilejowanym, zależnie od ochrony symlinków systemu. Kolizja między workerami nie wymaga symlinków.

**Potwierdzenie:** statyczne, bez modyfikowania systemowych celów. Nie zakładano, że sysctl dotyczące symlinków zawsze pozwalają na każdy wariant ataku.

**Naprawa i kryterium odbioru:** losowy prywatny katalog na sesję, UID użytkownika, tworzenie wyłączne i operacje względem bezpiecznie otwartego katalogu. Sprawdź równoczesne transfery identycznych nazw, niedostępność danych dla innego UID oraz linki w każdym komponencie ścieżki.

### F05 [P1] Sprawdzaj aktualne uprawnienia konta przy każdym logowaniu NLA — `linrdp/src/main.rs:581`

Resolver NLA odczytuje zapisane hasło SAM i rejestruje tożsamość, bez aktualnej kontroli systemowego konta. Mimo komentarza w `main.rs`, `ShadowValidator` nie weryfikuje potem tej ścieżki: acceptor zapisuje `result.credentials` tylko poza HYBRID/HYBRID_EX (`crates/ironrdp-acceptor/src/connection.rs:930`), a serwer pomija validator przy braku credentials (`crates/ironrdp-server/src/server.rs:3693`). Dla istniejącej sesji `attach_or_create` zwraca rekord bez PAM (`session/mod.rs:201`). Zablokowanie konta lub zmiana hasła poza mechanizmem aktualizującym SAM może zatem pozostawić możliwość ponownego dostępu starym hasłem. Otwarcie nowej sesji przez PAM nie naprawia reconnect do żywej sesji. Tryb console również nie przechodzi przez nową sesję PAM.

**Potwierdzenie:** pełna statyczna ścieżka NLA → resolver → brak validatora → attach istniejącej sesji. Nie zmieniano kont hosta.

**Naprawa i kryterium odbioru:** po zakończeniu uwierzytelniania protokołu wykonuj obowiązkową weryfikację bieżącej polityki konta i wymaganych poświadczeń; błąd musi zamykać dostęp przed podpięciem kanałów. Testy obejmują zablokowanie konta, zmianę hasła i wygaśnięcie konta po odłączeniu klienta, zarówno przy żywej sesji, jak i w console.

### F06 [P1] Egzekwuj PAM również po poprawnej weryfikacji hasha — `linrdp/src/auth.rs:160`

Poprawny hash z `/etc/shadow` daje bezpośrednie `Accept`; odczyt shadow ignoruje pola wygaśnięcia i nie uruchamia `pam_acct_mgmt`. `verify_system_password`, używany przez greeter, ma ten sam skrót. Przy podłączeniu do istniejącej sesji i w trybie console brak późniejszego PAM. Użytkownik z poprawnym hasłem, ale odmową wynikającą np. z wygaśnięcia konta lub reguł dostępu PAM, może nadal uzyskać pulpit. Niepoprawne próby dla obsługiwanych hashy również omijają moduły PAM zliczające błędy. W greeterze kolejne próby są przyjmowane bez własnego limitu (`greeter.rs:291`). Nowa sesja keepera wykonuje PAM, co ogranicza zakres problemu, lecz nie usuwa go.

**Naprawa i kryterium odbioru:** jeden wspólny punkt polityki logowania oparty na właściwym serwisie PAM, dla system, greeter, NLA i reconnect. Testy rzeczywistego stosu PAM muszą sprawdzać odmowę mimo poprawnego hasła i skuteczność ograniczania błędnych prób. To odrębny problem od nieaktualnego SAM w F05.

### F07 [P1] Ogranicz liczbę workerów i czas negocjacji pierwszego połączenia — `linrdp/src/supervisor.rs:215`

Każdy zaakceptowany TCP powoduje `fork` i uruchomienie kolejnego workera. Supervisor nie utrzymuje limitu aktywnych procesów ani limitu źródła. Ścieżka `run_connection_inner` wywołuje negocjację bez timeoutu (`crates/ironrdp-server/src/server.rs:2267`); ta oczekuje na początkowy PDU oraz TLS. Timeout kandydata do przejęcia połączenia i timeout późniejszego finalize nie obejmują tego oczekiwania. Klient bez uwierzytelnienia może utrzymywać wiele cichych połączeń i zużywać procesy, pamięć i deskryptory aż do limitów hosta/usługi.

**Potwierdzenie:** statyczna analiza ścieżki używanej przez `main.rs:874`; nie wykonywano obciążenia ani DoS.

**Naprawa i kryterium odbioru:** globalny limit workerów z rejestrem PID, deadline całej fazy przed uwierzytelnieniem i budżet kosztownych prób. Test lokalny musi wykazać usunięcie cichych klientów po deadline oraz obsłużenie legalnego klienta po osiągnięciu limitu i zwolnieniu zasobów.

### F08 [P2] Ogranicz rozmiar odpowiedzi RANGE przed alokacją — `linrdp/src/clipboard.rs:1100`

`requested_size` pochodzące z PDU jest bezpośrednio użyte do alokacji `Vec`. Nie ma limitu fragmentu po stronie wysyłania. Nawet kontrola końca zakresu względem rozmiaru pliku nie wystarczy: użytkownik może udostępnić duży plik, a klient zażądać jednego wielogigabajtowego fragmentu. To pozwala zająć pamięć workera/hosta i przerwać sesję. Limity `MAX_FILE_SIZE` i `MAX_TOTAL_SIZE` dotyczą pobierania plików od klienta, nie tej funkcji.

**Naprawa i kryterium odbioru:** egzekwuj mały maksymalny fragment przed alokacją oraz limit sumarycznych buforów. Test żądania np. `u32::MAX` ma kończyć się odmową bez dużej alokacji. Nie wykonywano takiej alokacji podczas audytu.

### F09 [P2] Zachowaj informację o ekranie po zalogowaniu przez formularz — `linrdp/src/session/router.rs:131`

Ścieżka `show_greeter` wiąże sesję w osobnym wątku, ale nie ustawia `bound_display`. Tylko `bind_as` ustawia to pole. `on_disconnected` zleca zapis blokady wyłącznie dla `Some(bound)`, więc po zalogowaniu formularzem nie zaznaczy sesji jako zablokowanej. Ponadto `session::signal_logind_lock` uruchamia `loginctl lock-session` bez identyfikatora sesji, a worker nie jest keeperem otwierającym PAM. Ogólny kontroler używa sesji D-Bus `auto`, co również nie wskazuje jawnie docelowej sesji. Nie należy traktować tych wywołań jako dowodu zablokowania właściwego pulpitu.

**Naprawa i kryterium odbioru:** współdzielony stan związanej sesji i jawny identyfikator logind, ewentualnie komenda do keepera. Test: logowanie formularzem → rozłączenie → zapis `locked=true` i sygnał do właściwej sesji logind. Ustalenie nie oznacza samo w sobie anonimowego obejścia logowania RDP.

### F10 [P2] Serializuj aktualizacje magazynu SAM — `linrdp/src/sam.rs:321`

`set_password` wykonuje niezablokowane read–modify–write całej mapy. Dwa równoczesne wywołania capture mogą odczytać ten sam stan, dodać/zmienić inne konta, a ostatni rename usunie zmianę poprzednika. Atomowość pliku chroni przed częściową treścią, ale nie przed utratą aktualizacji. Może to cofnąć synchronizację hasła albo zgubić nowo zapisane konto; w połączeniu z F05 pozostawia nieaktualne poświadczenia NLA.

**Naprawa i kryterium odbioru:** blokada wspólnego, stałego pliku obejmująca odczyt, zmianę i zapis; ta sama synchronizacja dla migracji. Test dwóch procesów z barierą po odczycie musi zachować obie aktualizacje.

### F11 [P2] Użyj weryfikatora SHA-256 dla hashy `$5$` — `linrdp/src/auth.rs:274`

Gałąź deklaruje obsługę `$5$` i `$6$`, ale dla obu wywołuje `sha_crypt::sha512_check`. Biblioteka udostępnia odrębne `sha256_check`; poprawne hasło dla `$5$` zostanie odrzucone. Ponieważ jest to rozstrzygające `Ok(false)`, PAM nie zostanie użyty jako fallback. Dotyczy logowania system/greeter i capture na systemach z SHA-256-crypt.

**Naprawa i kryterium odbioru:** rozdziel funkcje według identyfikatora schematu albo powierz weryfikację PAM. Dodaj znane wektory poprawnego i błędnego hasła dla każdego obsługiwanego schematu. Potwierdzenie statyczne obejmowało implementację lokalnej zależności `sha-crypt 0.5`.

## Ocena audytora

**Nie rekomenduję obecnego stanu do produkcyjnego środowiska z wzajemnie niezaufanymi użytkownikami ani do bezpośredniego udostępnienia w Internecie.** Najważniejsze powody to naruszenia granic uprawnień w operacjach plikowych, wyścig tożsamości sesji i brak spójnej autoryzacji reconnect. VPN lub firewall ograniczy powierzchnię ataku z sieci, ale nie naprawi problemów dostępnych dla legalnego użytkownika sesji.

Projekt ma wartościowe mechanizmy: osobny proces na połączenie, utrzymywanie życia sesji przez keeper, losowe ciasteczka X11, wymagane `-auth` zamiast `-ac`, gate odmawiający ambient fallback, kontrolowaną kolejność `initgroups` → `setgid` → `setuid`, prywatny zapis generowanego klucza TLS i testy wielu wcześniejszych regresji. Nie wystarcza to jeszcze do izolacji: proces przetwarzający wejście sieciowe i dane schowka zachowuje root, a część granic opiera się na ścieżkach i komentarzach zamiast wymuszanych niezmiennikach.

Ocena utrzymywalności: duże moduły łączą odpowiedzialności — `clipboard.rs` ponad 1500 linii, `gfx_display.rs` ponad 2700, a serwer protokołu kilka tysięcy. Najpilniejsze rozdzielenie powinno wynikać z granic uprawnień: autoryzacja, keeper, operacje plikowe użytkownika oraz worker protokołu. Same zmiany stylistyczne nie rozwiązują wskazanych luk. Komentarze o ponownej walidacji NLA i „race-free” przydziale nie opisują faktycznego zachowania całej ścieżki.

## Ryzyka projektowe i ograniczenia funkcjonalne

- **SAM nie jest chroniony samym sekretem maszyny.** Klucz AES-GCM pochodzi z identyfikatorów hosta, a wariant bez DMI wyłącznie z `/etc/machine-id` (`sam.rs:266`). Gdy oba odczyty zawodzą, kod nadal szyfruje kluczem wyprowadzonym z pustego wejścia. To nie daje poufności hasła wobec kogoś posiadającego kopię magazynu i identyfikatory; pełny backup może obejmować oba. Uprawnienia 0600 pozostają istotną ochroną. Zalecam niezależny losowy sekret poza backupem danych lub magazyn kluczy, odmowę pracy bez materiału kluczowego, procedurę rotacji i ograniczenie czasu przechowywania haseł. Nie jest to dowód zdalnego odczytu SAM samą znajomością machine-id.
- **Hasła pozostają w pamięci.** Klonowanie `String`, mapa całego SAM i przechowywanie danych konwersacji PAM nie gwarantują wyzerowania. Należy ograniczyć liczbę kopii, czas życia oraz ekspozycję przez zrzuty procesu; bez audytu wdrożenia nie stwierdzam, czy coredumpy są faktycznie dostępne.
- **USB i mikrofon mają ograniczoną implementację.** USB rejestruje urządzenia, lecz nie realizuje I/O; mikrofon liczy pakiety, a `MicInputChannel::new` nie wykorzystuje przekazanego sinka. Kod sam opisuje ten stan, dlatego nie klasyfikuję go jako nowej regresji. Deklaracje produktu powinny odróżniać negocjację kanału od funkcjonalnego przekierowania urządzenia.
- **Klucze PEM są w repozytorium.** Znaleziono parę w `linrdp/` i certyfikaty testowe. Aktualny domyślny loader generuje tożsamość w `/etc/linrdp/cert`, więc sama obecność plików nie dowodzi użycia wspólnego klucza w produkcji. Trzeba oznaczyć je jednoznacznie jako testowe i sprawdzić obrazy/pakiety wdrożeniowe.
- **Zależności i FFI wymagają osobnej warstwy kontroli.** Projekt zawiera vendored IronRDP, natywne kodeki i bloki `unsafe`. Nie wykonano aktualnego skanowania baz podatności, pełnego audytu unsafe ani fuzzingu parserów. Brak wpisu CVE w tym raporcie nie oznacza braku znanych podatności. Odtwarzalność ułatwi przypięcie wersji toolchain zamiast ruchomego `stable` oraz dokumentowanie rewizji pochodzenia vendored kodu.

## Metoda, pokrycie i wiarygodność

Był to ręczny audyt skoncentrowany na ryzyku, nie pełny przegląd każdej linii całego workspace. Szczegółowo sprawdzono uwierzytelnianie shadow/PAM/SAM, resolver NLA i wywołania validatora, supervisor, lifecycle sesji, rejestr, przydział ekranów, Xauthority, zrzucanie uprawnień, TLS, schowek i unit systemd. Punktowo sprawdzono gate, greeter, UDP, USB, mikrofon, walidację konfiguracji i odpowiednie części vendored acceptora/serwera. Nie potwierdzono bezpieczeństwa wszystkich parserów PDU, grafiki, kompresji, funkcji Wayland ani całego drzewa zależności.

Model zagrożeń obejmuje nieuwierzytelnionego klienta TCP, złośliwego legalnego klienta RDP, lokalne konto bez roota i współbieżne sesje różnych użytkowników. Uwzględniono domyślny model uruchamiania usługi jako root. Nie przeprowadzono pentestu wdrożenia, ataków na konta hosta ani wyczerpywania zasobów.

Walidacja:

| Kontrola | Wynik i ograniczenia |
|---|---|
| `cargo test -p linrdp --offline --no-default-features` w sandboxie | 265 zaliczonych, 8 nieudanych; blokady TCP i asercje związane z X11 |
| To samo polecenie poza sandboxem | 273 testy jednostkowe i 2 integracyjne zaliczone, kod wyjścia 0 |
| Test komponentowy Xauthority | Potwierdzone nadpisanie pliku kontrolnego przez symlink |
| Test komponentowy rezerwacji/rekordu | Potwierdzona kolizja sond i przyjęcie rekordu innego konta |
| Cały workspace / feature Wayland / fuzzing / sanitizer / skan CVE | Nie wykonano |

Użyto rustc 1.98.1. Zwięzły zapis wyników jest w [test-results.txt](test-results.txt). Reprodukcja dwóch testów komponentowych: `python3 docs/audit/reproduce.py` po zbudowaniu projektu. Skrypt kompiluje produkcyjne moduły przez `#[path]` oraz aktualną funkcję `wait_for_record`; używa wyłącznie plików kontrolnych w katalogu tymczasowym. Asercje potwierdzają obecność błędów, więc po ich naprawie powinny przestać przechodzić. Nie zastępują testów end-to-end. Szablon: [proof-template.rs.txt](proof-template.rs.txt).

Zielone testy nie unieważniają ustaleń: dotychczasowy zestaw nie obejmuje adversarialnych ścieżek między UID, współbieżnego tworzenia sesji i odwołania uprawnień podczas życia pulpitu. Test `pam_session` z mockiem sprawdza kolejność zapisaną we własnym mocku, nie egzekwowanie polityki przez wszystkie produkcyjne ścieżki.

## Plan napraw i warunki dopuszczenia

1. **Przed udostępnieniem niezaufanym użytkownikom:** napraw F01–F04; przenieś operacje schowka i zapisy w katalogach użytkowników do procesów z ich uprawnieniami. Sprawdź odmowę dostępu między UID w izolowanym środowisku testowym.
2. **Przed zatwierdzeniem uwierzytelniania:** napraw F05–F06 i F10; wprowadź jedną obowiązkową kontrolę polityki na każdej drodze do pulpitu. Weryfikuj zablokowanie, wygaśnięcie i zmianę hasła przy istniejącej sesji.
3. **Przed ekspozycją sieciową:** napraw F07–F08; dodaj testy limitów procesów, timeoutów i pamięci bez obciążania środowiska produkcyjnego.
4. **Domknij poprawność:** napraw F09 i F11, uruchom regresje dla greeter/reconnect/console oraz macierz rzeczywistych klientów. Rozdziel procesy keepers od workerów w zarządzaniu usługą tak, aby zachowanie sesji nie utrzymywało niepożądanych połączeń po zatrzymaniu usługi.
5. **Przegląd po naprawach:** niezależnie zweryfikuj konkretne zmiany i ponów testy atakujących scenariuszy. Osobno wykonaj aktualny audyt zależności i fuzzing parserów sieciowych. Dopiero te dowody pozwolą zmienić ocenę gotowości produkcyjnej.

Raport jest oceną badanego commita, nie certyfikacją bezpieczeństwa produktu. Każde ustalenie ma wskazany scenariusz, punkt kodu i kryterium naprawy; ryzyka bez pełnego dowodu zostały oddzielone od potwierdzonych defektów.
