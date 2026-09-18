# Audyt kodu LinRDP — 18 września 2026

Badany commit: `5f6fb9cdeec2819dc2c7b2c8fbcfdde372be99c6`. Drzewo robocze przed audytem było czyste. Raport dotyczy stanu rozwiązania, a nie regresji konkretnego PR. Zgodnie z prośbą zakres skilla `review-agent` rozszerzono na istniejące defekty i zapis raportu; kod produkcyjny pozostał niezmieniony. Nie znaleziono obowiązujących plików AGENTS.md w sprawdzonych katalogach nadrzędnych ani repozytorium.

## Ustalenia — od najpoważniejszych

Priorytet P1 oznacza pilną naprawę, P2 — defekt do zaplanowanej naprawy. Nie przypisuję P0 ani liczbowego CVSS bez pełnej walidacji środowiska i sposobu wdrożenia. „Potwierdzone statycznie” oznacza wykazaną ścieżkę w kodzie, nie wykonany atak na działający serwer.

### F01 [P1] Zapisuj Xauthority bez uprawnień roota i bez podążania za symlinkami — `linrdp/src/session/xauth.rs:99`

`write_cookie` działa w keeperze jako root, przed uruchomieniem procesów użytkownika. Katalog `/run/user/<uid>` należy do użytkownika, który może przygotować `linrdp/Xauthority` jako symlink. `OpenOptions` z `truncate(true)` podąża za linkiem, a następnie `chown_to` podąża za nim ponownie. Rozpoczęcie nowej sesji może więc nadpisać plik chroniony uprawnieniami roota oraz oddać jego własność użytkownikowi. Podmiana katalogu nadrzędnego dodatkowo obchodzi zabezpieczenie ograniczone do samego pliku. To ścieżka lokalnej eskalacji uprawnień dla użytkownika mogącego uruchomić sesję.

**Dowód:** test komponentowy wywołał produkcyjne `write_cookie` na symlinku do pliku kontrolnego i potwierdził jego nadpisanie. Nie nadpisywano plików systemowych ani nie wykonywano eskalacji między UID. Wywołanie uprzywilejowane: `session/keeper_main.rs:75`.

**Naprawa i kryterium odbioru:** operacje w katalogu użytkownika wykonuje proces z jego UID; ewentualna obsługa uprzywilejowana używa deskryptorów katalogów, kontroli właściciela i rozwiązywania ścieżek bez symlinków w całym łańcuchu. Testy muszą obejmować link w pliku, link w katalogu i podmianę między otwarciem a zmianą właściciela. Samo `O_NOFOLLOW` na końcowym pliku nie rozwiązuje wszystkich wariantów.

**Naprawiono 18 września 2026** (`e2ac21d`). `write_cookie` rozwidla proces, wywołuje `privilege::drop_to(owner)` i dopiero wtedy tworzy katalog i plik; keeper zachowuje swoje uprawnienia, a błąd dziecka wraca potokiem, bo sesja bez ciasteczka to pulpit, do którego nikt się nie połączy. Zniknął `chown` — nie ma czego przejąć: cokolwiek ścieżka rozwiąże, użytkownik i tak mógłby to zapisać sam. To odpowiada na uwagę o samym `O_NOFOLLOW`: kontrolą nie jest już sprawdzenie ścieżki, tylko sprawdzenie uprawnień przez jądro, więc link w katalogu nadrzędnym i podmiana w trakcie przestają cokolwiek dawać. `O_NOFOLLOW` i `O_EXCL` po unlinku zostają na pliku końcowym, żeby zastany link był błędem, a nie przekierowaniem, nawet wewnątrz plików samego użytkownika.

Test: `a_symlink_at_the_cookie_path_is_not_followed` (`linrdp/src/session/xauth.rs`) sadza symlink na ścieżce ciasteczka i sprawdza, że plik docelowy jest nietknięty, a to, co powstało, jest zwykłym plikiem, nie linkiem.

### F02 [P1] Powiąż wynik tworzenia sesji z użytkownikiem i konkretnym keeperem — `linrdp/src/session/mod.rs:118`

`create` przydziela numer ekranu tylko na czas sondy, po czym zwalnia blokadę przed uruchomieniem keepera. Dwa procesy mogą wybrać ten sam numer. Keeper przegranego nie uzyska blokady, ale `wait_for_record` oczekuje wyłącznie rekordu dla numeru, bez sprawdzenia użytkownika lub identyfikatora żądania. `spawn_keeper` obserwuje zakończenie procesu odłączającego, nie gotowość właściwego keepera. Gdy zwycięzca opublikuje rekord, oba workery mogą go przyjąć. Router wiąże ekran z `rec.user`, nie porównując go z uwierzytelnionym kontem (`session/router.rs:183`). Skutkiem może być dostęp do pulpitu innego użytkownika przy równoczesnym tworzeniu sesji.

**Dowód:** deterministyczny test produkcyjnego alokatora wykazał identyczny numer dwóch sond i odmowę drugiej rezerwacji. Produkcyjna funkcja `wait_for_record` przyjęła następnie rekord zwycięzcy „bob” dla przegranego żądania. Testuje to wadliwy mechanizm; nie przeprowadzono pełnego równoległego logowania RDP. Odbiór rekordu: `session/keeper_main.rs:259`.

**Naprawa i kryterium odbioru:** przekazuj utrzymywaną rezerwację do keepera lub atomowo przydzielaj ją w keeperze z odpowiedzią przez prywatny kanał IPC. Odpowiedź musi zawierać zweryfikowane UID i identyfikator żądania; przed `gate::bind` ponownie sprawdź zgodność. Dodaj test równoczesnego tworzenia sesji różnych użytkowników i osobno dwóch połączeń tego samego użytkownika.

**Naprawiono 18 września 2026** (`e2ac21d`). Wybrano pierwszy z dwóch wariantów: worker **utrzymuje** rezerwację i przekazuje ją keeperowi na dziedziczonym deskryptorze (`DisplayLease::into_handoff_fd` → `--keeper-lock-fd 4` → `DisplayLease::adopt`). `flock` należy do opisu otwartego pliku, a nie do procesu, więc ten sam zamek żyje nieprzerwanie od chwili wyboru numeru do zamknięcia ostatniej kopii deskryptora — okna, przez które przechodziły dwa logowania, po prostu nie ma. Keeper weryfikuje przy adopcji, że deskryptor faktycznie trzyma zamek, a nie przyjmuje numeru na słowo.

Zgodności pilnują dwa miejsca zamiast jednego: `wait_for_record` dostało argument `user` i odmawia rekordu należącego do kogoś innego, a `bind_to_desktop` — nowa, jedyna droga od zweryfikowanego konta do pulpitu — sprawdza `rec.user == user` przed `gate::bind`.

Testy: `a_handed_over_claim_is_still_held_by_the_new_owner` i `adopting_a_descriptor_that_holds_no_lock_is_refused` (`display_alloc.rs`), `a_record_for_another_account_is_refused` (`keeper_main.rs`). Testów dwóch *równocześnie startujących* sesji nie dopisano — scenariusz jest zamknięty konstrukcyjnie (numer nie bywa wolny), a nie warunkiem, który dałoby się sprawdzić deterministycznie bez sterowania szeregowaniem.

### F03 [P1] Czytaj pliki schowka jako właściciel sesji — `linrdp/src/clipboard.rs:1094`

Worker nadal działa jako root; zrzucanie uprawnień dotyczy dzieci keepera. Poller schowka akceptuje wskazane przez sesję ścieżki `file://`, sprawdza `metadata` jako root i wpisuje je do `outgoing_files` (`clipboard.rs:688`). `read_file_range` otwiera wskazany plik również jako root. Użytkownik pulpitu może ustawić lokalną selekcję na ścieżkę pliku, do którego sam nie ma dostępu, i pobrać jego zawartość klientem RDP. Nie trzeba uzyskać praw odczytu w sesji — wystarczy umieścić URI. To narusza granicę dostępu do plików i może ujawnić m.in. systemowe dane uwierzytelniające.

**Potwierdzenie:** prześledzono URI → deskryptor → mapa plików → `on_file_contents_request` → `File::open`; brak zmiany UID w workerze. Nie pobierano rzeczywistych sekretów.

**Naprawa i kryterium odbioru:** osobny proces obsługujący pliki z UID i grupami użytkownika, przekazywanie otwartych deskryptorów zamiast ponownego otwierania ścieżek jako root. Test: konto A wskazuje plik roota oraz plik konta B; oba żądania mają zakończyć się odmową. Sprawdzenie `access()` przed uprzywilejowanym `open()` nie usuwa wyścigu.

**Naprawiono 18 września 2026** (`095be41`, uzupełnione w `bee33ad`). Dokładnie tak, jak opisuje kryterium: nowy moduł `linrdp/src/session/fileagent.rs` startuje jeden proces pomocniczy na sesję, z UID i grupami użytkownika (`initgroups` → `setgid` → `setuid`, przez istniejące `privilege::drop_to`). Poller woła `agent.stat(path)`, a `on_file_contents_request` — `agent.open_read(path)`; worker nie otwiera już żadnej ścieżki sam. Wraca **otwarty deskryptor**, przekazany przez `SCM_RIGHTS`, więc sprawdzenie uprawnień nastąpiło przy `open`, poświadczeniami użytkownika, na ścieżce, którą faktycznie rozwiązało jądro. To jest odpowiedź na uwagę o `access()`: nie ma drugiego rozwiązywania ścieżki, więc nie ma między czym a czym się wyścigać.

Pomocnik jest `exec`-em tego samego binarnika (`--file-agent`), nie zwykłym `fork`-iem: w chwili gotowości kanału schowka worker ma już wielowątkowy runtime, a dziecko takiego procesu dziedziczy zamki trzymane przez wątki, których w nim nie ma. Gdy pomocnika nie ma — ekran logowania, albo nieudany start — transfer plików jest wyłączony i mówi o tym w logu; tekst i obrazy działają dalej. Powrót do wykonywania tej pracy w workerze byłby właśnie tym błędem, więc go nie ma.

Tryb console binduje sesję, ale połączenie i tak jest uwierzytelnione jako konkretne konto — `gate::set_console_user` zapisuje je, żeby i tam operacje plikowe szły poświadczeniami logowania.

Test: `a_descriptor_crosses_the_socket_and_still_points_at_the_right_file` (`fileagent.rs`) przechodzi cały protokół — utworzenie, zapis przez deskryptor, `stat`, odczyt z powrotem. Testu „konto A wskazuje plik roota i plik konta B" nie dopisano: wymaga dwóch rzeczywistych kont i roota, czego zestaw jednostkowy nie ma. Odmowa wynika tam z `open` wykonanego przez proces z UID konta A, więc egzekwuje ją jądro, nie nasz kod.

### F04 [P1] Izoluj katalogi plików przychodzących i odrzucaj symlinki — `linrdp/src/clipboard.rs:1041`

Każdy worker rozpoczyna `PASTE_SEQ` od zera i tworzy ten sam `/tmp/linrdp-paste-0`. Katalogi nie mają identyfikatora sesji ani jawnie prywatnych uprawnień. Dwie sesje z identyczną nazwą pliku trafiają w ten sam plik; `File::create` go obcina (`clipboard.rs:191`, `201`, `973`). Przy typowym umask 022 pliki są również czytelne dla innych lokalnych kont. Lokalny użytkownik może wcześniej przygotować katalog i symlink do celu; tekstowa kontrola `safe_join` nie zapobiega podążaniu za linkami podczas zapisu jako root. Wariant z podstawionym celem może prowadzić do zapisu treści dostarczonej przez klienta w pliku uprzywilejowanym, zależnie od ochrony symlinków systemu. Kolizja między workerami nie wymaga symlinków.

**Potwierdzenie:** statyczne, bez modyfikowania systemowych celów. Nie zakładano, że sysctl dotyczące symlinków zawsze pozwalają na każdy wariant ataku.

**Naprawa i kryterium odbioru:** losowy prywatny katalog na sesję, UID użytkownika, tworzenie wyłączne i operacje względem bezpiecznie otwartego katalogu. Sprawdź równoczesne transfery identycznych nazw, niedostępność danych dla innego UID oraz linki w każdym komponencie ścieżki.

**Naprawiono 18 września 2026** (`095be41`). Wszystkie cztery elementy kryterium: katalog tworzy pomocnik z F03, więc powstaje z UID użytkownika; nazwa to `linrdp-paste-<konto>-<8 losowych bajtów z /dev/urandom>`; tworzenie jest wyłączne (`mkdir`, nie `create_dir_all`), a tryb 0700 ustawiany przy tworzeniu przez `DirBuilder::mode`, nie zostawiony `umask`-owi. `PASTE_SEQ` i numerowanie od zera zniknęły, więc dwie sesje nie mają jak trafić w ten sam katalog — kolizja bez symlinków, na którą zwraca uwagę raport, przestaje być możliwa, bo nazwy są rozłączne, a nie dlatego, że coś je rozstrzyga.

`safe_join` zmieniło się w `safe_relative`: buduje ścieżkę **względną**, a nie bezwzględną do otwarcia jako root. Kontrolę tekstową zostawiono jako pierwsze sito (nazwa z separatorem to zepsuty deskryptor), ale ochroną jest teraz przejście pomocnika po komponentach — `openat` z `O_NOFOLLOW | O_DIRECTORY` na każdym poziomie, `unlinkat` + `openat` z `O_CREAT | O_EXCL | O_NOFOLLOW` na pliku. Link w dowolnym komponencie jest błędem, a każdy krok wiąże się z katalogiem, który faktycznie otworzył, a nie ze ścieżką do ponownego rozwiązania. Sprzątanie starych katalogów też przeniosło się do pomocnika i dotyka wyłącznie katalogów należących do tego UID.

Testy: `creating_a_file_below_the_paste_directory_refuses_a_symlinked_parent`, `making_directories_below_the_paste_directory_stays_inside_it`, `paste_directory_names_are_unpredictable_and_distinct`, `a_relative_path_may_only_be_plain_names` (`fileagent.rs`), `a_paste_without_a_file_helper_is_refused` (`clipboard.rs`). Tryb 0700 sprawdzany jest w `a_descriptor_crosses_the_socket_and_still_points_at_the_right_file`. Niedostępności danych dla innego UID nie testowano — jak wyżej, wymaga dwóch kont.

### F05 [P1] Sprawdzaj aktualne uprawnienia konta przy każdym logowaniu NLA — `linrdp/src/main.rs:581`

Resolver NLA odczytuje zapisane hasło SAM i rejestruje tożsamość, bez aktualnej kontroli systemowego konta. Mimo komentarza w `main.rs`, `ShadowValidator` nie weryfikuje potem tej ścieżki: acceptor zapisuje `result.credentials` tylko poza HYBRID/HYBRID_EX (`crates/ironrdp-acceptor/src/connection.rs:930`), a serwer pomija validator przy braku credentials (`crates/ironrdp-server/src/server.rs:3693`). Dla istniejącej sesji `attach_or_create` zwraca rekord bez PAM (`session/mod.rs:201`). Zablokowanie konta lub zmiana hasła poza mechanizmem aktualizującym SAM może zatem pozostawić możliwość ponownego dostępu starym hasłem. Otwarcie nowej sesji przez PAM nie naprawia reconnect do żywej sesji. Tryb console również nie przechodzi przez nową sesję PAM.

**Potwierdzenie:** pełna statyczna ścieżka NLA → resolver → brak validatora → attach istniejącej sesji. Nie zmieniano kont hosta.

**Naprawa i kryterium odbioru:** po zakończeniu uwierzytelniania protokołu wykonuj obowiązkową weryfikację bieżącej polityki konta i wymaganych poświadczeń; błąd musi zamykać dostęp przed podpięciem kanałów. Testy obejmują zablokowanie konta, zmianę hasła i wygaśnięcie konta po odłączeniu klienta, zarówno przy żywej sesji, jak i w console.

**Naprawiono 18 września 2026** (`e2ac21d`, tryb console w `bee33ad`). Powstała jedna droga od zweryfikowanego konta do pulpitu — `router::bind_to_desktop` — i jej pierwszą czynnością jest `auth::authorize_for_desktop(user, password)`, czyli pełna decyzja logowania wykonana **po** zakończeniu uwierzytelniania protokołu, poświadczeniami, które klient rzeczywiście przedstawił. Idą przez nią wszystkie ścieżki: NLA, Client Info PDU, formularz logowania i podłączenie do żywej sesji. Ponieważ wołanie jest przed `attach_or_create` i przed `gate::bind`, odmowa zamyka dostęp, zanim cokolwiek zostanie podpięte — worker kończy się z przyczyną w logu.

Tryb console przechodzi tę samą kontrolę. Wymagało to osobnej poprawki: router był instalowany tylko przy `multi_session`, czyli `serve_fd.is_some() && !console_mode`, więc gałąź console była nieosiągalna. Teraz router jest instalowany dla każdego workera, a `multi_session` bramkuje już tylko uzbrojenie gate'u i katalog stanu, których console faktycznie nie potrzebuje. Połączenie console bez zapisanej tożsamości jest odrzucane, zamiast pokazywać współdzielony pulpit nierozpoznanemu klientowi.

Testów „zablokowanie / wygaśnięcie / zmiana hasła przy żywej sesji i w console" nie dopisano: wymagają prawdziwego stosu PAM i modyfikowania kont hosta, czego zestaw jednostkowy nie robi. Pokryte jest to, co da się pokryć bez tego — że nierozstrzygnięta decyzja jest odmową (`an_undecidable_login_is_refused_rather_than_guessed`) i że pola wygaśnięcia w `/etc/shadow` odmawiają mimo poprawnego hasła (`shadow_ageing_fields_can_refuse_an_account_with_the_right_password`), oba w `auth.rs`.

### F06 [P1] Egzekwuj PAM również po poprawnej weryfikacji hasha — `linrdp/src/auth.rs:160`

Poprawny hash z `/etc/shadow` daje bezpośrednie `Accept`; odczyt shadow ignoruje pola wygaśnięcia i nie uruchamia `pam_acct_mgmt`. `verify_system_password`, używany przez greeter, ma ten sam skrót. Przy podłączeniu do istniejącej sesji i w trybie console brak późniejszego PAM. Użytkownik z poprawnym hasłem, ale odmową wynikającą np. z wygaśnięcia konta lub reguł dostępu PAM, może nadal uzyskać pulpit. Niepoprawne próby dla obsługiwanych hashy również omijają moduły PAM zliczające błędy. W greeterze kolejne próby są przyjmowane bez własnego limitu (`greeter.rs:291`). Nowa sesja keepera wykonuje PAM, co ogranicza zakres problemu, lecz nie usuwa go.

**Naprawa i kryterium odbioru:** jeden wspólny punkt polityki logowania oparty na właściwym serwisie PAM, dla system, greeter, NLA i reconnect. Testy rzeczywistego stosu PAM muszą sprawdzać odmowę mimo poprawnego hasła i skuteczność ograniczania błędnych prób. To odrębny problem od nieaktualnego SAM w F05.

**Naprawiono 18 września 2026** (`e2ac21d`). Wspólnym punktem polityki jest `auth::decide`, i odwrócono w nim kolejność: **najpierw PAM**, `/etc/shadow` dopiero wtedy, gdy libpam nie da się załadować. To jest sedno naprawy — weryfikowanie hasha samodzielnie i kończenie na tym omijało `pam_acct_mgmt` w całości, a nieudane próby nie docierały do tego, co je liczy. Serwis wybiera `pam::login_service()`: `linrdp`, gdy `/etc/pam.d/linrdp` istnieje (ten sam stos, który otwiera sesje, więc uwierzytelnienie i sesja podlegają tym samym regułom i tym samym licznikom `pam_faillock`), inaczej `login`. Wybór po obecności pliku, a nie po kodzie błędu, żeby „stos odmówił" dało się odróżnić od „stosu nie było".

Ścieżka zapasowa `/etc/shadow` nie jest już bez polityki: `shadow_account_policy` czyta pola starzenia i wygaśnięcia (`lastchg`, `max`, `inactive`, `expire`) i odmawia kontu wygasłemu, kontu z wymuszoną zmianą hasła i hasłu po terminie. Konto spoza `/etc/shadow` bez PAM nie jest przepuszczane — nie ma na czym oprzeć zgody. `Login::Unavailable` (nic nie potrafiło rozstrzygnąć) jest odmową, nie domysłem.

Greeter dostał własne ograniczanie prób (`AttemptThrottle`): opóźnienie przed każdą próbą, rosnące po każdej nieudanej, z pułapem — bo na ścieżce shadow nic innego ich nie liczy, a formularz przyjmował je z szybkością zdarzeń klawiatury. Przechwytywanie poświadczeń (`--capture-credential`) celowo **nie** przechodzi przez `decide`, tylko przez `password_matches_shadow`: działa wewnątrz stosu `auth` PAM-a (`pam_exec`), a wejście tam ponownie w PAM dla konta, które PAM właśnie uwierzytelnia, liczyłoby próbę dwa razy.

Testy: `each_shadow_hash_scheme_is_verified_with_its_own_algorithm`, `shadow_ageing_fields_can_refuse_an_account_with_the_right_password`, `an_account_outside_shadow_is_not_approved_without_pam`, `a_login_without_a_user_name_is_refused_before_any_backend` (`auth.rs`), `repeated_failures_cost_progressively_more`, `a_successful_login_clears_the_penalty` (`greeter.rs`). Testów na rzeczywistym stosie PAM nie ma — zestaw jednostkowy nie ma stosu, do którego mógłby się odwołać.

**Uwaga o zmianie zachowania:** PAM jest teraz pierwszy zawsze, gdy libpam się ładuje. Źle skonfigurowany `/etc/pam.d/linrdp` stanie się odmową tam, gdzie wcześniej był omijany przez poprawny hash. W logu pojawia się wtedy `PAM (linrdp) refused`.

### F07 [P1] Ogranicz liczbę workerów i czas negocjacji pierwszego połączenia — `linrdp/src/supervisor.rs:215`

Każdy zaakceptowany TCP powoduje `fork` i uruchomienie kolejnego workera. Supervisor nie utrzymuje limitu aktywnych procesów ani limitu źródła. Ścieżka `run_connection_inner` wywołuje negocjację bez timeoutu (`crates/ironrdp-server/src/server.rs:2267`); ta oczekuje na początkowy PDU oraz TLS. Timeout kandydata do przejęcia połączenia i timeout późniejszego finalize nie obejmują tego oczekiwania. Klient bez uwierzytelnienia może utrzymywać wiele cichych połączeń i zużywać procesy, pamięć i deskryptory aż do limitów hosta/usługi.

**Potwierdzenie:** statyczna analiza ścieżki używanej przez `main.rs:874`; nie wykonywano obciążenia ani DoS.

**Naprawa i kryterium odbioru:** globalny limit workerów z rejestrem PID, deadline całej fazy przed uwierzytelnieniem i budżet kosztownych prób. Test lokalny musi wykazać usunięcie cichych klientów po deadline oraz obsłużenie legalnego klienta po osiągnięciu limitu i zwolnieniu zasobów.

**Naprawiono 18 września 2026** (`49521d7`). Wszystkie trzy elementy kryterium:

- **Rejestr PID i limit globalny.** `supervisor::Workers` trzyma mapę pid → adres. Wymagało to porzucenia `SIGCHLD = SIG_IGN`: automatyczne sprzątanie oznaczało, że dziecko znikało, a supervisor nigdy się o tym nie dowiadywał, więc rejestr mógłby tylko rosnąć i limit zamykałby usługę po `max_workers` połączeniach *w sumie*, a nie *naraz*. Teraz `waitpid(-1, WNOHANG)` w pętli, plus timeout 1 s w `poll`, żeby na cichym porcie też wracać do sprzątania. Odmowa zamyka gniazdo, zamiast rozwidlać worker, który miałby o niej powiedzieć — to wydałoby dokładnie ten zasób, którego się broni.
- **Budżet na źródło.** `max_per_client` liczone po adresie, ponad wszystkimi listenerami, żeby jedno źródło nie zajęło całego budżetu hosta ani nie zamknęło usługi wszystkim.
- **Deadline całej fazy.** `RdpServer::set_handshake_timeout` obejmuje `negotiate_and_authenticate` w całości — pierwszy PDU, TLS i CredSSP — bo żadne oczekiwanie w środku nie miało własnego terminu, a timeouty kandydata i finalize zaczynają się dopiero po nim.

Limity są konfigurowalne: nowy blok `limits` (`max_workers: 128`, `max_per_client: 8`, `handshake_seconds: 30`), nieprzesłanialny per-listener, bo budżet, który jeden port mógłby sobie podnieść, nie byłby budżetem.

Testy: `the_host_stops_forking_once_its_budget_is_full`, `one_client_cannot_take_more_than_its_share`, `a_finished_worker_gives_its_share_back` (`supervisor.rs`) — ostatni pokrywa właśnie „obsłużenie legalnego klienta po zwolnieniu zasobów". Testu usuwania cichych klientów po deadline nie dopisano: wymaga rzeczywistego połączenia i upływu czasu, czego zestaw jednostkowy nie robi. Nie wykonywano też żadnego obciążenia ani DoS.

### F08 [P2] Ogranicz rozmiar odpowiedzi RANGE przed alokacją — `linrdp/src/clipboard.rs:1100`

`requested_size` pochodzące z PDU jest bezpośrednio użyte do alokacji `Vec`. Nie ma limitu fragmentu po stronie wysyłania. Nawet kontrola końca zakresu względem rozmiaru pliku nie wystarczy: użytkownik może udostępnić duży plik, a klient zażądać jednego wielogigabajtowego fragmentu. To pozwala zająć pamięć workera/hosta i przerwać sesję. Limity `MAX_FILE_SIZE` i `MAX_TOTAL_SIZE` dotyczą pobierania plików od klienta, nie tej funkcji.

**Naprawa i kryterium odbioru:** egzekwuj mały maksymalny fragment przed alokacją oraz limit sumarycznych buforów. Test żądania np. `u32::MAX` ma kończyć się odmową bez dużej alokacji. Nie wykonywano takiej alokacji podczas audytu.

**Naprawiono 18 września 2026** (`49521d7`). `range_response_len` liczy długość **przed** jakąkolwiek alokacją, jako minimum z trzech rzeczy: pułapu fragmentu (`MAX_RANGE_RESPONSE`, równego `FILE_CHUNK_SIZE` = 512 KiB, czyli temu, o co prosimy sami), tego, co zostało z pliku po `position`, i tego, o co poproszono. Pozycja za końcem pliku daje zero, na które odpowiadamy pustą odpowiedzią zamiast alokować cokolwiek. Klient, który chce więcej, pyta od następnego offsetu — tak protokół i tak ma być prowadzony.

Testy: `a_range_request_cannot_ask_for_more_than_one_chunk` (żądanie `u32::MAX` na pliku 8 GiB daje dokładnie pułap fragmentu) i `a_range_past_the_end_of_the_file_yields_nothing` (`clipboard.rs`). Duża alokacja nie jest wykonywana ani w testach, ani w kodzie.

### F09 [P2] Zachowaj informację o ekranie po zalogowaniu przez formularz — `linrdp/src/session/router.rs:131`

Ścieżka `show_greeter` wiąże sesję w osobnym wątku, ale nie ustawia `bound_display`. Tylko `bind_as` ustawia to pole. `on_disconnected` zleca zapis blokady wyłącznie dla `Some(bound)`, więc po zalogowaniu formularzem nie zaznaczy sesji jako zablokowanej. Ponadto `session::signal_logind_lock` uruchamia `loginctl lock-session` bez identyfikatora sesji, a worker nie jest keeperem otwierającym PAM. Ogólny kontroler używa sesji D-Bus `auto`, co również nie wskazuje jawnie docelowej sesji. Nie należy traktować tych wywołań jako dowodu zablokowania właściwego pulpitu.

**Naprawa i kryterium odbioru:** współdzielony stan związanej sesji i jawny identyfikator logind, ewentualnie komenda do keepera. Test: logowanie formularzem → rozłączenie → zapis `locked=true` i sygnał do właściwej sesji logind. Ustalenie nie oznacza samo w sobie anonimowego obejścia logowania RDP.

**Naprawiono 18 września 2026** (`e2ac21d`). Oba elementy kryterium:

- **Współdzielony stan.** `bound_display` to `Arc<Mutex<Option<BoundSession>>>` zamiast `Cell`, a obie drogi logowania zapisują go, bo obie wołają teraz to samo `bind_to_desktop`. Dwie kopie tej logiki były właśnie powodem, dla którego formularz pomijał blokadę — więc nie ma już dwóch kopii.
- **Jawny identyfikator logind.** Keeper czyta `XDG_SESSION_ID` ze środowiska PAM i zapisuje je w rekordzie sesji (`SessionRecord::logind_id`); jest jedynym procesem, który je widzi, i tylko dopóki jego sesja PAM jest otwarta, więc rekord jest jedynym miejscem, gdzie ta wartość może zamieszkać. `signal_logind_lock` wywołuje `loginctl lock-session <id>`. Bez identyfikatora nie woła niczego i mówi o tym w logu — wołanie bez argumentu działało na sesji procesu wołającego, a worker żadnej nie ma, więc sygnał albo zawodził, albo trafiał gdzie indziej; milczące „udało się" było gorsze od przyznania, że nie ma czego powiadomić.

Testu end-to-end „formularz → rozłączenie → `locked=true` i sygnał" nie dopisano: wymaga X, logind i klienta RDP. Round-trip pola w rekordzie pokrywa `records_round_trip_every_field` (`registry.rs`).

### F10 [P2] Serializuj aktualizacje magazynu SAM — `linrdp/src/sam.rs:321`

`set_password` wykonuje niezablokowane read–modify–write całej mapy. Dwa równoczesne wywołania capture mogą odczytać ten sam stan, dodać/zmienić inne konta, a ostatni rename usunie zmianę poprzednika. Atomowość pliku chroni przed częściową treścią, ale nie przed utratą aktualizacji. Może to cofnąć synchronizację hasła albo zgubić nowo zapisane konto; w połączeniu z F05 pozostawia nieaktualne poświadczenia NLA.

**Naprawa i kryterium odbioru:** blokada wspólnego, stałego pliku obejmująca odczyt, zmianę i zapis; ta sama synchronizacja dla migracji. Test dwóch procesów z barierą po odczycie musi zachować obie aktualizacje.

**Naprawiono 18 września 2026** (`49521d7`). Dokładnie tak: `sam::StoreLock` bierze `flock(LOCK_EX)` na `/var/lib/linrdp/sam.lock` i trzyma go przez cały odczyt, zmianę i zapis. Plik jest osobny i stały, bo sam magazyn jest podmieniany przez `rename` — zamek na starym i-węźle nic by nie znaczył dla następnego piszącego, który otwiera nowy. Blokada jest blokująca, nie `LOCK_NB`: piszący to pomocniki przechwytywania poświadczeń, każdy raz na logowanie i na czas przepisania małego pliku, a rezygnacja oznaczałaby ciche porzucenie hasła, które logowanie właśnie potwierdziło.

`migrate_plaintext` bierze ten sam zamek i po jego uzyskaniu czyta plik **ponownie**, żeby nie nadpisać migracji, którą w międzyczasie wykonał ktoś inny. Tani odczyt przed zamkiem zostaje, bo typowy przypadek to magazyn już zapieczętowany albo nieistniejący.

Test: `the_store_lock_lets_only_one_writer_in_at_a_time` (`sam.rs`) — cztery wątki po dwadzieścia przebiegów, z licznikiem wykrywającym jakiekolwiek nałożenie się sekcji krytycznych. Nie jest to test dwóch procesów z barierą: ścieżka magazynu to `/var/lib/linrdp`, do którego test nie ma prawa pisać, więc ćwiczony jest sam mechanizm zamka, pod którym przepisanie teraz działa.

### F11 [P2] Użyj weryfikatora SHA-256 dla hashy `$5$` — `linrdp/src/auth.rs:274`

Gałąź deklaruje obsługę `$5$` i `$6$`, ale dla obu wywołuje `sha_crypt::sha512_check`. Biblioteka udostępnia odrębne `sha256_check`; poprawne hasło dla `$5$` zostanie odrzucone. Ponieważ jest to rozstrzygające `Ok(false)`, PAM nie zostanie użyty jako fallback. Dotyczy logowania system/greeter i capture na systemach z SHA-256-crypt.

**Naprawa i kryterium odbioru:** rozdziel funkcje według identyfikatora schematu albo powierz weryfikację PAM. Dodaj znane wektory poprawnego i błędnego hasła dla każdego obsługiwanego schematu. Potwierdzenie statyczne obejmowało implementację lokalnej zależności `sha-crypt 0.5`.

**Naprawiono 18 września 2026** (`e2ac21d`). Funkcje rozdzielone po identyfikatorze schematu: `"5"` → `sha_crypt::sha256_check`, `"6"` → `sha_crypt::sha512_check`, `"1"` → `verify_md5`, `"y"` → yescrypt. Wspólna gałąź `"1" | "5" | "6"` zniknęła. Niezależnie od tego, dzięki F06 ta ścieżka jest teraz zapasowa: przy dostępnym libpam weryfikuje PAM, więc nawet schemat, którego ten kod nie implementuje, nie kończy się rozstrzygającym `Ok(false)`.

Test: `each_shadow_hash_scheme_is_verified_with_its_own_algorithm` (`auth.rs`) używa opublikowanych wektorów SHA-crypt (specyfikacja Drepera) dla `$5$` i `$6$`, sprawdza poprawne i błędne hasło dla obu, i osobno potwierdza, że `sha512_check` nie weryfikuje hasha `$5$` — czyli że sam błąd faktycznie był tym, czym raport go nazywa.

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

## Stan planu napraw — 18 września 2026

Dopisane po wykonaniu napraw; notatki pod poszczególnymi ustaleniami opisują każdą z nich osobno.

1. **F01–F04 — zrobione.** Operacje plikowe w katalogach użytkowników i obsługa plików schowka wykonują procesy z uprawnieniami tych użytkowników. Odmowy między UID nie sprawdzono w izolowanym środowisku testowym — egzekwuje je jądro przy `open` wykonanym przez proces z właściwym UID, ale to nie zastępuje przebiegu z dwoma rzeczywistymi kontami.
2. **F05–F06 i F10 — zrobione.** Jedna obowiązkowa kontrola polityki na każdej drodze do pulpitu, `auth::decide`, z PAM jako pierwszym źródłem decyzji. Weryfikacji zablokowania, wygaśnięcia i zmiany hasła przy istniejącej sesji nie przeprowadzono: wymaga rzeczywistego stosu PAM i modyfikowania kont hosta.
3. **F07–F08 — zrobione.** Limity procesów, budżet na źródło, deadline całej fazy przed uwierzytelnieniem i ograniczenie fragmentu RANGE, z testami jednostkowymi. Nie obciążano żadnego środowiska.
4. **F09 i F11 — zrobione.** Regresji dla greeter/reconnect/console ani macierzy rzeczywistych klientów nie uruchomiono. Rozdzielenie keeperów od workerów w zarządzaniu usługą pozostaje **niezrobione** — to osobna zmiana w jednostkach systemd, nie w tym zakresie.
5. **Przegląd po naprawach — niezrobiony.** Niezależna weryfikacja zmian, ponowne testy scenariuszy atakujących, aktualny audyt zależności i fuzzing parserów sieciowych pozostają do wykonania. Bez nich ocena gotowości produkcyjnej z sekcji „Ocena audytora" stoi.

Otwarte zostają też wszystkie pozycje z sekcji „Ryzyka projektowe i ograniczenia funkcjonalne": wyprowadzanie klucza SAM z tożsamości hosta, czas życia haseł w pamięci, niepełna implementacja USB i mikrofonu, klucze testowe w repozytorium oraz zależności i FFI. Nie są to defekty z dowodem, tylko własności rozwiązania, i żadnej z nich nie zmieniano.

Dowody komponentowe z `reproduce.py` **przestały się kompilować** — zgodnie z zapowiedzią z sekcji „Metoda, pokrycie i wiarygodność", że po naprawie przestaną przechodzić. `wait_for_record` wymaga teraz konta, a `SessionRecord` — identyfikatora sesji logind. Skrypt zostawiono tak, jak go napisano; oba scenariusze odtworzono jako testy w drzewie, wymienione pod F01 i F02.

Walidacja po naprawach: `cargo test -p linrdp --offline --no-default-features` — 297 testów jednostkowych i 2 integracyjne, wszystkie zaliczone; `cargo clippy --all-targets` bez błędów. Nie wykonano testów end-to-end z rzeczywistymi klientami RDP, prób między UID na działającej maszynie ani niczego z tego, co powyżej oznaczono jako niezrobione.
