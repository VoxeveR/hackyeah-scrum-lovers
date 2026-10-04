# hackyeah-scrum-lovers · SpireGate

we love scrum we cant code we can vibe

SpireGate to warstwa kontroli (AI Control Layer) stojąca między dowolnym agentem a modelem i narzędziami.
Agent zmienia tylko `base_url` na gateway i dostaje wirtualny klucz; prawdziwe klucze (OpenAI, Jev) zna tylko gateway.

## Start

```bash
uv sync
make test          # 113 testów, bez kluczy i sieci, ~3 s
make demo          # scenariusz KYC bez ataku (skryptowany model, stub Jev)
make demo-attack   # ten sam scenariusz, strona WWW zawiera ukrytą instrukcję dla AI
make demo-loop     # serwis nie odpowiada, agent ponawia w kółko to samo wywołanie
make serve &       # gateway + dashboard; potem otwórz /ui/#/engine (strona Engine)
make load          # 100 prawdziwych żądań symulowanej floty — widać je płynące na stronie Engine (albo przycisk Start)
```

Z prawdziwymi modelami: `cp .env.example .env`, wpisz `OPENAI_API_KEY` (i opcjonalnie `TYPESAFE_API_KEY` dla Jev), potem `make demo-live`.
Bez `TYPESAFE_API_KEY` gateway sam używa stuba System One i pisze to w śladzie.

## Scenariusz 1: agent KYC

Polecenie użytkownika (identyczne w obu wariantach): „Przygotuj podsumowanie KYC klienta ACME-001, sprawdź wiadomości o nim w internecie i wyślij podsumowanie do ania@gs.com.”

Agent ma trzy narzędzia: `crm_get_client` (dane prywatne), `web_fetch` (treść niezaufana) i `send_email` (wysyłka). Gateway przy każdym żądaniu:

1. **rozpoznaje agenta** po wirtualnym kluczu i sprawdza, czy model jest na liście dozwolonych,
2. **etykietuje sesję** z historii rozmowy: wynik z CRM → `client_pii`, wynik z WWW → `untrusted`,
3. **maskuje** IBAN, LEI i PESEL (tylko poprawne sumy kontrolne) przed wysłaniem do zewnętrznego modelu,
4. **sprawdza każdą akcję**, o którą prosi model, zanim agent ją wykona.

| Wariant | Co się dzieje | Kto decyduje |
|---|---|---|
| `benign` | e-mail idzie do ania@gs.com; model widzi tylko `[IBAN#1]`, `[PESEL#1]` | DET-FIN-ID-001 (redakcja) |
| `attack` | strona każe wysłać kartotekę na kyc-review@acme-corp.com → Jev ukrywa stronę przed modelem, a gdyby ją przepuścił, wysyłkę blokuje reguła | S1-JEV-001 (Jev), IFC-TRIFECTA-001 (reguła, piętro bezpieczeństwa) |

Reguła przepływu danych zatrzymuje atak nawet po usunięciu wszystkich detektorów i Jeva (patrz testy).

## Scenariusz 2: Claude Code, Codex i własne aplikacje (hooki, SDK)

Ta sama polityka działa dla agentów, którzy sami wykonują narzędzia:

| Klient | Jak się podpina | Szczegóły |
|---|---|---|
| Claude Code | hooki `PreToolUse` / `PostToolUse` / `UserPromptSubmit` → `hooks/spire_hook.py` | [`demo/claude-code/`](demo/claude-code/README.md) |
| Codex CLI | te same hooki w `config.toml` (format `codex`, blokada przez exit 2) | [`demo/codex/config.toml`](demo/codex/config.toml), nieprzetestowane na żywo |
| Własna aplikacja | `spiregate.sdk.Guard` → `POST /v1/decide` | przykład niżej |

Hook nigdy nie odpowiada „allow”: przepuszczona akcja wraca do zwykłych pytań o zgodę agenta.
Gdy gateway nie odpowiada, hook i SDK blokują (fail-closed). Ruch Claude Code do Anthropic nie przechodzi przez SpireGate.

```python
from spiregate.sdk import Guard
guard = Guard(key="spire-demo-sdk", session_id="pay-1")

@guard.tool("send_email")
def send_email(to, subject, body): ...   # sprawdzane przed wykonaniem, wynik raportowany po
```

## Dashboard

`make serve` wypisuje adres panelu z tokenem administratora, np. `http://127.0.0.1:8787/ui/#token=…`.
Stały token ustawisz w `.env` (`SPIRE_ADMIN_TOKEN=`). Klucz agenta nie otwiera panelu. Panel jest po angielsku.

| Strona | Co pokazuje |
|---|---|
| Overview | decyzje i trend z 30 minut, stan bezpieczeństwa, reguły w akcji, agenci |
| **Engine** | prawdziwe żądania na żywo: najpierw krok *Company policy* (liczba reguł, rev; kliknięcie otwiera Policy), potem trzy tory: deterministyka, deterministyka + Jev, sam Jev; opóźnienie i koszt samej bramki, przycisk Start/Stop (ruch symulowanej floty, najdłużej 15 s) |
| Live | każda decyzja z łańcucha audytu; kliknięcie pokazuje sygnały, prawdopodobieństwa Jev, hash |
| **Policy** | edytor reguł: dodawanie z katalogu, edycja, usuwanie, **import z tekstu polityki firmy**, karta feedu sygnatur |
| Budgets | zużycie limitów per organizacja / biuro / agent, wydatki wg modelu, koszt warstwy kontroli, aktywne bezpieczniki pętli |
| Playground | dowolna akcja lub wynik narzędzia przez prawdziwą ścieżkę decyzji, z tym, co zobaczy agent |
| Audit | weryfikacja łańcucha, eksport JSONL / CSV / OCSF, historia przeładowań polityki |

Panel nie ma zależności zewnętrznych (działa offline). Zmiana z panelu podmienia w pliku polityki tylko blok zmienionej
reguły (komentarze w reszcie pliku zostają), jest walidowana na całym pliku przed zapisem i zapisywana atomowo, więc
gateway nigdy nie wczyta połowy edycji. Każda zmiana podbija `policy_rev`.

### Edytor polityki i import z tekstu

Strona **Policy** grupuje reguły wg tego, kto decyduje: *Deterministic*, *Deterministic + Jev*, *Jev*.
**+ Rule** otwiera katalog gotowych sprawdzeń z prostym formularzem (bez CEL-a); reguła zapamiętuje szablon i parametry,
więc później otwiera się w tym samym formularzu. Reguły spoza katalogu (np. progi Jev) mają edycję zaawansowaną.
Usunięcie wymaga drugiego kliknięcia; inwariantów nie da się zmienić ani usunąć.

**Import from text**: wklejasz politykę firmy zwykłym językiem (PL lub EN), a gateway rozbija ją na zdania i proponuje
reguły. Co da się sprawdzić z pewnością (dane, domeny, kwoty, polecenia, godziny), staje się regułą
deterministyczną z parametrami wziętymi z tekstu. Resztę („nie przekazuj informacji o M&A osobom spoza zespołu”)
ocenia Jev dosłownie według zdania z polityki. Nic nie jest zapisywane, dopóki człowiek nie zaznaczy propozycji;
to, co polityka już robi, jest oznaczone „already in the policy”. Zdania o budżetach są pokazane jako pominięte: budżety
ustawia się w sekcji `budgets:` pliku polityki, nie regułami. Serwer buduje reguły od nowa z szablonu i parametrów,
więc przeglądarka nie może dopisać do pliku dowolnego warunku. Import działa regułami dopasowania (bez LLM).

Katalog sprawdzeń (każde włącza się tylko wtedy, gdy bank doda je do polityki):

| Grupa | Sprawdzenia |
|---|---|
| Dane (maskowanie w wynikach, opcjonalnie z weryfikacją Jev) | PESEL, IBAN, numer karty, LEI, ISIN, sekrety i klucze, NIP, REGON, SSN, routing number (ABA), CUSIP, SWIFT/BIC, e-mail, telefon. Numery z sumą kontrolną są walidowane (`python-stdnum`), więc przypadkowe ciągi cyfr nie są maskowane |
| Akcje | wysyłka tylko do wskazanych domen, poświadczenia, pobierz-i-uruchom, polecenia niszczące (`rm -rf`, force push, `DROP TABLE`, `terraform destroy`), podnoszenie uprawnień (`sudo`, `chmod 777`), instalacja pakietów, płatności powyżej kwoty, godziny pracy i weekend, zakaz narzędzi |
| Zasady opisowe | dowolne zdanie z polityki firmy, oceniane przez Jev przy ryzykownych akcjach (przegląd albo blokada) |

## Polityka

Jeden plik: [`policy/spiregate.policy.yaml`](policy/spiregate.policy.yaml). Zmiany działają od następnego żądania, bez restartu.
Zły plik zostaje odrzucony, a gateway działa dalej na ostatniej poprawnej wersji. Kontrole `ACC-TOOL-001`, `IFC-TRIFECTA-001` i `CTL-SELF-001`
są inwariantami: nie można ich usunąć.

Zasady są trzech rodzajów:
- **Fakty** (dostęp, ścieżki, przepływ danych, kwoty, godziny, budżety): rozstrzyga reguła, Jev nie jest pytany.
- **Zasady semantyczne**: reguła z blokiem `verify:`. Gdy reguła przepuści akcję, Jev sprawdza, czy coś jej nie umknęło
  (np. PESEL zapisany słownie, dane klienta wysłane na dozwolony host). `verify.when` zawęża, kiedy w ogóle pytać.
- **Zasady opisowe**: tylko Jev (zgodność akcji z poleceniem, polecenia ukryte w treści, zdania z polityki firmy:
  `detector: systemone_rule` z polem `rule`). Ich `when` to zakres; polecenia shell są wyłączone z pytania o zgodność
  z poleceniem, bo pilnuje ich deterministyka.

System One (Jev, docelowo lokalna Laya) zwraca prawdopodobieństwo, a progi w polityce zamieniają je na decyzję:
poniżej `escalate_at` zatwierdza, od `escalate_at` kieruje do przeglądu przez człowieka, od `block_at` blokuje.
Blokada wyniku narzędzia (np. strona z ukrytym poleceniem) oznacza, że model go nie zobaczy. Jev nigdy nie cofa decyzji
reguły deterministycznej i nie jest pytany, gdy reguła już zablokowała. Gdy Jev nie odpowiada, zasady oceniane tylko
przez niego trafiają do przeglądu (`on_error`), a nie są przepuszczane po cichu. Wszystkie pytania o jedną akcję idą
w jednym wywołaniu. Każda reguła w pliku działa zawsze (enforce); żeby regułę wyłączyć, usuwa się ją z pliku — nie ma trybów monitor/off, bo kontrola albo chroni, albo jej nie ma.

## Budżety i koszty

Sekcje `prices` i `budgets` w pliku polityki. Każda reguła ma zakres (`org`, `desk:<nazwa>`, `agent:<id>`, z wzorcami `*`),
okno przesuwne (minuta / godzina / dzień) i dowolne z limitów: USD, tokeny, żądania, wywołania narzędzi.

- **Rezerwacja przed wywołaniem.** Gateway rezerwuje najgorszy przypadek (szacowane wejście + `max_tokens`) na każdym
  pasującym budżecie, zanim zapyta model. Po odpowiedzi rezerwacja zamienia się w faktyczny koszt. Równoległe agenty nie
  przekroczą budżetu między sprawdzeniem a wydatkiem.
- **Odmowa bez ponawiania.** Przekroczenie to `403 budget_exceeded` z nazwą budżetu, zakresem i czasem odnowienia.
- **Bezpiecznik pętli (LOOP-001).** To samo narzędzie z tymi samymi argumentami 4× w 60 s blokuje to jedno wywołanie
  na 120 s. Inne akcje agenta działają dalej.
- **Modele lokalne** liczone są w sekundach GPU (`usd_per_gpu_second`), zewnętrzne w tokenach.
- **Koszt warstwy kontroli.** Pytania do System One są liczone osobno, jako procent kosztu modeli.
- Restart gateway nie zeruje wydatków: stan budżetów odtwarza się z łańcucha audytu.

## Audyt

`make audit` pokazuje decyzje, `make verify` sprawdza łańcuch hashy w `var/audit.jsonl` (zmiana lub usunięcie wpisu = błąd).
