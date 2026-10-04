"""Company policy in plain language → rules the gate enforces.

Every statement is read on its own. What can be checked with certainty (identifiers, recipient domains,
amounts, destructive commands…) becomes a deterministic rule with parameters taken from the text.
What cannot (intent, confidentiality of a topic, "do not discuss…") becomes a plain-language rule judged by
System One, word for word. Nothing is written until a person reviews the proposals in the dashboard.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .catalog import TEMPLATES, build, next_id
from .detectors import KIND_LABELS

# keyword → identifier kind (Polish and English, inflected forms by prefix)
_KIND_WORDS = [
    (r"\bpesel", "PESEL"), (r"\biban|numer\w* (?:rachunk|kont[aou] bankow)|account numbers?|bank accounts?", "IBAN"),
    (r"kart\w* (?:płatnicz|kredytow|debetow)|numer\w* kart|card numbers?|credit cards?|\bpan\b", "CARD"),
    (r"\bnip\b|tax id", "NIP"), (r"\bregon", "REGON"), (r"\bssn\b|social security", "SSN"),
    (r"routing|\baba\b", "ABA"), (r"\bcusip", "CUSIP"), (r"\bswift\b|\bbic\b", "BIC"), (r"\blei\b", "LEI"),
    (r"\bisin", "ISIN"), (r"e-?mail\w*|adres\w* poczt", "EMAIL"), (r"telefon\w*|phone numbers?", "PHONE"),
    (r"hasł\w*|sekret\w*|kluczy? api|api keys?|tokens?\b|secrets?|passwords?", "SECRET"),
]
_STRONG = re.compile(r"\b(?:zakaz\w*|nie wolno|nigdy|bezwzględnie|zabronion\w*|must not|never|prohibited|forbidden)\b", re.I)
# a prohibition, as company policies usually phrase it ("nie może", "nie przekazuj", "do not share")
_PROHIBIT = re.compile(r"\b(?:zakaz\w*|nie wolno|nigdy|zabronion\w*|nie mo(?:że|gą|żna)|nie \w+(?:aj|uj|ij|ysyłaj)\b"
                       r"|must not|may not|cannot|can't|do not|don't|never|prohibited|forbidden)", re.I)
_REVIEW = re.compile(r"akcept\w*|zatwierdz\w*|zgod\w* (?:przełożon|człowiek|kierownik)|przegląd\w*|approv\w*|review|sign-?off", re.I)
_DOMAIN = re.compile(r"@?\b((?:[a-z0-9-]+\.)+(?:com|pl|net|org|eu|io|co\.uk|de|ch|uk|us|bank))\b", re.I)
_MONEY = re.compile(r"(\d[\d\s.,]*\d|\d)\s*(k|tys\.?|mln|m)?\s*(usd|pln|zł|eur|\$|€|dolar\w*|euro)?", re.I)


@dataclass
class Proposal:
    statement: str
    template: str
    params: dict[str, Any]
    title: str | None = None
    why: str = ""
    item: dict[str, Any] = field(default_factory=dict)   # the control, as it would be written
    exists: bool = False                                  # the policy already does this

    def view(self) -> dict[str, Any]:
        if not self.template:     # a statement the importer recognised but does not turn into a rule
            return {"statement": self.statement, "template": "", "template_title": "Skipped", "params": {}, "title": self.title,
                    "lane": "d", "target": "skip", "why": self.why, "item": {}, "exists": False}
        t = TEMPLATES[self.template]
        lane = "dj" if self.template == "mask_identifiers" and self.params.get("verify") else t.lane
        return {"statement": self.statement, "template": self.template, "template_title": t.title, "params": self.params,
                "title": self.item.get("title") or self.title, "lane": lane, "target": "control", "why": self.why,
                "item": self.item, "exists": self.exists}


def statements(text: str) -> list[str]:
    """One policy statement per line or bullet; long lines split into sentences."""
    out = []
    for raw in re.split(r"\n+", text or ""):
        line = re.sub(r"^\s*(?:[-*•▪◦]|\d+[.)]|[a-z][.)]|§\s*\d+\.?)\s*", "", raw).strip()
        if len(line) < 6:
            continue
        if _HEADING.search(line) and not _RULE_WORDS.search(line):
            continue                          # "AI usage policy (excerpt)", "Section 3: data", "Zasady ogólne:"
        for sent in re.split(r"(?<=[.!?])\s+(?=[A-ZĄĆĘŁŃÓŚŹŻ])", line):
            sent = sent.strip()
            if len(sent) >= 6:
                out.append(sent)
    return out


# a heading: short, no full stop, names a policy or a section
_HEADING = re.compile(r"^(?=.{0,80}$)[^.!?]*\b(?:polic\w*|polityk\w*|regulamin\w*|zasad\w*|rules|guidelines|section|rozdział)\b[^.!?]*$",
                      re.I)
_RULE_WORDS = re.compile(r"\b(?:must|may|should|shall|never|do not|don't|cannot|requires?|nie|wolno|może|mogą|zakaz\w*|wymaga\w*)\b",
                         re.I)


def _money(s: str) -> float | None:
    best = None
    for m in _MONEY.finditer(s):
        num, mult, cur = m.groups()
        if not cur and not mult and not re.search(r"powyżej|ponad|przekracz|above|over|exceed|limit|budżet|budget", s, re.I):
            continue
        digits = num.replace(" ", "").replace(" ", "")
        if "," in digits and "." in digits:
            digits = digits.replace(".", "").replace(",", ".") if digits.rfind(",") > digits.rfind(".") else digits.replace(",", "")
        elif "," in digits:
            digits = digits.replace(",", "." if len(digits.split(",")[-1]) <= 2 else "")
        elif digits.count(".") > 1 or (digits.count(".") == 1 and len(digits.split(".")[-1]) == 3):
            digits = digits.replace(".", "")
        try:
            v = float(digits)
        except ValueError:
            continue
        v *= {"k": 1e3, "tys": 1e3, "tys.": 1e3, "mln": 1e6, "m": 1e6}.get((mult or "").lower(), 1)
        best = v if best is None else max(best, v)
    return best



def _action(s: str, default: str = "block") -> str:
    if _REVIEW.search(s):
        return "escalate"
    return "block" if _STRONG.search(s) or default == "block" else "escalate"


# ---------------------------------------------------------------- matchers: statement → [(template, params, why)]
def _m_credentials(s: str):
    if re.search(r"poświadcz\w*|credential\w*|\.aws|\.ssh|kluczy? prywatn\w*|private keys?|plik\w* z (?:hasł|klucz)\w*", s, re.I) \
            and re.search(r"czyt\w*|odczyt\w*|dostęp\w*|otwier\w*|access|read|open|używ\w*|nie mo", s, re.I):
        return [("block_credentials", {"action": _action(s)}, "access to credentials")]
    return []


_SEE = re.compile(r"widz\w*|wgląd\w*|pokaz\w*|ujawni\w*|maskow\w*|ukry\w*|dostęp\w*|odczyt\w*|przetwarza\w*"
                 r"|\bsee\b|\bview\w*|\bshow\w*|reveal\w*|expos\w*|\bmask\w*|redact\w*|\baccess\w*|\bread\b", re.I)


def _m_identifiers(s: str):
    kinds = []
    for rx, kind in _KIND_WORDS:
        if re.search(rx, s, re.I) and kind not in kinds:
            kinds.append(kind)
    if "EMAIL" in kinds and not _SEE.search(s):   # "send emails only to…" is about messages, not addresses to hide
        kinds.remove("EMAIL")
    if not kinds:
        return []
    verify = "PESEL" in kinds or bool(re.search(r"w żadnej (?:formie|postaci)|in any form|słownie|spelled", s, re.I))
    labels = ", ".join(KIND_LABELS.get(k, k) for k in kinds)
    return [("mask_identifiers", {"kinds": kinds, "verify": verify}, f"data: {labels}")]


def _m_egress(s: str):
    if not re.search(r"wysył\w*|przesył\w*|przekaz\w*|udostępn\w*|e-?mail\w*|poza (?:bank|firm|organizac)|send\w*|share|outside|external",
                     s, re.I):
        return []
    if not re.search(r"tylko|wyłącznie|jedynie|only|exclusively|poza|outside", s, re.I):
        return []
    domains = [d.lower() for d in _DOMAIN.findall(s)]
    if not domains:
        return []
    return [("egress_domains", {"domains": sorted(set(domains), key=domains.index)}, f"recipients: {', '.join(dict.fromkeys(domains))}")]


def _m_download_exec(s: str):
    if re.search(r"pobier\w*\s+i\s+uruchami\w*|uruchami\w* (?:skrypt|kod|program)\w* (?:z|pobran)|download\w* and (?:run|execut)\w*"
                 r"|curl\s*\|\s*(?:ba)?sh|skrypt\w* z internetu|scripts? from the internet", s, re.I):
        return [("block_download_exec", {"action": _action(s)}, "download and run")]
    return []


def _m_destructive(s: str):
    if re.search(r"usuw\w*|kasow\w*|niszcz\w*|delete|destroy|rm -rf|force[- ]push|drop table|nadpis\w* histori", s, re.I) \
            and re.search(r"plik|repozytor|baz\w* danych|tabel|gałęzi|branch|histori|danych|files?|database|repo|infrastruktur", s, re.I):
        return [("block_destructive", {"action": _action(s)}, "destructive commands")]
    return []


def _m_privilege(s: str):
    if re.search(r"\bsudo\b|\broot\b|uprawnie\w* (?:administrator|admin|roota)|admin(?:istrator)? (?:rights|privileges)|privilege", s, re.I):
        return [("block_privilege", {"action": _action(s)}, "admin privileges")]
    return []


def _m_packages(s: str):
    if re.search(r"instal\w* (?:\w+ )?(?:pakiet|bibliotek|zależnoś|oprogramowan)\w*|pip install|npm install"
                 r"|install\w* (?:\w+ )?(?:packages|libraries|dependencies|software)", s, re.I):
        return [("block_package_install", {"action": _action(s, "escalate")}, "package installs")]
    return []


def _m_amount(s: str):
    if not re.search(r"przelew\w*|płatnoś\w*|płatnicz\w*|transfer\w*|payment\w*|wire\w*|transakcj\w* finansow", s, re.I):
        return []
    if not re.search(r"powyżej|ponad|przekracz\w*|więcej niż|above|over|exceed\w*|greater than|>\s*\d", s, re.I):
        return []
    amount = _money(s)
    if amount is None:
        return []
    return [("amount_review", {"amount": amount, "action": _action(s, "escalate")}, f"threshold {amount:,.0f}")]


def _m_hours(s: str):
    if not re.search(r"poza godzinami|po godzinach|outside (?:business|working|office) hours|after hours|w weekend\w*|weekends?", s, re.I):
        return []
    m = re.search(r"(\d{1,2})(?::\d{2})?\s*[-–]\s*(\d{1,2})(?::\d{2})?", s)
    start, end = (int(m.group(1)), int(m.group(2))) if m else (8, 18)
    return [("business_hours", {"start": start, "end": end, "action": _action(s, "escalate")}, f"hours {start}–{end}")]


def _is_budget(s: str) -> bool:
    return bool(re.search(r"budżet\w*|limit\w* (?:wydatk|koszt)|wydatk\w* na (?:model|ai|llm)|koszt\w* (?:model|ai|llm)|budget|spend\w*",
                          s, re.I)) and _money(s) is not None


def _m_tools(s: str, tools: list[str]):
    named = [t for t in re.findall(r"`([A-Za-z0-9_.:-]+)`", s)]
    named += [t for t in tools if t != "*" and re.search(rf"\b{re.escape(t)}\b", s)]
    if named and re.search(r"nie (?:może|wolno)\w* (?:używać|uruchamiać|korzystać)|zakaz\w* (?:używania|korzystania)|must not use|never use|do not use", s, re.I):
        return [("deny_tools", {"tools": list(dict.fromkeys(named))}, f"tools: {', '.join(dict.fromkeys(named))}")]
    return []


def _covered(item: dict[str, Any], controls: list[Any]) -> bool:
    """True when the policy already enforces what this proposal would add."""
    if not item:
        return False
    if item.get("detector") == "identifiers":
        have = {k for c in controls if c.detector == "identifiers" and c.phase == item["phase"] for k in c.kinds or []}
        return set(item.get("kinds") or []) <= have
    if item.get("detector") == "systemone_rule":
        return any(c.rule and " ".join(c.rule.split()).lower() == item["rule"].lower() for c in controls)
    if item.get("when"):
        squash = lambda w: re.sub(r"\s+", "", w or "")
        return any(c.phase == item["phase"] and squash(c.when) == squash(item["when"]) for c in controls)
    return False


def propose(text: str, taken: set[str], tools: list[str] = (), controls: list[Any] = ()) -> list[Proposal]:
    """Proposals for every statement; nothing is written here. Rules the policy already has are marked."""
    out: list[Proposal] = []
    taken = set(taken)
    for s in statements(text):
        if _is_budget(s):
            out.append(Proposal(statement=s, template="", params={}, title="Budget",
                                why="budgets live in the policy file's budgets section, not in rules"))
            continue
        found = _m_amount(s) + _m_credentials(s) + _m_download_exec(s) \
            + _m_destructive(s) + _m_privilege(s) + _m_packages(s) + _m_hours(s) + _m_tools(s, list(tools)) + _m_egress(s)
        if not any(t in ("block_credentials",) for t, _, _ in found):
            found += _m_identifiers(s)       # "keys and passwords in files" is about credentials, not masking text
        if not found:
            prohibit = bool(_PROHIBIT.search(s)) and not _REVIEW.search(s)
            found = [("prose_rule", {"text": s, "action": "block" if prohibit else "escalate"},
                      "no pattern can check this: Jev judges it")]
        for template, params, why in found:
            t = TEMPLATES[template]
            cid = next_id(t.prefix, taken)
            taken.add(cid)
            try:
                item = build(template, params, cid)
            except ValueError as e:
                item, why = {}, f"{why} (needs input: {e})"
            out.append(Proposal(statement=s, template=template, params=params, why=why, item=item,
                                exists=_covered(item, list(controls))))
    return out


SAMPLE = """AI usage policy (excerpt)
1. AI agents must never see client PESEL numbers or payment card numbers, in any form.
2. Client data may only be emailed to addresses in the gs.com domain.
3. Downloading and running scripts from the internet is prohibited.
4. Agents must not read files containing keys or credentials.
5. Transfers over 10,000 USD require human approval.
6. Agents must not delete repositories or databases.
7. Installing new packages requires approval from the security team.
8. Payments and emails outside business hours (8–18) require a manager's approval.
9. Do not share information about planned M&A deals with anyone outside the deal team.
10. Agents must not promise clients any future rate of return."""
