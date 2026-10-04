"""Deterministic T0 detectors: canonicalisation, checksum-validated identifiers, injection lexicon."""

from __future__ import annotations

import fnmatch
import re
import unicodedata
from dataclasses import dataclass

from stdnum import bic, cusip, iban, isin, lei, luhn
from stdnum.pl import nip, pesel, regon
from stdnum.us import rtn, ssn

_ZERO_WIDTH = re.compile("[​-‏‪-‮⁠-⁤﻿]")
_UNICODE_TAGS = re.compile("[\U000e0000-\U000e007f]")


def canonicalize(text: str) -> tuple[str, list[str]]:
    """NFKC plus removal of invisible characters used to smuggle instructions."""
    flags = []
    if _UNICODE_TAGS.search(text):
        flags.append("unicode_tags")
        text = _UNICODE_TAGS.sub("", text)
    if _ZERO_WIDTH.search(text):
        flags.append("zero_width")
        text = _ZERO_WIDTH.sub("", text)
    return unicodedata.normalize("NFKC", text), flags


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int
    value: str  # normalised (no spaces, upper case)


def _card_valid(s: str) -> bool:
    return 13 <= len(s) <= 19 and luhn.is_valid(s)


# Always detected (they label a session as holding client data). Validated by checksum, or a high-confidence format.
BASE_KINDS = frozenset({"IBAN", "LEI", "ISIN", "CARD", "PESEL", "SECRET"})
# Opt-in: detected only where a rule asks for them. Several are bare 9-10 digit numbers with a checksum, so
# detecting them everywhere would turn order numbers into "client data".
EXTRA_KINDS = frozenset({"NIP", "REGON", "SSN", "ABA", "CUSIP", "BIC", "EMAIL", "PHONE"})
KNOWN_KINDS = BASE_KINDS | EXTRA_KINDS
KIND_LABELS = {
    "PESEL": "PESEL", "IBAN": "IBAN", "CARD": "card number", "LEI": "LEI", "ISIN": "ISIN", "SECRET": "secrets and keys",
    "NIP": "NIP (PL tax id)", "REGON": "REGON", "SSN": "SSN", "ABA": "routing number (ABA)", "CUSIP": "CUSIP",
    "BIC": "SWIFT / BIC", "EMAIL": "email", "PHONE": "phone number",
}

# High-confidence secret formats. For key=value forms only the value (group 1) is masked.
_SECRETS = [re.compile(p, f) for p, f in [
    (r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16})\b", 0),                                      # AWS access key id
    (r"(?i)\baws_(?:secret_access_key|session_token)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{16,})", 0),   # AWS secret / session
    (r"(-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )?PRIVATE KEY-----)", 0),  # PEM private key
    (r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b", 0),                         # GitHub
    (r"\b(sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,})", 0),                                               # OpenAI / Anthropic
    (r"\b(xox[abposr]-[A-Za-z0-9-]{10,})", 0),                                                      # Slack
    (r"\b(AIza[0-9A-Za-z_-]{35})\b", 0),                                                           # Google API key
    (r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})", 0),                   # JWT
    (r"(?i)\b(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|password|passwd)\b[\"']?\s*[=:]\s*[\"']?([^\s\"',;]{12,})", 0),
]]

# Order matters: earlier kinds claim their span first (an IBAN contains digit runs).
_CANDIDATES = [
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b", re.I), iban.is_valid),
    ("LEI", re.compile(r"\b[0-9A-Z]{18}\d{2}\b", re.I), lei.is_valid),
    ("ISIN", re.compile(r"\b[A-Z]{2}[A-Z0-9]{9}\d\b", re.I), isin.is_valid),
    ("CARD", re.compile(r"\b\d(?:[ -]?\d){12,18}\b"), _card_valid),
    ("PESEL", re.compile(r"\b\d{11}\b"), pesel.is_valid),
]


def _shrink_to_valid(raw: str, valid) -> str | None:
    """A greedy match may swallow a trailing word ("... 7654 32 and"); drop tokens until valid."""
    tokens = raw.split(" ")
    while tokens:
        candidate = "".join(tokens).upper()
        if valid(candidate):
            return " ".join(tokens)
        tokens.pop()
    return None


_DIGITS = re.compile(r"\D")
_EXTRA_CANDIDATES = [   # order matters when one number fits two kinds (an ABA routing number vs a CUSIP)
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), lambda s: ssn.is_valid(s)),
    ("BIC", re.compile(r"\b[A-Z]{4}(?:PL|US|GB|DE|FR|CH|LU|IE|NL|IT|ES|JP|HK|SG|AT|BE|SE|NO|DK|FI|CZ)[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),
     lambda s: bic.is_valid(s)),
    ("NIP", re.compile(r"\b(?:PL ?)?\d{3}[- ]?\d{3}[- ]?\d{2}[- ]?\d{2}\b|\b(?:PL ?)?\d{3}[- ]?\d{2}[- ]?\d{2}[- ]?\d{3}\b"),
     lambda s: nip.is_valid(_DIGITS.sub("", s))),
    ("ABA", re.compile(r"\b\d{9}\b"), lambda s: rtn.is_valid(s)),
    ("CUSIP", re.compile(r"\b[0-9]{3}[0-9A-Z]{5}\d\b"), lambda s: cusip.is_valid(s)),
    ("REGON", re.compile(r"\b\d{9}(?:\d{5})?\b"), lambda s: regon.is_valid(s)),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), lambda s: True),
    ("PHONE", re.compile(r"(?<![\w+])(?:\+48[ -]?\d{3}[ -]?\d{3}[ -]?\d{3}|\+1[ -]?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}"
                         r"|\b\d{3}[ -]\d{3}[ -]\d{3})\b"), lambda s: True),
]


def find_identifiers(text: str, extra: set[str] | frozenset[str] | None = None) -> list[Finding]:
    """Base kinds always; opt-in kinds (EXTRA_KINDS) only when asked for in `extra`."""
    found: list[Finding] = []
    taken: list[tuple[int, int]] = []
    wanted = [c for c in _EXTRA_CANDIDATES if extra and c[0] in extra]
    for kind, pattern, valid in _CANDIDATES + wanted:
        for m in pattern.finditer(text):
            start = m.start()
            if any(a <= start < b for a, b in taken):
                continue
            kept = _shrink_to_valid(m.group(0), valid)
            if kept is None:
                continue
            end = start + len(kept)
            taken.append((start, end))
            found.append(Finding(kind, start, end, re.sub(r"[ -]", "", kept).upper()))
    for rx in _SECRETS:
        for m in rx.finditer(text):
            start, end = m.span(1)
            if any(a < end and start < b for a, b in taken):
                continue
            taken.append((start, end))
            found.append(Finding("SECRET", start, end, m.group(1)))
    return sorted(found, key=lambda f: f.start)


class Redactor:
    """Replaces identifiers with stable typed placeholders ([IBAN#1]) across a whole conversation."""

    def __init__(self) -> None:
        self.placeholders: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def redact(self, text: str, kinds: set[str] | None = None) -> tuple[str, list[str]]:
        """Masks identifiers; with `kinds`, only those kinds (detection still runs for all, so spans stay right)."""
        findings = [f for f in find_identifiers(text, extra=(kinds & EXTRA_KINDS) if kinds else None)
                    if kinds is None or f.kind in kinds]
        if not findings:
            return text, []
        out, last, used = [], 0, []
        for f in findings:
            ph = self.placeholders.get(f.value)
            if ph is None:
                self._counters[f.kind] = self._counters.get(f.kind, 0) + 1
                ph = f"[{f.kind}#{self._counters[f.kind]}]"
                self.placeholders[f.value] = ph
            out.append(text[last:f.start])
            out.append(ph)
            used.append(ph)
            last = f.end
        out.append(text[last:])
        return "".join(out), used


def redact_json(obj, redactor: "Redactor", kinds: set[str] | None = None):
    """Masks every string inside a JSON-like value and keeps its shape (dicts, lists, numbers untouched)."""
    used: list[str] = []

    def walk(o):
        if isinstance(o, str):
            new, u = redactor.redact(o, kinds)
            used.extend(u)
            return new
        if isinstance(o, list):
            return [walk(x) for x in o]
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        return o

    return walk(obj), used


_INJECTION_PATTERNS = [
    ("ignore_instructions_en", r"\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules)"),
    ("ignore_instructions_pl", r"\bzignoruj\s+(?:wszystkie\s+|wcześniejsze\s+|poprzednie\s+)*(?:polecenia|instrukcje|zasady)"),
    ("addressed_to_ai", r"\b(?:ai|assistant|agent|asystent(?:ie)?)\s*[:,]\s*(?:please\s+|proszę\s+)?(?:send|forward|email|wyślij|prześlij)"),
    ("send_to_address", r"\b(?:send|forward|email|wyślij|prześlij)\b[^.\n]{0,100}\b(?:to|do|na)\b[^.\n]{0,40}@"),
    ("hidden_html", r"display\s*:\s*none|color\s*:\s*(?:white|#fff\b|#ffffff)|font-size\s*:\s*0"),
]
_INJECTION_RES = [(name, re.compile(p, re.I)) for name, p in _INJECTION_PATTERNS]


def injection_hits(text: str) -> list[str]:
    canonical, flags = canonicalize(text)
    return flags + [name for name, rx in _INJECTION_RES if rx.search(canonical)]


def recipient_matches(recipient: str, patterns: list[str]) -> bool:
    r = recipient.strip().lower()
    return any(fnmatch.fnmatchcase(r, p.lower()) for p in patterns)


def is_internal(recipient: str, internal_domains: list[str]) -> bool:
    r = recipient.strip().lower()
    return any(r.endswith("@" + d.lower()) for d in internal_domains)


# ---------------------------------------------------------------- residue: what precise masking may have missed

_PLACEHOLDER = re.compile(r"\[[A-Z]+\??#\d+\]")
_DIGIT_GROUP = re.compile(r"(?<![\w\[#])\d(?:[ \t.\-–/]{1,3}\d|\d){8,33}(?![\w\]])")
_DIGIT_RANGE = {"PESEL": (9, 13), "CARD": (12, 19), "IBAN": (10, 34)}
_NUMBER_WORDS = ("zero|jeden|jedna|jedynka|dwa|dwie|trzy|cztery|pięć|piec|sześć|szesc|siedem|osiem|dziewięć|dziewiec"
                 "|one|two|three|four|five|six|seven|eight|nine|oh")
_WORD_SEQUENCE = re.compile(rf"\b(?:{_NUMBER_WORDS})\b(?:[ \t,\-]+(?:{_NUMBER_WORDS})\b){{5,}}", re.I)  # one line only
KIND_KEYWORDS = {"PESEL": ["pesel"], "IBAN": ["iban", "rachun", "konto", "account"], "CARD": ["kart", "card"],
                 "LEI": ["lei"], "ISIN": ["isin"]}
OTHER_NUMBER_CONTEXT = re.compile(
    r"(?:zam[oó]wieni\w*|order\w*|faktur\w*|invoice\w*|\btel\.?|telefon\w*|phone\w*|ticket\w*|sprawy|konta?\s+klienta)"
    r"(?:\s+(?:nr|numer|no|number)\.?)?\W{0,5}$", re.I)


@dataclass(frozen=True)
class Hint:
    start: int
    end: int
    reason: str
    other_number: bool = False  # preceded by "zamówienie", "faktura", "tel." ...: probably not this identifier


def residue_hints(text: str, kinds: set[str]) -> list[Hint]:
    """Cheap, inclusive signals that an identifier may survive in a non-canonical form.
    Placeholders like [PESEL#1] are already masked and never count."""
    scrub = _PLACEHOLDER.sub(lambda m: " " * len(m.group(0)), text)  # same length, so offsets stay valid
    hints: list[Hint] = []
    lo = min(_DIGIT_RANGE.get(k, (9, 34))[0] for k in kinds)
    hi = max(_DIGIT_RANGE.get(k, (9, 34))[1] for k in kinds)
    for m in _DIGIT_GROUP.finditer(scrub):
        if lo <= len(re.sub(r"\D", "", m.group(0))) <= hi:
            other = bool(OTHER_NUMBER_CONTEXT.search(scrub[max(0, m.start() - 30):m.start()]))
            hints.append(Hint(m.start(), m.end(), "grupa cyfr", other))
    for m in _WORD_SEQUENCE.finditer(scrub):
        hints.append(Hint(m.start(), m.end(), "liczba słownie"))
    for kind in kinds:
        for kw in KIND_KEYWORDS.get(kind, []):
            for m in re.finditer(rf"\b{kw}\w*", scrub, re.I):
                window = scrub[m.end():m.end() + 40].split("\n", 1)[0]  # same line: the next line is another field
                d = re.search(r"\d(?:[\d \t.\-]*\d)?", window)
                if d:
                    hints.append(Hint(m.end() + d.start(), m.end() + d.end(), f"cyfry obok słowa „{kw}”"))
    hints.sort(key=lambda h: (h.start, -h.end))
    merged: list[Hint] = []
    for h in hints:
        if merged and h.start < merged[-1].end:
            last = merged[-1]
            merged[-1] = Hint(last.start, max(last.end, h.end), last.reason, last.other_number and h.other_number)
        else:
            merged.append(h)
    return merged


def json_strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, list):
        return [s for x in obj for s in json_strings(x)]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in json_strings(v)]
    return []


def mask_residue(obj, kinds: set[str], label: str):
    """Masks every residue hint inside a JSON-like value as [LABEL?#n]; returns (new value, count)."""
    count = 0

    def mask(text: str) -> str:
        nonlocal count
        out, last = [], 0
        for h in residue_hints(text, kinds):
            if h.other_number:  # the verifier is asked again afterwards; if it still sees an ID, we withhold
                continue
            count += 1
            out.append(text[last:h.start] + f"[{label}?#{count}]")
            last = h.end
        out.append(text[last:])
        return "".join(out)

    def walk(o):
        if isinstance(o, str):
            return mask(o)
        if isinstance(o, list):
            return [walk(x) for x in o]
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        return o

    return walk(obj), count


def withhold_json(obj, notice: str):
    """Replaces every string with a notice, keeping the shape (and `type` discriminators) intact."""
    if isinstance(obj, str):
        return notice
    if isinstance(obj, list):
        return [withhold_json(x, notice) for x in obj]
    if isinstance(obj, dict):
        return {k: (v if k == "type" and isinstance(v, str) else withhold_json(v, notice)) for k, v in obj.items()}
    return obj
