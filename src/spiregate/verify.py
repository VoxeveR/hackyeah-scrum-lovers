"""Verifier after the sanitizer: deterministic masking runs first, then System One (Jev/Laya) is asked
whether anything of that kind is still in the text. It never sees the values we found, only what is left."""

from __future__ import annotations

import json
from typing import Any

from .detectors import residue_hints
from .policy import Verify

FORMS = {
    "none": "w tekście nie ma takiego numeru",
    "digits_spaced": "cyfry rozdzielone spacjami, kropkami lub myślnikami",
    "spelled_out": "numer zapisany słownie",
    "partial": "tylko część numeru, np. ostatnie cyfry",
    "encoded": "numer zakodowany lub zaciemniony, np. base64",
    "other": "inna forma",
}


def residue_questions(v: Verify) -> dict[str, Any]:
    return {
        "residual": {"type": "noul", "instructions": v.question,
                     "criteria": {"true": v.positive, "false": v.negative}},
        "form": {"type": "choice", "instructions": "W jakiej formie ten numer występuje w tekście?", "criteria": FORMS},
    }


def rule_questions(v: Verify) -> dict[str, Any]:
    return {"violates": {"type": "noul", "instructions": v.question,
                         "criteria": {"true": v.positive, "false": v.negative}}}


def state_text(obj: Any) -> str:
    return (obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False))[:4000]


def stub_residual(state: Any, kinds: set[str]) -> float:
    """Offline stand-in for the verifier, NOT a model: it 'sees' residue where the hints are, except
    digit groups whose context says they are something else (order, invoice, phone). Real Jev/Laya
    reads the criteria instead."""
    text = state_text(state)
    for h in residue_hints(text, kinds):
        if not h.other_number:
            return 0.92
    return 0.03
