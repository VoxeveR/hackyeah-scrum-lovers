"""Tests run against a pinned copy of the default policy.

policy/spiregate.policy.yaml is the live file that the dashboard edits, so its content changes as people use the
product. Every test module imports DEFAULT_POLICY from spiregate.app; pointing it at the fixture here (conftest is
imported before the test modules) keeps the suite independent of those edits.
"""

from pathlib import Path

import spiregate.app

POLICY = Path(__file__).parent / "fixtures" / "spiregate.policy.yaml"
spiregate.app.DEFAULT_POLICY = POLICY
