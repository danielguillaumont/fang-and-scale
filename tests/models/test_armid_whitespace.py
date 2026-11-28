"""The fast whitespace check gives the same answer as the per-character one.

``has_ascii_whitespace`` replaced ``any(c.isspace() for c in value)`` in
``parse_arm_id`` and the scope gate's URL split (docs/PERFORMANCE.md). Both
callers check ``isascii()`` first, so ASCII input is the whole domain.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from fns.models.armid import ASCII_WHITESPACE, ArmIdError, has_ascii_whitespace, parse_arm_id
from fns.scope.targets import TargetError, _split

ASCII = st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=127), max_size=300)


def test_the_set_is_every_ascii_character_isspace_accepts() -> None:
    assert "".join(chr(i) for i in range(128) if chr(i).isspace()) == ASCII_WHITESPACE
    assert set(ASCII_WHITESPACE) == set("\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f ")


@given(ASCII)
def test_same_answer_as_isspace_on_ascii(value: str) -> None:
    assert has_ascii_whitespace(value) == any(c.isspace() for c in value)


@pytest.mark.parametrize("ch", list(ASCII_WHITESPACE))
def test_arm_ids_and_urls_with_any_ascii_whitespace_are_still_refused(ch: str) -> None:
    sub = "00000000-0000-4000-8000-000000000010"
    with pytest.raises(ArmIdError):
        parse_arm_id(f"/subscriptions/{sub}/resourceGroups/rg{ch}app")
    with pytest.raises(TargetError):
        _split(f"https://management.azure.com/subscriptions/{sub}{ch}/x")
