"""Display-only escaping; original graph values must remain unchanged."""

import json
import unicodedata


def terminal_text(value: str) -> str:
    """Neutralize controls, format/bidi controls, surrogates and line separators."""
    return "".join(
        json.dumps(char, ensure_ascii=True)[1:-1]
        if unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        else char
        for char in value
    )
