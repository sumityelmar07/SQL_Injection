"""
Input normalizer.

Attackers encode payloads to slip past pattern matching:
  - URL encoding:   %27  → '
  - HTML entities:  &lt; → <
  - Hex literals:   0x27 → '
  - Unicode tricks: ＯＲ  → OR (full-width letters)
  - Mixed case:     OrDeR bY → order by

This module strips all of that so signatures and anomaly checks always
see the canonical form of the input.
"""

import re
import unicodedata
from urllib.parse import unquote_plus
import html


def normalize(raw: str) -> str:
    """Return the canonical, lowercased form of *raw*."""
    if not isinstance(raw, str):
        return ""

    text = raw

    # 1. Repeat URL-decode until no more percent-encodings remain.
    #    One pass misses double-encoded values like %2527 → %27 → '
    prev = None
    while prev != text:
        prev = text
        text = unquote_plus(text)

    # 2. Decode HTML entities: &amp; → &, &#39; → ', &lt; → <
    text = html.unescape(text)

    # 3. Replace hex literals like 0x27 or 0X41 with their character.
    def _hex_to_char(match):
        try:
            return chr(int(match.group(0), 16))
        except (ValueError, OverflowError):
            return match.group(0)

    text = re.sub(r"0[xX][0-9a-fA-F]{1,6}", _hex_to_char, text)

    # 4. NFKC normalization collapses full-width/half-width Unicode to ASCII.
    #    e.g. ａ (U+FF41) → a,  ／ (U+FF0F) → /
    text = unicodedata.normalize("NFKC", text)

    # 5. Lowercase so OR, Or, oR are all treated the same.
    text = text.lower()

    # 6. Collapse runs of whitespace (including tabs, newlines) to a single space.
    text = re.sub(r"\s+", " ", text).strip()

    # 7. Remove MySQL/MSSQL inline comment obfuscation: /*!...*/ → space
    text = re.sub(r"/\*!?.*?\*/", " ", text, flags=re.DOTALL)

    # 8. Collapse repeated spaces left over from step 7.
    text = re.sub(r" {2,}", " ", text).strip()

    return text
