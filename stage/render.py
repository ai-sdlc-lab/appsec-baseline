"""Render untrusted strings inert for logs, job summaries and PR comments (SPEC-0001 §1.7, M-14, M-30).

- control characters (incl. CR/LF) become a space, so `::workflow-commands::` can't start a line;
- a leading `::` is removed;
- backticks, markdown link/image syntax and HTML brackets are neutralised;
- `@` gets a zero-width space so no one is mentioned;
- every item is cut to 200 characters.
"""

import re

LIMIT = 200
_CONTROL = re.compile("[\\x00-\\x1f\\x7f\\u2028\\u2029]")


def clean(text, limit: int = LIMIT) -> str:
    s = _CONTROL.sub(" ", str(text))
    s = s.replace("`", "'").replace("<", "‹").replace(">", "›")
    s = s.replace("](", "] (").replace("![", "! [").replace("@", "@\u200b")
    s = re.sub(r"(?i)\b(https?)://", r"\1[:]//", s)
    s = s.lstrip()
    while s.startswith("::"):
        s = s[2:].lstrip()
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return s


def comment(marker: str, title: str, items: list[str]) -> str:
    """A PR comment body: marker line, plain title, one inert item per line inside a fenced block."""
    body = "\n".join(f"- {clean(i)}" for i in items)
    return f"{marker}\n### {clean(title, 100)}\n\n```text\n{body}\n```\n"
