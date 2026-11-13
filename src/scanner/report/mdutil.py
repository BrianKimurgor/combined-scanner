def escape_text(value: object) -> str:
    """Make untrusted scanner or source text inert in GitHub-flavoured Markdown."""
    text = " ".join(str(value).split())
    for char, replacement in (
        ("&", "&amp;"),
        ("<", "&lt;"),
        (">", "&gt;"),
        ("|", "\\|"),
        ("`", "'"),
        ("[", "\\["),
        ("]", "\\]"),
        ("@", "@\u200b"),  # no mentions
        ("://", ":&#8203;//"),  # no auto-linked URLs
    ):
        text = text.replace(char, replacement)
    return text


def code_span(value: object) -> str:
    """A code span that is safe inside a table cell (GFM allows \\| there)."""
    inner = " ".join(str(value).split()).replace("`", "'").replace("|", "\\|")
    return f"`{inner}`"
