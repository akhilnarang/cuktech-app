"""Terminal output via rich: a drop-in ``print`` for the CLI.

Markup is OFF because messages contain literal ``[...]``. Soft-wrap is ON,
so long lines such as the 2FA URL do not split and you can copy them.
Colour comes only from the highlighter below.
"""


import sys

from rich.console import Console
from rich.highlighter import RegexHighlighter
from rich.theme import Theme


class _Highlighter(RegexHighlighter):
    base_style = "cuk."
    highlights = [
        r"(?P<good>\b(SUCCESS|removed|completed|validated|VERIFIED)\b)",
        r"(?P<bad>\b(error|failed|REJECTED|refusing|not valid)\b|consent not given)",
        r"(?P<warn>\b(INCONCLUSIVE|WARNING|REQUIRED|expired|unknown)\b)",
        r"(?P<mac>\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b)",
        r"(?P<did>\bblt\.[0-9a-z.]+\b)",
        r"(?P<url>https?://\S+)",
        r"(?P<rule>^=+$)",
    ]


_THEME = Theme({
    "cuk.good": "bold green",
    "cuk.bad": "bold red",
    "cuk.warn": "bold yellow",
    "cuk.mac": "cyan",
    "cuk.did": "cyan",
    "cuk.url": "underline blue",
    "cuk.rule": "dim",
})
_KW = dict(markup=False, emoji=False, soft_wrap=True,
           highlighter=_Highlighter(), theme=_THEME)
_out = Console(**_KW)
_err = Console(stderr=True, **_KW)


def print(*objects, sep=" ", end="\n", file=None, flush=False):  # noqa: A001
    """Print like the built-in ``print``, with rich colour highlights.

    Args:
        *objects: The values to print.
        sep: Text between the values.
        end: Text after the last value.
        file: ``sys.stderr`` sends the output to stderr. Any other value
            sends it to stdout.
        flush: Ignored. It is here for compatibility with the built-in.
    """
    (_err if file is sys.stderr else _out).print(*objects, sep=sep, end=end)


def panel(title: str, lines: list[str], style: str = "yellow") -> None:
    """Show a bordered block for text that the user must read before an answer.

    Args:
        title: The panel title, shown in bold.
        lines: The body lines.
        style: The rich border style. Default is ``"yellow"``.
    """
    from rich.panel import Panel
    from rich.text import Text

    body = Text("\n".join(lines))
    _out.print(Panel(body, title=Text(title, style="bold"), border_style=style,
                     expand=False))


def confirm(question: str) -> bool:
    """Ask a y/N question on the terminal.

    Only ``y`` or ``yes`` (any case) is Yes. Enter, other text and
    end-of-file are No.

    Args:
        question: The question text. The function adds ``[y/N]``.

    Returns:
        ``True`` if the user answered Yes.
    """
    try:
        answer = input(f"{question} [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")
