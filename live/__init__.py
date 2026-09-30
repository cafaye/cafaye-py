"""The env-gated tier, as a package.

It is a package for one reason: ``pyproject.toml``'s ``[tool.mypy] packages`` list
is how this repository decides what the type checker reads, and a directory that
is not named there is a directory whose every line is decoration. ``bin/prime``
never collects this in its default run — ``testpaths`` is ``["tests"]`` — and says
so out loud, which is the other half of the arrangement.
"""

from __future__ import annotations
