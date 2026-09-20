"""Importing this package registers every scanner.

Import order determines the order scans run in, so put the slow, important
ones first: the user sees results from those while the cheap ones finish.
"""
from . import systemfiles  # noqa: F401
from . import security     # noqa: F401
from . import stability    # noqa: F401
from . import disk         # noqa: F401
from . import startup      # noqa: F401
from . import performance  # noqa: F401
from . import junk         # noqa: F401
from . import privacy      # noqa: F401
from . import registry     # noqa: F401
from . import hardware     # noqa: F401

__all__ = [
    "systemfiles",
    "security",
    "stability",
    "disk",
    "startup",
    "performance",
    "junk",
    "privacy",
    "registry",
    "hardware",
]
