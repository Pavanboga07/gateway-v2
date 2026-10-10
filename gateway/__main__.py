"""Clean ``python -m gateway`` entry point.

Running ``python -m gateway.app`` executes the module a second time after
the package ``__init__`` has already imported it (hence the
already-in-``sys.modules`` startup warning). This module has a distinct
name, so it executes exactly once; prefer it (or the ``nexus-gateway``
console script) over ``python -m gateway.app``.
"""

from .app import main

main()
