"""Optional debug logging for angr Threading / BatchThreading exploration techniques.

Enable via ``--debug`` on trace solve scripts or environment variable
``TRACE_SOLVE_DEBUG=1`` (also accepts ``true``, ``yes``, ``on``).
"""

from __future__ import annotations

import logging
import os
import sys

_CONFIGURED = False

_THREADING_LOGGERS = (
    "angr.exploration_techniques.threading",
    "angr.exploration_techniques.batch_threading",
)


def trace_solve_debug_enabled() -> bool:
    return os.environ.get("TRACE_SOLVE_DEBUG", "").lower() in ("1", "true", "yes", "on")


def configure_exploration_technique_debug(enabled: bool | None = None) -> None:
    """
    When enabled, attach a stderr handler at DEBUG to Threading / BatchThreading loggers
    so technique diagnostics are visible without raising the root logger level.
    """
    global _CONFIGURED
    if enabled is None:
        enabled = trace_solve_debug_enabled()
    if not enabled or _CONFIGURED:
        return
    _CONFIGURED = True

    fmt = logging.Formatter(
        "%(levelname)s [%(threadName)s] %(name)s: %(message)s",
    )
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(fmt)

    for name in _THREADING_LOGGERS:
        log = logging.getLogger(name)
        log.setLevel(logging.DEBUG)
        log.addHandler(handler)
        log.propagate = False
